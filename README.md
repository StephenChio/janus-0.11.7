# Janus源码分析

## 1.从哪里来到哪里去

首先，我们都很清楚，音视频数据都是从客户端来到服务器的，服务器和客户端之间是通过ICE协议进行网络数据传输，那么我们先看看，ICE通信通道是如何建立起来的。

目前我们只参考服务端的实现，客户端的逻辑也是对称的（基本相同）

对WebRTC有一定了解的小伙伴都知道，我们和ICE的互动在设置本地Description的时候正式开始，我们看到源码:

## janus_videoroom_handler（在janus_videoroom.c）

```c
janus_sdp *answer = janus_sdp_generate_answer(...);
...
    
//生成answer返回给publisher之后，用answer再生成一个offer，该offer用来给那些想订阅该publisher的订阅者使用
offer = janus_sdp_generate_offer(...);
...
/* Generate an SDP string we can send back to the publisher 生成一个 SDP 字符串，我们可以将其发送回发布者 */
char *answer_sdp = janus_sdp_write(answer);
/* Generate an SDP string we can offer subscribers later on 生成一个 SDP 字符串，我们稍后可以提供给订阅者 */
char *offer_sdp = janus_sdp_write(offer);
...
json_t *jsep = json_pack("{ssss}", "type", type, "sdp", answer_sdp);
int res = gateway->push_event(msg->handle, &janus_videoroom_plugin, msg->transaction, event, jsep);
/* Store the participant's SDP for interested subscribers 为感兴趣的订阅者存储参与者的 SDP*/
participant->sdp = offer_sdp;
```

当janus收到offer的时候会把生成answer的任务交给对应的插件（如videoroom，streaming）

生成了answer之后，会把事件通过push_event重新回调给janus.c进行处理，同时再利用该answer生成另一个offer，如果有人需要订阅该流，可以把offer发送给订阅者。

那么我们回到janus.c当videoroom根据offer生成完answer之后，会回到janus.c，去设置本地ICE（answer回通过异步事件返回给客户端）

## janus_plugin_handle_sdp（在janus.c）

```c
if(ice_handle->agent == NULL) {
			/* We still need to configure the WebRTC stuff: negotiate RFC4588 by default 
			如果ICE代理为空，说明我们需要进行一些webRTC的配置，默认遵循RFC4588协议
			*/
			janus_flags_set(&ice_handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RFC4588_RTX);
			/* Process SDP in order to setup ICE locally (this is going to result in an answer from the browser) 
			为了设置本地ICE，我们会处理SDP，成功之后会返回answer给客户端
			*/
			janus_mutex_lock(&ice_handle->mutex);
			if(janus_ice_setup_local(ice_handle, 0, audio, video, data, 1) < 0) {
				/*设置本地ICE出错*/
				JANUS_LOG(LOG_ERR, "[%"SCNu64"] Error setting ICE locally\n", ice_handle->handle_id);
				janus_sdp_destroy(parsed_sdp);
				janus_mutex_unlock(&ice_handle->mutex);
				return NULL;
			}
			janus_mutex_unlock(&ice_handle->mutex);
		} 
```

在Janus内部有一个和插件相对应的ICE代理，所有跟这个插件相关的ICE数据传输都跟这个ICE代理有关，所有我们每为session加载一个插件，都是在添加一个ICE代理来实现我们的数据处理需求（例如转发到房间用户，转发到服务器（级联））

我们看到上面的janus_ice_setup_local函数，这个和网页端设置localDescription是类似的。

但是不一样的是，我们没有在janus中找到设置远端Description的方法，因为对于Janus来说，它是一个中转站，它只会在收到answer的时候创建一个ICE代理跟客户端进行数据转发。而Janus所提供给其他人的offer也是在这个时候生成的，并不需要重新设置ICE。本质上Janus不会是发起者，它对于每一端客户端都是接受者。它只是在内部把来自某人的ICE数据转发到需要该ICE数据的ICE通道。

## janus_ice_setup_local

```c
/**
 * @brief 设置本地Description
 * @param offer 是否已经设置了offer
 */
int janus_ice_setup_local(janus_ice_handle *handle, int offer, int audio, int video, int data, int trickle) {
	/*判断ICE核心handle是否可用*/
	if(!handle || g_atomic_int_get(&handle->destroyed))
		return -1;
	/*判断ICE核心handle是否已经存在ICE代理*/
	if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_AGENT)) {
		JANUS_LOG(LOG_WARN, "[%"SCNu64"] Agent already exists?\n", handle->handle_id);
		return -2;
	}
	g_atomic_int_set(&handle->closepc, 0);
	/*libnice创建一个ICE代理*/
	handle->agent = g_object_new(NICE_TYPE_AGENT,
		"compatibility", NICE_COMPATIBILITY_DRAFT19,
		"main-context", handle->mainctx,
		"reliable", FALSE,
		"full-mode", janus_ice_lite_enabled ? FALSE : TRUE,
		"keepalive-conncheck", janus_ice_keepalive_connchecks ? TRUE : FALSE,
		NULL);
	handle->agent_created = janus_get_monotonic_time();
	handle->srtp_errors_count = 0;
	handle->last_srtp_error = 0;
    /*设置代理的配置，例如角色控制状态，candidate收集完成的回调函数，组件状态改变的回调函数*/
	g_object_set(G_OBJECT(handle->agent), "upnp", FALSE, NULL);
	g_object_set(G_OBJECT(handle->agent), "controlling-mode", handle->controlling, NULL);
	g_signal_connect (G_OBJECT (handle->agent), "candidate-gathering-done",
		G_CALLBACK (janus_ice_cb_candidate_gathering_done), handle);
	g_signal_connect (G_OBJECT (handle->agent), "component-state-changed",
		G_CALLBACK (janus_ice_cb_component_state_changed), handle);
	/*是否定义了使用TCP进行ICE连接*/
		G_CALLBACK (janus_ice_cb_new_selected_pair), handle);
		g_signal_connect (G_OBJECT (handle->agent), "new-candidate-full",
			G_CALLBACK (janus_ice_cb_new_local_candidate), handle);
	g_signal_connect (G_OBJECT (handle->agent), "new-remote-candidate-full",
		G_CALLBACK (janus_ice_cb_new_remote_candidate), handle);

	/* Add all local addresses, except those in the ignore list 
	添加所有本地地址，除了我们需要忽略的那些
	*/
	/*添加地址到ICE代理*/
	nice_agent_add_local_address (handle->agent, &addr_local);
	/* If this is our first offer, let's generate some mids 如果这是我们的第一个offer，生成一些mids 
	当我们没有设置过offer的时候，设置一些信息*/
	if(!offer) {
		if(audio) {
			if(handle->audio_mid == NULL)
				handle->audio_mid = g_strdup("audio");
			if(handle->stream_mid == NULL)
				handle->stream_mid = handle->audio_mid;
		}
		if(video) {
			if(handle->video_mid == NULL)
				handle->video_mid = g_strdup("video");
			if(handle->stream_mid == NULL)
				handle->stream_mid = handle->video_mid;
		}
	}
	/* Now create an ICE stream for all the media we'll handle
	现在为了所有我们处理的媒体生成一个ICE stream
	 */
	handle->stream_id = nice_agent_add_stream(handle->agent, 1);
	/*初始化一个ICE stream*/
	janus_ice_stream *stream = g_malloc0(sizeof(janus_ice_stream));
	/* FIXME By default, if we're being called we're DTLS clients, but this may be changed by ICE...
	如果我们接受offer，那么我们是接收端，反之我们是客户端 */
	stream->dtls_role = offer ? JANUS_DTLS_ROLE_CLIENT : JANUS_DTLS_ROLE_ACTPASS;
	/*初始化ICE streamn结束*/
	handle->stream = stream;
	/*初始化ICE 组件*/
	janus_ice_component *component = g_malloc0(sizeof(janus_ice_component));
	janus_refcount_init(&component->ref, janus_ice_component_free);
	/*把ICE stream加载到ICE组件中*/
	component->stream = stream;
	janus_refcount_increase(&stream->ref);
	/*把ICE组件stream id为ICE stream Id*/
	component->stream_id = stream->stream_id;
	component->component_id = 1;
	janus_mutex_init(&component->mutex);
	/*把ICE 组件加载到ICE stream中*/
	stream->component = component;
	nice_agent_attach_recv(handle->agent, handle->stream_id, 1, g_main_loop_get_context(handle->mainloop), janus_ice_cb_nice_recv, component);
	return 0;
}

```

janus_ice_setup_local主要做的就是创建一个ICE代理，并为代理传入一些回调函数，在合适的时候被执行。

```c
g_signal_connect (G_OBJECT (handle->agent), "candidate-gathering-done",
		G_CALLBACK (janus_ice_cb_candidate_gathering_done), handle);
```

我们在ICE收集完candidate之后会执行janus_ice_cb_candidate_gathering_done函数

```c
g_signal_connect (G_OBJECT (handle->agent), "component-state-changed",
		G_CALLBACK (janus_ice_cb_component_state_changed), handle);
```

我们在ICE的组件状态改变之后会执行janus_ice_cb_component_state_changed函数

```c
g_signal_connect (G_OBJECT (handle->agent), "new-candidate-full",
			G_CALLBACK (janus_ice_cb_new_local_candidate), handle);
```

我们在ICE获取新的完整candidate之后会执行janus_ice_cb_new_local_candidate，可以把candidate收集起来发送给客户端（trickle）

```c
nice_agent_attach_recv(handle->agent, handle->stream_id, 1, g_main_loop_get_context(handle->mainloop), janus_ice_cb_nice_recv, component);
```

我们在ICE收到数据的时候会执行janus_ice_cb_nice_recv函数

## janus_ice_cb_nice_recv

```c
/**
 * @brief 从ICE收到数据包
 * 
 * @param agent 
 * @param stream_id 
 * @param component_id 
 * @param len 
 * @param buf 
 * @param ice 
 */
static void janus_ice_cb_nice_recv(NiceAgent *agent, guint stream_id, guint component_id, guint len, gchar *buf, gpointer ice) {
    // 省略一些代码
	if(janus_is_dtls(buf) || (!janus_is_rtp(buf, len) && !janus_is_rtcp(buf, len))) {
		/* This is DTLS: either handshake stuff, or data coming from SCTP DataChannels 
		这是 DTLS：要么是握手的东西，要么是来自 SCTP 数据通道的数据 */
		janus_dtls_srtp_incoming_msg(component->dtls, buf, len);
		// 省略一些代码
		return;
	}
	/* Not DTLS... RTP or RTCP? (http://tools.ietf.org/html/rfc5761#section-4) 
	不是DTLS数据，判断是RTP还是RTCP */
	if(janus_is_rtp(buf, len)) {
		plugin->incoming_rtp(handle->app_handle, &rtp);
	} else if(janus_is_rtcp(buf, len)) {
		/* This is RTCP 如果是RTCP数据 暂不在此分析*/
		return;
	} else {
		/* 不是RTP 也不是RTCP 数据，可能是一些其他数据*/
		return;
	}
}
```

janus_ice_cb_nice_recv函数会把收到的数据包进行判断，到底是dtls，rtp还是rtcp数据，代码只处理上述三种数据，我们这里只关注rtp数据

janus_ice_cb_nice_recv在完成一系列的判断和设置之后，会调用该handle上插件的incoming_rtp函数，代码中如下：

```c
plugin->incoming_rtp(handle->app_handle, &rtp);
```

那么根据handle插件的不同，他们就会去到不同的插件进行处理，我们这里以videoroom为例

videoroom使用janus_videoroom_incoming_rtp函数来实现了incoming_rtp

## janus_videoroom_incoming_rtp

```c
/**
 * @brief 处理对方的传入RTP包
 *
 * @param handle
 * @param pkt
 */
void janus_videoroom_incoming_rtp(janus_plugin_session *handle, janus_plugin_rtp *pkt)
{
	// 省略一些判断
	/*获取session下的发布者*/
	janus_videoroom_publisher *participant = janus_videoroom_session_get_publisher_nodebug(session);
	// 省略一些判断
	janus_videoroom *videoroom = participant->room;

	gboolean video = pkt->video;
	char *buf = pkt->buffer;
	uint16_t len = pkt->length;
	/* In case this is an audio packet and we're doing talk detection, check the audio level extension
	如果这是一个音频数据包并且我们正在进行通话检测，请检查音频级别扩展*/
	if (!video && videoroom->audiolevel_event && participant->audio_active && !participant->audio_muted)
	{
				if (audio_dBov_avg < audio_level_average)
				{
					/* Participant talking, should we notify all participants? 参与者在说话，我们是否通知其他人？*/
				}
				else
				{
					/* Participant not talking anymore, should we notify all participants? 参与者没有在说话，我们是否通知其他人？*/
				}
				
				/* Only notify in case of state changes 只有状态改变的时候通知*/
				if (notify_talk_event)
				{
                    
				}
			}
		}
	}

	if ((!video && participant->audio_active && !participant->audio_muted) || (video && participant->video_active && !participant->video_muted))
	{
		//音频或者视频
		janus_rtp_header *rtp = (janus_rtp_header *)buf;
		int sc = video ? 0 : -1;
		if (video && (participant->ssrc[0] != 0 || participant->rid[0] != NULL))
		{
		GHashTableIter iter;
		gpointer value;
        //是否有rtp_forward
		g_hash_table_iter_init(&iter, participant->rtp_forwarders);
		/* 遍历用 于转发 rtp 数据包的 udp 套接字*/
		while (participant->udp_sock > 0 && g_hash_table_iter_next(&iter, NULL, &value))
		{
			janus_videoroom_rtp_forwarder *rtp_forward = (janus_videoroom_rtp_forwarder *)value;
			if (rtp_forward->is_data || (video && !rtp_forward->is_video) || (!video && rtp_forward->is_video))
				continue;
			/* First of all, check if we're simulcasting and if we need to forward or ignore this frame
			首先，检查我们是否在联播，是否需要转发或忽略此帧*/
			if (video && !rtp_forward->simulcast && rtp_forward->substream != sc)
			{
				continue;
			}
			else if (video && rtp_forward->simulcast)
			{
				/* This is video and we're simulcasting, check if we need to forward this frame
				这是视频，正在联播，请检查是否需要转发此帧*/
				if (!janus_rtp_simulcasting_context_process_rtp(&rtp_forward->sim_context,
																buf, len, participant->ssrc, participant->rid, participant->vcodec, &rtp_forward->context))
					continue;
			}
			检查这是 RTP 还是 SRTP 转发器 */
			if (!rtp_forward->is_srtp)
			{
				/* Plain RTP 普通RTP转发 */
				if (sendto(participant->udp_sock, buf, len, 0, address, addrlen) < 0)
			}
			else
			{
				/* SRTP: check if we already encrypted the packet before
				SRTP：检查我们之前是否已经加密过数据包 */
				if (rtp_forward->srtp_ctx->slen == 0)
				{
					/*如果没有解密秘钥*/
					
					}
				}
				if (rtp_forward->srtp_ctx->slen > 0)
				{
					/*如果有解密秘钥*/
					if (sendto(participant->udp_sock, rtp_forward->srtp_ctx->sbuf, rtp_forward->srtp_ctx->slen, 0, address, addrlen) < 0)
				}
			}
		}
		/* Save the frame if we're recording 保存关键帧 */
		if (!video || (participant->ssrc[0] == 0 && participant->rid[0] == NULL))
		{
			janus_recorder_save_frame(video ? participant->vrc : participant->arc, buf, len);
		}
		else
		{
			/* We're simulcasting, save the best video quality 我们正在联播，保存最好的视频质量 */
			gboolean save = janus_rtp_simulcasting_context_process_rtp(&participant->rec_simctx, buf, len, participant->ssrc, participant->rid, participant->vcodec, &participant->rec_ctx);
			if (save)
			{
				/*录制 */
			}
		}
		/* Done, relay it 转发 */
		janus_videoroom_rtp_relay_packet packet;
		if (video && videoroom->do_svc)
		/* Go: some viewers may decide to drop the packet, but that's up to them
		一些观众可能会决定丢弃数据包，但这取决于他们*/
            
		g_slist_foreach(participant->subscribers, janus_videoroom_relay_rtp_packet, &packet);

		/* Check if we need to send any REMB, FIR or PLI back to this publisher
		检查我们是否需要将任何 REMB、FIR 或 PLI 发送回此发布者 */
		if (video && participant->video_active && !participant->video_muted)
		{
			/* Generate FIR/PLI too, if needed 生产FIR/PLI 请求关键帧，如果需要*/
			if (video && participant->video_active && !participant->video_muted && (videoroom->fir_freq > 0))
			{
				// fir_freq 常规通过 FIR 请求关键帧的频率（0=禁用）单位秒
				if ((now - participant->fir_latest) >= ((gint64)videoroom->fir_freq * G_USEC_PER_SEC))
				{
					/* FIXME We send a FIR every tot seconds FIXME 我们每 t 秒发送一次 FIR */
					//通过pli 请求关键帧
					janus_videoroom_reqpli(participant, "Regular keyframe request");
				}
			}
		}
	}
	janus_videoroom_publisher_dereference_nodebug(participant);
}
```

janus_videoroom_incoming_rtp主要做了下面一些事情：

1.如果传来了音频数据，分析发布者是否处于讲话状态，如果状态发生改变，则通知房间里所有人

2.判断该发布者是否存在rtp_forward转发

3.判断rtp是否加密，如果加密，判断我们是否有加解密秘钥

4.进行rtp_forward转发

5.判断发布者音视频是否需要录制，如果需要则进行录制

6.遍历该发布者的订阅者，调用janus_videoroom_relay_rtp_packet，为他们每一个转发rtp

7.根据设置，决定是否选择向发布者请求关键帧



## janus_videoroom_relay_rtp_packet

```c
/* Helper to quickly relay RTP packets from publishers to subscribers
快速将 RTP 数据包从发布者转发到订阅者 */
static void janus_videoroom_relay_rtp_packet(gpointer data, gpointer user_data)
{
	janus_videoroom_rtp_relay_packet *packet = (janus_videoroom_rtp_relay_packet *)user_data;
	// 省略
	janus_videoroom_subscriber *subscriber = (janus_videoroom_subscriber *)data;
	// 省略
	janus_videoroom_session *session = subscriber->session;
	// 省略
	/* Make sure there hasn't been a publisher switch by checking the SSRC
	通过检查 SSRC 确保没有发布者切换 */
	if (packet->is_video)
	{
		/* Check if this subscriber is subscribed to this medium 检查此订阅者是否订阅了此媒体 */
		// 省略
		/* Check if there's any SVC info to take into account
		检查是否有任何 SVC 信息需要考虑 */
		// 省略
			//处理普通视频
			/* Send the packet 发送视频包*/
			if (gateway != NULL)
			{
				janus_plugin_rtp rtp = {.video = packet->is_video, .buffer = (char *)packet->data, .length = packet->length, .extensions = packet->extensions};
				gateway->relay_rtp(session->handle, &rtp);
			}
		}
	}
	else
	{
		/* Send the packet 发送音频包*/
		if (gateway != NULL)
		{
			janus_plugin_rtp rtp = {.video = packet->is_video, .buffer = (char *)packet->data, .length = packet->length, .extensions = packet->extensions};
			gateway->relay_rtp(session->handle, &rtp);
		}
	}

	return;
}
```

进入到janus_videoroom_relay_rtp_packet之后，根据每一个不同订阅者它所期待的设置，我们在前面会做一大批处理，当然这不是我们现在讨论的重点，最后我们可以简单的把该函数看成处理两个核心的内容，就是通过调用gateway->relay_rtp(session->handle, &rtp);发送视频包，和发送音频包。

那么很显然，任务重心又从插件回到了janus核心本身。

## janus_plugin_relay_rtp

```c
/**
 * @brief 插件转发rtp数据
 * 
 * @param plugin_session 
 * @param packet 
 */
void janus_plugin_relay_rtp(janus_plugin_session *plugin_session, janus_plugin_rtp *packet) {
	if((plugin_session < (janus_plugin_session *)0x1000) || g_atomic_int_get(&plugin_session->stopped) ||
			packet == NULL || packet->buffer == NULL || packet->length < 1)
		return;
	janus_ice_handle *handle = (janus_ice_handle *)plugin_session->gateway_handle;
	if(!handle || janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP)
			|| janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT))
		return;
	janus_ice_relay_rtp(handle, packet);
}
```

## janus_ice_relay_rtp

```c
/**
 * @brief ICE转发RTP数据
 * 
 * @param handle 
 * @param packet 
 */
void janus_ice_relay_rtp(janus_ice_handle *handle, janus_plugin_rtp *packet) {
    //省略
	janus_ice_queue_packet(handle, pkt);
	 //省略
}
```

## janus_ice_queue_packet

```c
/**
 * @brief 入队RTP/RTCP包 供ICE传输
 * 
 * @param handle 
 * @param pkt 
 */
static void janus_ice_queue_packet(janus_ice_handle *handle, janus_ice_queued_packet *pkt) {
	/* TODO: There is a potential race condition where the "queued_packets"
	 * could get released between the condition and pushing the packet.
	 存在潜在的竞争条件，其中“queued_packets”可能在推送数据包之间被释放  */
	if(handle->queued_packets != NULL) {
		g_async_queue_push(handle->queued_packets, pkt);
		g_main_context_wakeup(handle->mainctx);
	} else {
		janus_ice_free_queued_packet(pkt);
	}
}
```

## janus_ice_outgoing_traffic_dispatch

```c
/**
 * @brief 传出流量的分配处理
 * 
 * @param source 
 * @param callback 
 * @param user_data 
 * @return gboolean 
 */
static gboolean janus_ice_outgoing_traffic_dispatch(GSource *source, GSourceFunc callback, gpointer user_data) {
	janus_ice_outgoing_traffic *t = (janus_ice_outgoing_traffic *)source;
	int ret = G_SOURCE_CONTINUE;
	janus_ice_queued_packet *pkt = NULL;
	while((pkt = g_async_queue_try_pop(t->handle->queued_packets)) != NULL) {
		if(janus_ice_outgoing_traffic_handle(t->handle, pkt) == G_SOURCE_REMOVE)
			ret = G_SOURCE_REMOVE;
	}
	return ret;
}

```

## janus_ice_outgoing_traffic_handle

```c
/**
 * @brief 用于传出的流量处理
 * 
 * @param handle 
 * @param pkt 
 * @return gboolean 
 */
static gboolean janus_ice_outgoing_traffic_handle(janus_ice_handle *handle, janus_ice_queued_packet *pkt) {
    //省略
	/* RTP or data */
	if(pkt->type == JANUS_ICE_PACKET_AUDIO || pkt->type == JANUS_ICE_PACKET_VIDEO) {
	/* RTP */
		int video = (pkt->type == JANUS_ICE_PACKET_VIDEO);
		if(pkt->encrypted) {
		janus_rtp_header *header = (janus_rtp_header *)pkt->data;
		int sent = nice_agent_send(handle->agent, stream->stream_id, component->component_id, pkt->length, (const gchar *)pkt->data);
            }
        }
     //省略
}
```



Janus WebRTC Server
===================

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-brightgreen.svg)](COPYING)
![janus-ci](https://github.com/meetecho/janus-gateway/workflows/janus-ci/badge.svg)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/13265/badge.svg)](https://scan.coverity.com/projects/meetecho-janus-gateway)
[![Fuzzing Status](https://oss-fuzz-build-logs.storage.googleapis.com/badges/janus-gateway.svg)](https://bugs.chromium.org/p/oss-fuzz/issues/list?sort=-opened&can=1&q=proj:janus-gateway)

Janus is an open source, general purpose, WebRTC server designed and developed by [Meetecho](https://www.meetecho.com). This version of the server is tailored for Linux systems, although it can be compiled for, and installed on, MacOS machines as well. Windows is not supported, but if that's a requirement, Janus is known to work in the "Windows Subsystem for Linux" on Windows 10: do **NOT** trust repos that provide .exe builds of Janus, they are not official and will not be supported.

Janus 是一个Meetecho设计开发的开源通用WebRTC服务器。这个版本这是为Linux系统量身定做的服务器，虽然它也可以编译运行在MacOS上，目前暂不支持Windows系统。但如果必须要求运行Windows系统上，只能通过Windows 10运行Linux虚拟机的方法去解决。别相信任何宣称是Janus打包提供的.exe文件，它不是官方的，并且不会获得支持。

For some online demos and documentations, make sure you pay the [project website](https://janus.conf.meetecho.com/) a visit!

如果想要观看线上demos和文档，您可以访问[项目网站](https://janus.conf.meetecho.com/)

If you have questions on Janus, or wish to discuss Janus with us and other users, please join our [meetecho-janus](https://groups.google.com/forum/#!forum/meetecho-janus) Google Group. If you encounter bugs, please submit an issue on [GitHub](https://github.com/meetecho/janus-gateway/issues): make sure you read the [guidelines](.github/ISSUE_TEMPLATE.md) before opening an issue, though.

如果您有关于Janus的任何问题，和希望和我们其他用户一起讨论，请加入我们的Google Group[meetecho-janus](https://groups.google.com/forum/#!forum/meetecho-janus)。如果您发现了bugs，请在[GitHub](https://github.com/meetecho/janus-gateway/issues)提交问题，但是您提交问题之前，请确保您阅读了[指南](.github/ISSUE_TEMPLATE.md)

## Dependencies
To install it, you'll need to satisfy the following dependencies:

为了去安装Janus，您需要去安装以下特定的依赖

* [Jansson](http://www.digip.org/jansson/)
* [libconfig](https://hyperrealm.github.io/libconfig/)
* [libnice](https://libnice.freedesktop.org/) (at least v0.1.16 suggested, v0.1.18 recommended)
* [OpenSSL](http://www.openssl.org/) (at least v1.0.1e)
* [libsrtp](https://github.com/cisco/libsrtp) (at least v2.x suggested)
* [usrsctp](https://github.com/sctplab/usrsctp) (only needed if you are interested in Data Channels)
* [libmicrohttpd](http://www.gnu.org/software/libmicrohttpd/) (at least v0.9.59; only needed if you are interested in REST support for the Janus API)
* [libwebsockets](https://libwebsockets.org/) (only needed if you are interested in WebSockets support for the Janus API)
* [cmake](http://www.cmake.org/) (only needed if you are interested in WebSockets and/or BoringSSL support, as they make use of it)
* [rabbitmq-c](https://github.com/alanxz/rabbitmq-c) (only needed if you are interested in RabbitMQ support for the Janus API or events)
* [paho.mqtt.c](https://eclipse.org/paho/clients/c) (only needed if you are interested in MQTT support for the Janus API or events)
* [nanomsg](https://nanomsg.org/) (only needed if you are interested in Nanomsg support for the Janus API)
* [libcurl](https://curl.haxx.se/libcurl/) (only needed if you are interested in the TURN REST API support)

A couple of plugins depend on a few more libraries:

一些插件所依赖于的第三方库

* [Sofia-SIP](http://sofia-sip.sourceforge.net/) (only needed for the SIP plugin)
* [libopus](http://opus-codec.org/) (only needed for the AudioBridge plugin)
* [libogg](http://xiph.org/ogg/) (needed for the VoiceMail plugin and/or post-processor, and optionally AudioBridge and Streaming plugins)
* [libcurl](https://curl.haxx.se/libcurl/) (only needed if you are interested in RTSP support in the Streaming plugin or in the sample Event Handler plugin)
* [Lua](https://www.lua.org/download.html) (only needed for the Lua plugin)

Additionally, you'll need the following libraries and tools:

此外，您还需要以下库和工具：

* [GLib](http://library.gnome.org/devel/glib/)
* [zlib](https://zlib.net/)
* [pkg-config](http://www.freedesktop.org/wiki/Software/pkg-config/)
* [gengetopt](http://www.gnu.org/software/gengetopt/)

All of those libraries are usually available on most of the most common distributions. Installing these libraries on a recent Fedora, for instance, is very simple:

所有这些库通常在大多数最常见的发行版上都可用。 例如，在最近的 Fedora 上安装这些库非常简单
    
	yum install libmicrohttpd-devel jansson-devel \
	   openssl-devel libsrtp-devel sofia-sip-devel glib2-devel \
	   opus-devel libogg-devel libcurl-devel pkgconfig gengetopt \
	   libconfig-devel libtool autoconf automake

Notice that you may have to `yum install epel-release` as well if you're attempting an installation on a CentOS machine instead.

请注意，如果您尝试在 CentOS 机器上安装，您可能还需要 `yum install epel-release`。

On Ubuntu or Debian, it would require something like this:

在 Ubuntu 或 Debian 上，它需要安装以下内容：
	
	aptitude install libmicrohttpd-dev libjansson-dev \
		libssl-dev libsrtp-dev libsofia-sip-ua-dev libglib2.0-dev \
		libopus-dev libogg-dev libcurl4-openssl-dev liblua5.3-dev \
		libconfig-dev pkg-config gengetopt libtool automake

* *Note:* please notice that libopus may not be available out of the box on your distro. In that case, you'll have to [install it manually](http://www.opus-codec.org).

* *Note:* 请注意，您的发行版中可能没有开箱即用的 libopus。 在这种情况下，您必须[手动安装](http://www.opus-codec.org)。

While `libnice` is typically available in most distros as a package, the version available out of the box in Ubuntu is known to cause problems. As such, we always recommend manually compiling and installing the master version of libnice.
To build libnice, you need Python 3, Meson and Ninja:

虽然 `libnice` 通常在大多数发行版中作为一个软件包提供，但已知 Ubuntu 中的开箱即用版本会导致问题。 因此，我们始终建议手动编译和安装 libnice 的主版本。要构建 libnice，您需要 Python 3、Meson 和 Ninja

	git clone https://gitlab.freedesktop.org/libnice/libnice
	cd libnice
	meson --prefix=/usr build && ninja -C build && sudo ninja -C build install

* *Note:* Make sure you remove the distro version first, or you'll cause conflicts between the installations. In case you want to keep both for some reason, for custom installations of libnice you can also run `pkg-config --cflags --libs nice` to make sure Janus can find the right installation. If that fails, you may need to set the `PKG_CONFIG_PATH` environment variable prior to compiling Janus, e.g., `export PKG_CONFIG_PATH=/path/to/libnice/lib/pkgconfig`

* *Note:* 确保先删除发行版，否则会导致安装之间发生冲突。 如果您出于某种原因想要保留两者，对于 libnice 的自定义安装，您还可以运行 `pkg-config --cflags --libs nice` 以确保 Janus 可以找到正确的安装。 如果失败，您可能需要在编译 Janus 之前设置 `PKG_CONFIG_PATH` 环境变量，例如，`export PKG_CONFIG_PATH=/path/to/libnice/lib/pkgconfig`

In case you're interested in compiling the sample Event Handler plugin, you'll need to install the development version of libcurl as well (usually `libcurl-devel` on Fedora/CentOS, `libcurl4-openssl-dev` on Ubuntu/Debian).

如果您对编译示例事件处理程序插件感兴趣，您还需要安装 libcurl 的开发版本（通常在 Fedora/CentOS 上为“libcurl-devel”，在 Ubuntu/Debian 上为“libcurl4-openssl-dev” ）。

If your distro ships a pre-1.5 version of libsrtp, you'll have to uninstall that version and [install 1.5.x, 1.6.x or 2.x manually](https://github.com/cisco/libsrtp/releases). In fact, 1.4.x is known to cause several issues with WebRTC. While 1.5.x is supported, we recommend installing 2.x instead Notice that the following steps are for version 2.2.0, but there may be more recent versions available:

如果您使用了1.5之前的libsrtp版本，您必须卸载该版本并 [手动安装 1.5.x、1.6.x 或 2.x](https://github.com/cisco/libsrtp/releases ）。 事实上，已知 1.4.x 会导致 WebRTC 出现一些问题。 虽然支持 1.5.x，但我们建议安装 2.x 请注意，以下步骤适用于版本 2.2.0，但可能有更新的版本可用：

	wget https://github.com/cisco/libsrtp/archive/v2.2.0.tar.gz
	tar xfv v2.2.0.tar.gz
	cd libsrtp-2.2.0
	./configure --prefix=/usr --enable-openssl
	make shared_library && sudo make install

Notice that the `--enable-openssl` part is _important_, as it's needed for AES-GCM support. As an alternative, you can also pass `--enable-nss` to have libsrtp use NSS instead of OpenSSL. A failure to configure libsrtp with either might cause undefined references when starting Janus, as we'd be trying to use methods that aren't there.

注意，`--enable-openssl`部分是非常注意的，它是AES-GCM支持所需要的，作为备选项，您可以输入`--enable-nss`去让libstrp使用USS而不是openssl,否则，在Janus开始配置libsrtp的时候可能会出现未找到定义引用的错误，它可能在使用不存在的方法。


The Janus configure script autodetects which one you have installed and links to the correct library automatically, choosing 2.x if both are installed. If you want 1.5 or 1.6 to be picked (which is NOT recommended), pass `--disable-libsrtp2` when configuring Janus to force it to use the older version instead.

Janus 配置脚本会自动检测您安装了哪个库并自动链接到正确的库，如果两者都安装了则选择 2.x。 如果您希望选择 1.5 或 1.6（不推荐），请在配置 Janus 时传递 `--disable-libsrtp2` 以强制它使用旧版本。

* *Note:* when installing libsrtp, no matter which version, you may need to pass `--libdir=/usr/lib64` to the configure script if you're installing on a x86_64 distribution.

* *Note:* 安装 libsrtp 时，无论是哪个版本，如果您在 x86_64 发行版上安装，您可能需要将 `--libdir=/usr/lib64` 传递给配置脚本。

If you want to make use of BoringSSL instead of OpenSSL (e.g., because you want to take advantage of `--enable-dtls-settimeout`), you'll have to manually install it to a specific location. Use the following steps:

如果您想使用 BoringSSL 而不是 OpenSSL（例如，因为您想利用 `--enable-dtls-settimeout`），则必须手动将其安装到特定位置。 使用以下步骤：

	git clone https://boringssl.googlesource.com/boringssl
	cd boringssl
	# Don't barf on errors
	sed -i s/" -Werror"//g CMakeLists.txt
	# Build
	mkdir -p build
	cd build
	cmake -DCMAKE_CXX_FLAGS="-lrt" ..
	make
	cd ..
	# Install
	sudo mkdir -p /opt/boringssl
	sudo cp -R include /opt/boringssl/
	sudo mkdir -p /opt/boringssl/lib
	sudo cp build/ssl/libssl.a /opt/boringssl/lib/
	sudo cp build/crypto/libcrypto.a /opt/boringssl/lib/

Once the library is installed, you'll have to pass an additional `--enable-boringssl` flag to the configure script, as by default Janus will be built assuming OpenSSL will be used. By default, Janus expects BoringSSL to be installed in `/opt/boringssl` -- if it's installed in another location, pass the path to the configure script as such: `--enable-boringssl=/path/to/boringssl` If you were using OpenSSL and want to switch to BoringSSL, make sure you also do a `make clean` in the Janus folder before compiling with the new BoringSSL support. If you enabled BoringSSL support and also want Janus to detect and react to DTLS timeouts with faster retransmissions, then pass `--enable-dtls-settimeout` to the configure script too.

安装库后，您必须将附加的 `--enable-boringssl` 标志传递给配置脚本，因为默认情况下，将使用 OpenSSL 构建 Janus。 默认情况下，Janus 期望 BoringSSL 安装在 `/opt/boringssl` 中——如果它安装在另一个位置，则将路径传递给配置脚本，如下所示：`--enable-boringssl=/path/to/boringssl` 如果 您正在使用 OpenSSL 并希望切换到 BoringSSL，请确保在使用新的 BoringSSL 支持进行编译之前还在 Janus 文件夹中执行“make clean”。 如果您启用了 BoringSSL 支持，并且还希望 Janus 以更快的重传速度检测和响应 DTLS 超时，那么也将 `--enable-dtls-settimeout` 传递给配置脚本。

For what concerns usrsctp, which is needed for Data Channels support, it is usually not available in repositories, so if you're interested in them (support is optional) you'll have to install it manually. It is a pretty easy and standard process:

对于数据通道支持所需的 usrsctp，它通常在存储库中不可用，因此如果您对它们感兴趣（支持是可选的），您必须手动安装它。 这是一个非常简单和标准的过程：

	git clone https://github.com/sctplab/usrsctp
	cd usrsctp
	./bootstrap
	./configure --prefix=/usr --disable-programs --disable-inet --disable-inet6
	make && sudo make install

* *Note:* you may need to pass `--libdir=/usr/lib64` to the configure script if you're installing on a x86_64 distribution.

* *Note:* 如果您在 x86_64 发行版上安装，您可能需要将 `--libdir=/usr/lib64` 传递给配置脚本。

The same applies for libwebsockets, which is needed for the optional WebSockets support. If you're interested in supporting WebSockets to control Janus, as an alternative (or replacement) to the default plain HTTP REST API, you'll have to install it manually:

这同样适用于 libwebsockets，这是可选的 WebSockets 支持。 如果您有兴趣支持 WebSockets 来控制 Janus，作为默认纯 HTTP REST API 的替代，您必须手动安装它：

	git clone https://libwebsockets.org/repo/libwebsockets
	cd libwebsockets
	# If you want the stable version of libwebsockets, uncomment the next line
	# git checkout v3.2-stable
	mkdir build
	cd build
	# See https://github.com/meetecho/janus-gateway/issues/732 re: LWS_MAX_SMP
	# See https://github.com/meetecho/janus-gateway/issues/2476 re: LWS_WITHOUT_EXTENSIONS
	cmake -DLWS_MAX_SMP=1 -DLWS_WITHOUT_EXTENSIONS=0 -DCMAKE_INSTALL_PREFIX:PATH=/usr -DCMAKE_C_FLAGS="-fpic" ..
	make && sudo make install

* *Note:* if libwebsockets.org is unreachable for any reason, replace the first line with this:

* *Note:* 如果libwebsockets.org由于某些原因已经不可访问了，用下面内容替换掉第一行

	git clone https://github.com/warmcat/libwebsockets.git

The same applies for Eclipse Paho MQTT C client library, which is needed for the optional MQTT support. If you're interested in integrating MQTT channels as an alternative (or replacement) to HTTP and/or WebSockets to control Janus, or as a carrier of Janus Events, you can install the latest version with the following steps:

这同样适用于 Eclipse Paho MQTT C 客户端库，这是可选的 MQTT 支持。 如果您有兴趣集成 MQTT 通道作为 HTTP 和/或 WebSockets 的替代来控制 Janus，或者作为 Janus 事件的载体，您可以通过以下步骤安装最新版本：

	git clone https://github.com/eclipse/paho.mqtt.c.git
	cd paho.mqtt.c
	make && sudo make install

* *Note:* you may want to set up a different install path for the library, to achieve that, replace the last command by 'sudo prefix=/usr make install'.

* *Note:* 您可能希望为库设置不同的安装路径，为此，将最后一个命令替换为“sudo prefix=/usr make install”。

In case you're interested in Nanomsg support, you'll need to install the related C library. It is usually available as an easily installable package in pretty much all repositories. The following is an example on how to install it on Ubuntu:

如果您对 Nanomsg 支持感兴趣，您需要安装相关的 C 库。 它通常作为一个易于安装的包在几乎所有存储库中提供。 以下是如何在 Ubuntu 上安装它的示例：

	aptitude install libnanomsg-dev

Finally, the same can be said for rabbitmq-c as well, which is needed for the optional RabbitMQ support. In fact, several different versions of the library can be found, and the versions usually available in most distribution repositories are not up-do-date with respect to the current state of the development. As such, if you're interested in integrating RabbitMQ queues as an alternative (or replacement) to HTTP and/or WebSockets to control Janus, you can install the latest version with the following steps:

最后，rabbitmq-c 也是一样的，这是可选的 RabbitMQ 支持。 事实上，在发行系统上可以找到几个不同版本的库，并且大多数分发存储库中通常可用的版本相对于当前的开发状态并不是最新的。 因此，如果您有兴趣集成 RabbitMQ 队列作为 HTTP 和/或 WebSockets 的替代来控制 Janus，您可以通过以下步骤安装最新版本：

	git clone https://github.com/alanxz/rabbitmq-c
	cd rabbitmq-c
	git submodule init
	git submodule update
	mkdir build && cd build
	cmake -DCMAKE_INSTALL_PREFIX=/usr ..
	make && sudo make install

* *Note:* you may need to pass `--libdir=/usr/lib64` to the configure script if you're installing on a x86_64 distribution.

* *Note:* 如果您在 x86_64 发行版上安装，您可能需要将 `--libdir=/usr/lib64` 传递给配置脚本。

To conclude, should you be interested in building the Janus documentation as well, you'll need some additional tools too:

最后，如果您也对构建 Janus 文档感兴趣，您还需要一些额外的工具：

* [Doxygen](http://www.doxygen.org)
* [Graphviz](http://www.graphviz.org/)

On Fedora:

	yum install doxygen graphviz

On Ubuntu/Debian:

	aptitude install doxygen graphviz


## Compile
Once you have installed all the dependencies, get the code:

一旦您已经安装完所有依赖，您可以运行下面命令：

	git clone https://github.com/meetecho/janus-gateway.git
	cd janus-gateway

Then just use:

然后使用：

	sh autogen.sh

to generate the configure file. After that, configure and compile as usual to start the whole compilation process:

生成配置文件。 之后，像往常一样配置和编译，开始整个编译过程：

	./configure --prefix=/opt/janus
	make
	make install

Since Janus requires configuration files for both the core and its modules in order to work, you'll probably also want to install the default configuration files to use, which you can do this way:

由于 Janus 需要核心及其模块的配置文件才能工作，因此您可能还需要安装要使用的默认配置文件，您可以这样做：

	make configs

Remember to only do this once, or otherwise a subsequent `make configs` will overwrite any configuration file you may have modified in the meanwhile.

请记住只执行一次，否则后续的`make configs`将覆盖您同时修改的任何配置文件。

If you've installed the above libraries but are not interested, for instance, in Data Channels, WebSockets, MQTT and/or RabbitMQ, you can disable them when configuring:

如果您已经安装了上述库但不想使用，例如对 Data Channels、WebSockets、MQTT 和/或 RabbitMQ，您可以在配置时禁用它们：

	./configure --disable-websockets --disable-data-channels --disable-rabbitmq --disable-mqtt

There are configuration flags for pretty much all external modules and many of the features, so you may want to issue a `./configure --help` to dig through the available options. A summary of what's going to be built will always appear after you do a configure, allowing you to double check if what you need and don't need is there.

几乎所有外部模块和许多功能都有配置标志，因此您可能需要发出 `./configure --help` 来挖掘可用选项。在您进行配置后，将始终显示将要构建的内容的摘要，让您可以仔细检查您需要和不需要的内容是否存在。

If Doxygen and graphviz are available, the process can also build the documentation for you. By default the compilation process will not try to build the documentation, so if you instead prefer to build it, use the `--enable-docs` configuration option:

如果 Doxygen 和 graphviz 可用，该过程还可以为您构建文档。 默认情况下，编译过程不会尝试构建文档，因此如果您更喜欢构建它，请使用 `--enable-docs` 配置选项：

	./configure --enable-docs

You can also selectively enable/disable other features (e.g., specific plugins you don't care about, or whether or not you want to build the recordings post-processor). Use the --help option when configuring for more info.

您还可以选择性地启用/禁用其他功能（例如，您不关心的特定插件，或者您是否要构建录制后置处理器）。 配置时使用 --help 选项以获取更多信息。

### Building on FreeBSD
* *Note*: rtp_forward of streams only works streaming to IPv6, because of #2051 and thus the feature is not supported on FreeBSD at the moment.
* *Note*: 由于#2051，streams的 rtp_forward 仅适用于streaming到 IPv6，因此 FreeBSD 目前不支持该功能。

When building on FreeBSD you can install the depencencies from ports or packages, here only pkg method is used. You also need to use `gmake` instead of `make`,
since it is a GNU makefile. `./configure` can be run without arguments since the default prefix is `/usr/local` which is your default `LOCALBASE`.
Note that the `configure.ac` is coded to use openssl in base. If you wish to use openssl from ports or any other ssl you must change `configure.ac` accordingly.

在 FreeBSD 上构建时，您可以从端口或软件包安装依赖项，这里只使用 pkg 方法。 您还需要使用 `gmake` 而不是 `make`，
因为它是一个 GNU makefile。 `./configure` 可以不带参数运行，因为默认前缀是 `/usr/local`，这是您的默认 `LOCALBASE`。
请注意，`configure.ac` 被编码为在 base 中使用 openssl。 如果您希望从端口或任何其他 ssl 使用 openssl，您必须相应地更改 `configure.ac`。

	pkg install libsrtp2 libusrsctp jansson libnice libmicrohttpd libwebsockets curl opus sofia-sip libogg jansson libnice libconfig \
	    libtool gmake autoconf autoconf-wrapper glib gengetopt


### Building on MacOS
While most of the above instructions will work when compiling Janus on MacOS as well, there are a few aspects to highlight when doing that.

虽然上述大部分说明在 MacOS 上编译 Janus 时也可以使用，但在执行此操作时有几个方面需要强调。

First of all, you can use `brew` to install most of the dependencies:

	brew install jansson libnice openssl srtp libusrsctp libmicrohttpd \
		libwebsockets cmake rabbitmq-c sofia-sip opus libogg curl glib \
		libconfig pkg-config gengetopt autoconf automake libtool

For what concerns libwebsockets, though, make sure that the installed version is higher than `2.4.1`, or you might encounter the problems described in [this post](https://groups.google.com/forum/#!topic/meetecho-janus/HsFaEXBz4Cg). If `brew` doesn't provide a more recent version, you'll have to install the library manually.

但是，对于 libwebsockets 的问题，请确保安装的版本高于 `2.4.1`，否则您可能会遇到 [this post](https://groups.google.com/forum/#!topic) 中描述的问题 /meetecho-janus/HsFaEXBz4Cg)。 如果 `brew` 没有提供更新的版本，您必须手动安装该库。

Notice that you may need to provide a custom `prefix` and `PKG_CONFIG_PATH` when configuring Janus as well, e.g.:

请注意，在配置 Janus 时，您可能还需要提供自定义的 `prefix` 和 `PKG_CONFIG_PATH`，例如：

	./configure --prefix=/usr/local/janus PKG_CONFIG_PATH=/usr/local/opt/openssl/lib/pkgconfig

Everything else works exactly the same way as on Linux.

其他一切的工作方式与 Linux 上的完全相同。

## Configure and start
To start the server, you can use the `janus` executable. There are several things you can configure, either in a configuration file:

要启动服务器，您可以使用 `janus` 可执行文件。 您可以在配置文件中配置几项内容：

	<installdir>/etc/janus/janus.jcfg

or on the command line:

或通过命令行参数：

	<installdir>/bin/janus --help
	
	Usage: janus [OPTIONS]...
	
	-h, --help                    Print help and exit
	-V, --version                 Print version and exit
	-b, --daemon                  Launch Janus in background as a daemon
	                              (default=off)
	-p, --pid-file=path           Open the specified PID file when starting Janus
	                              (default=none)
	-N, --disable-stdout          Disable stdout based logging  (default=off)
	-L, --log-file=path           Log to the specified file (default=stdout only)
	-H  --cwd-path                Working directory for Janus daemon process
	                              (default=/)
	-i, --interface=ipaddress     Interface to use (will be the public IP)
	-P, --plugins-folder=path     Plugins folder (default=./plugins)
	-C, --config=filename         Configuration file to use
	-F, --configs-folder=path     Configuration files folder (default=./conf)
	-c, --cert-pem=filename       DTLS certificate
	-k, --cert-key=filename       DTLS certificate key
	-K, --cert-pwd=text           DTLS certificate key passphrase (if needed)
	-S, --stun-server=address:port
	                              STUN server(:port) to use, if needed (e.g.,
	                              Janus behind NAT, default=none)
	-1, --nat-1-1=ip              Public IP to put in all host candidates,
	                              assuming a 1:1 NAT is in place (e.g., Amazon
	                              EC2 instances, default=none)
	-2, --keep-private-host       When nat-1-1 is used (e.g., Amazon EC2
	                              instances), don't remove the private host,
	                              but keep both to simulate STUN  (default=off)
	-E, --ice-enforce-list=list   Comma-separated list of the only interfaces to
	                              use for ICE gathering; partial strings are
	                              supported (e.g., eth0 or eno1,wlan0,
	                              default=none)
	-X, --ice-ignore-list=list    Comma-separated list of interfaces or IP
	                              addresses to ignore for ICE gathering;
	                              partial strings are supported (e.g.,
	                              vmnet8,192.168.0.1,10.0.0.1 or
	                              vmnet,192.168., default=vmnet)
	-6, --ipv6-candidates         Whether to enable IPv6 candidates or not
	                              (experimental)  (default=off)
	-O, --ipv6-link-local         Whether IPv6 link-local candidates should be
	                              gathered as well  (default=off)
	-l, --libnice-debug           Whether to enable libnice debugging or not
	                              (default=off)
	-f, --full-trickle            Do full-trickle instead of half-trickle
	                              (default=off)
	-I, --ice-lite                Whether to enable the ICE Lite mode or not
	                              (default=off)
	-T, --ice-tcp                 Whether to enable ICE-TCP or not (warning: only
	                              works with ICE Lite)
	                              (default=off)
	-Q, --min-nack-queue=number   Minimum size of the NACK queue (in ms) per user
	                              for retransmissions, no matter the RTT
	-t, --no-media-timer=number   Time (in s) that should pass with no media
	                              (audio or video) being received before Janus
	                              notifies you about this
	-W, --slowlink-threshold=number
	                              Number of lost packets (per s) that should
	                              trigger a 'slowlink' Janus API event to users
	                              (default=0, feature disabled)
	-r, --rtp-port-range=min-max  Port range to use for RTP/RTCP (only available
								  if the installed libnice supports it)
	-B, --twcc-period=number      How often (in ms) to send TWCC feedback back to
	                              senders, if negotiated (default=200ms)
	-n, --server-name=name        Public name of this Janus instance
	                              (default=MyJanusInstance)
	-s, --session-timeout=number  Session timeout value, in seconds (default=60)
	-m, --reclaim-session-timeout=number
	                              Reclaim session timeout value, in seconds
	                              (default=0)
	-d, --debug-level=1-7         Debug/logging level (0=disable debugging,
	                              7=maximum debug level; default=4)
	-D, --debug-timestamps        Enable debug/logging timestamps  (default=off)
	-o, --disable-colors          Disable color in the logging  (default=off)
	-M, --debug-locks             Enable debugging of locks/mutexes (very
	                              verbose!)  (default=off)
	-a, --apisecret=randomstring  API secret all requests need to pass in order
	                              to be accepted by Janus (useful when wrapping
	                              Janus API requests in a server, none by
	                              default)
	-A, --token-auth              Enable token-based authentication for all
	                              requests  (default=off)
	-e, --event-handlers          Enable event handlers  (default=off)
	-w, --no-webrtc-encryption    Disable WebRTC encryption, so no DTLS or SRTP
	                              (only for debugging!)  (default=off)


Options passed through the command line have the precedence on those specified in the configuration file. To start the server, simply run:

通过命令行传递的选项优先于配置文件中指定的选项。 要启动服务器，只需运行：

	<installdir>/bin/janus

This will start the server, and have it look at the configuration file.

这将启动服务器，并让它查看配置文件。

Make sure you have a look at all of the configuration files, to tailor Janus to your specific needs: each configuration file is documented, so it shouldn't be hard to make changes according to your requirements. The repo comes with some defaults (assuming you issues `make configs` after installing the server) that tend to make sense for generic deployments, and also includes some sample configurations for all the plugins (e.g., web servers to listen on, conference rooms to create, streaming mountpoints to make available at startup, etc.).

确保您查看了所有配置文件，以根据您的特定需求定制 Janus：每个配置文件都有文档记录，因此根据您的要求进行更改应该不难。 该 配置文件 带有一些默认值（假设您在安装服务器后发出`make configs`），这往往对通用部署有意义，并且还包括所有插件的一些示例配置（例如，要监听的 Web 服务器、会议室 创建、流式传输mountpoints以在启动时可用等）。

To test whether it's working correctly, you can use the demos provided with this package in the `html` folder: these are exactly the same demos available online on the [project website](https://janus.conf.meetecho.com/). Just copy the file it contains in a webserver, or use a userspace webserver to serve the files in the `html` folder (e.g., with php or python), and open the `index.html` page in either Chrome or Firefox. A list of demo pages exploiting the different plugins will be available. Remember to edit the transport/port details in the demo JavaScript files if you changed any transport-related configuration from its defaults. Besides, the demos refer to the pre-configured plugin resources, so if you add some new resources (e.g., a new videoconference) you may have to tweak the demo pages to actually use them.

要测试它是否正常工作，您可以使用 `html` 文件夹中此软件包提供的演示：这些演示与 [项目网站]（https://janus.conf.meetecho.com/ ）上在线提供的演示完全相同。

## Documentation
Janus is thoroughly documented. You can find the current documentation, automatically generated with Doxygen, on the [project website](https://janus.conf.meetecho.com/docs/).

Janus 有完整的文档记录。 您可以在 [项目网站](https://janus.conf.meetecho.com/docs/) 上找到使用 Doxygen 自动生成的当前文档。

## Help us!
Any thought, feedback or (hopefully not!) insult is welcome!

Developed by [@meetecho](https://github.com/meetecho)
