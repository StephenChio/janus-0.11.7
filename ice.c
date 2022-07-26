/*! \file    ice.c
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    ICE/STUN/TURN processing
 * \details  Implementation (based on libnice) of the ICE process. The
 * code handles the whole ICE process, from the gathering of candidates
 * to the final setup of a virtual channel RTP and RTCP can be transported
 * on. Incoming RTP and RTCP packets from peers are relayed to the associated
 * plugins by means of the incoming_rtp and incoming_rtcp callbacks. Packets
 * to be sent to peers are relayed by peers invoking the relay_rtp and
 * relay_rtcp core callbacks instead.
 * ICE 进程的实现（基于 libnice）。 该代码处理整个 ICE 过程，
 * 从候选者的收集到可以传输RTP 和 RTCP的虚拟通道的最终设置。 
 * 通过incoming_rtp 和incoming_rtcp 回调将来自对端传入RTP和RTCP数据包转发到相关插件。
 * 要发送到对端的数据包由调用relay_rtp和relay_rtcp核心回调进行转发。
 *
 * \ingroup protocols
 * \ref protocols
 */

#include <ifaddrs.h>
#include <poll.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <fcntl.h>
#include <stun/usages/bind.h>
#include <nice/debug.h>

#include "janus.h"
#include "debug.h"
#include "ice.h"
#include "turnrest.h"
#include "sdp.h"
#include "rtpsrtp.h"
#include "rtcp.h"
#include "apierror.h"
#include "ip-utils.h"
#include "events.h"

/* STUN server/port, if any STUN服务和端口 如果有*/
static char *janus_stun_server = NULL;
static uint16_t janus_stun_port = 0;

char *janus_ice_get_stun_server(void) {
	return janus_stun_server;
}
uint16_t janus_ice_get_stun_port(void) {
	return janus_stun_port;
}


/* TURN server/port and credentials, if any TURN服务和端口 如果有*/
static char *janus_turn_server = NULL;
static uint16_t janus_turn_port = 0;
static char *janus_turn_user = NULL, *janus_turn_pwd = NULL;
static NiceRelayType janus_turn_type = NICE_RELAY_TYPE_TURN_UDP;

char *janus_ice_get_turn_server(void) {
	return janus_turn_server;
}
uint16_t janus_ice_get_turn_port(void) {
	return janus_turn_port;
}


/* TURN REST API support, if any TURN服务REST API支持 如果有*/
char *janus_ice_get_turn_rest_api(void) {
#ifndef HAVE_TURNRESTAPI
	return NULL;
#else
	return (char *)janus_turnrest_get_backend();
#endif
}

/* Force relay settings 强制使用relay设置 */
static gboolean force_relay_allowed = FALSE;
void janus_ice_allow_force_relay(void) {
	force_relay_allowed = TRUE;
}
gboolean janus_ice_is_force_relay_allowed(void) {
	return force_relay_allowed;
}

/* ICE-Lite status */
static gboolean janus_ice_lite_enabled;
gboolean janus_ice_is_ice_lite_enabled(void) {
	return janus_ice_lite_enabled;
}

/* ICE-TCP support (only libnice >= 0.1.8, currently broken) */
static gboolean janus_ice_tcp_enabled;
gboolean janus_ice_is_ice_tcp_enabled(void) {
	return janus_ice_tcp_enabled;
}

/* Full-trickle support */
static gboolean janus_full_trickle_enabled;
gboolean janus_ice_is_full_trickle_enabled(void) {
	return janus_full_trickle_enabled;
}

/* mDNS resolution support */
static gboolean janus_mdns_enabled;
gboolean janus_ice_is_mdns_enabled(void) {
	return janus_mdns_enabled;
}

/* IPv6 support */
static gboolean janus_ipv6_enabled;
static gboolean janus_ipv6_linklocal_enabled;
gboolean janus_ice_is_ipv6_enabled(void) {
	return janus_ipv6_enabled;
}
static gboolean janus_ipv6_linklocal_enabled;
gboolean janus_ice_is_ipv6_linklocal_enabled(void) {
	return janus_ipv6_linklocal_enabled;
}

#ifdef HAVE_ICE_NOMINATION
/* Since libnice 0.1.15, we can configure the ICE nomination mode: it was
 * always "aggressive" before, so we set it to "aggressive" by default as well */
static NiceNominationMode janus_ice_nomination = NICE_NOMINATION_MODE_AGGRESSIVE;
void janus_ice_set_nomination_mode(const char *nomination) {
	if(nomination == NULL) {
		JANUS_LOG(LOG_WARN, "Invalid ICE nomination mode, falling back to 'aggressive'\n");
	} else if(!strcasecmp(nomination, "regular")) {
		JANUS_LOG(LOG_INFO, "Configuring Janus to use ICE regular nomination\n");
		janus_ice_nomination = NICE_NOMINATION_MODE_REGULAR;
	} else if(!strcasecmp(nomination, "aggressive")) {
		JANUS_LOG(LOG_INFO, "Configuring Janus to use ICE aggressive nomination\n");
		janus_ice_nomination = NICE_NOMINATION_MODE_AGGRESSIVE;
	} else {
		JANUS_LOG(LOG_WARN, "Unsupported ICE nomination mode '%s', falling back to 'aggressive'\n", nomination);
	}
}
const char *janus_ice_get_nomination_mode(void) {
	return (janus_ice_nomination == NICE_NOMINATION_MODE_REGULAR ? "regular" : "aggressive");
}
#endif

/* Keepalive via connectivity checks 通过连接检查保持活跃 */
static gboolean janus_ice_keepalive_connchecks = FALSE;
void janus_ice_set_keepalive_conncheck_enabled(gboolean enabled) {
	janus_ice_keepalive_connchecks = enabled;
	if(janus_ice_keepalive_connchecks) {
		JANUS_LOG(LOG_INFO, "Using connectivity checks as PeerConnection keep-alives\n");
		JANUS_LOG(LOG_WARN, "Notice that the current libnice master is breaking connections after 50s when keepalive-conncheck enabled. As such, better to stick to 0.1.18 until the issue is addressed upstream\n");
	}
}
gboolean janus_ice_is_keepalive_conncheck_enabled(void) {
	return janus_ice_keepalive_connchecks;
}

/* Opaque IDs set by applications are by default only passed to event handlers
 * for correlation purposes, but not sent back to the user or application in
 * the related Janus API responses or events, unless configured otherwise 
 * 默认情况下，应用程序设置的Opaque ID 仅传递给事件处理程序以用于关联目的，
 * 但不会在相关的 Janus API 响应或事件中发送回用户或应用程序，除非另有配置 */
static gboolean opaqueid_in_api = FALSE;
void janus_enable_opaqueid_in_api(void) {
	opaqueid_in_api = TRUE;
}
gboolean janus_is_opaqueid_in_api_enabled(void) {
	return opaqueid_in_api;
}

/* Only needed in case we're using static event loops spawned at startup (disabled by default)
仅在我们使用启动时产生的静态事件循环时才需要（默认禁用） */
typedef struct janus_ice_static_event_loop {
	int id;
	GMainContext *mainctx;
	GMainLoop *mainloop;
	GThread *thread;
} janus_ice_static_event_loop;


static int static_event_loops = 0;
static gboolean allow_loop_indication = FALSE;
static GSList *event_loops = NULL, *current_loop = NULL;
static janus_mutex event_loops_mutex = JANUS_MUTEX_INITIALIZER;

/**
 * @brief 执行静态事件循环的线程
 * 
 * @param data 
 * @return void* 
 */
static void *janus_ice_static_event_loop_thread(void *data) {
	janus_ice_static_event_loop *loop = data;
	JANUS_LOG(LOG_VERB, "[loop#%d] Event loop thread started\n", loop->id);
	if(loop->mainloop == NULL) {
		JANUS_LOG(LOG_ERR, "[loop#%d] Invalid loop...\n", loop->id);
		g_thread_unref(g_thread_self());
		return NULL;
	}
	JANUS_LOG(LOG_DBG, "[loop#%d] Looping...\n", loop->id);
	g_main_loop_run(loop->mainloop);
	/* When the loop quits, we can unref it 当循环退出时，我们可以取消它*/
	g_main_loop_unref(loop->mainloop);
	g_main_context_unref(loop->mainctx);
	JANUS_LOG(LOG_VERB, "[loop#%d] Event loop thread ended!\n", loop->id);
	return NULL;
}


int janus_ice_get_static_event_loops(void) {
	return static_event_loops;
}
gboolean janus_ice_is_loop_indication_allowed(void) {
	return allow_loop_indication;
}

/**
 * @brief 设置ICE的静态事件loops
 * 
 * @param loops 
 * @param allow_api 
 */
void janus_ice_set_static_event_loops(int loops, gboolean allow_api) {
	if(loops == 0)
		return;
	else if(loops < 1) {
		JANUS_LOG(LOG_WARN, "Invalid number of static event loops (%d), disabling\n", loops);
		return;
	}
	/* Create a pool of new event loops 创建一个新事件循环池 */
	int i = 0;
	for(i=0; i<loops; i++) {
		janus_ice_static_event_loop *loop = g_malloc0(sizeof(janus_ice_static_event_loop));
		loop->id = static_event_loops;
		loop->mainctx = g_main_context_new();
		loop->mainloop = g_main_loop_new(loop->mainctx, FALSE);
		/* Now spawn a thread for this loop 现在为这个循环生成一个线程 */
		GError *error = NULL;
		char tname[16];
		g_snprintf(tname, sizeof(tname), "hloop %d", loop->id);
		loop->thread = g_thread_try_new(tname, &janus_ice_static_event_loop_thread, loop, &error);
		if(error != NULL) {
			g_main_loop_unref(loop->mainloop);
			g_main_context_unref(loop->mainctx);
			g_free(loop);
			JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch a new event loop thread...\n",
				error->code, error->message ? error->message : "??");
			g_error_free(error);
		} else {
			event_loops = g_slist_append(event_loops, loop);
			static_event_loops++;
		}
	}
	current_loop = event_loops;
	JANUS_LOG(LOG_INFO, "Spawned %d static event loops (handles won't have a dedicated loop)\n", static_event_loops);
	allow_loop_indication = allow_api;
	JANUS_LOG(LOG_INFO, "  -- Janus API %s be able to drive the loop choice for new handles\n",
		allow_loop_indication ? "will" : "will NOT");
	return;
}

/**
 * @brief 停止静态事件循环：退出所有静态循环并等待线程离开
 * 
 */
void janus_ice_stop_static_event_loops(void) {
	if(static_event_loops < 1)
		return;
	/* Quit all the static loops and wait for the threads to leave 退出所有静态循环并等待线程离开 */
	janus_mutex_lock(&event_loops_mutex);
	GSList *l = event_loops;
	while(l) {
		janus_ice_static_event_loop *loop = (janus_ice_static_event_loop *)l->data;
		if(loop->mainloop != NULL && g_main_loop_is_running(loop->mainloop))
			g_main_loop_quit(loop->mainloop);
		g_thread_join(loop->thread);
		l = l->next;
	}
	g_slist_free_full(event_loops, (GDestroyNotify)g_free);
	janus_mutex_unlock(&event_loops_mutex);
}

/* libnice debugging */
static gboolean janus_ice_debugging_enabled;
gboolean janus_ice_is_ice_debugging_enabled(void) {
	return janus_ice_debugging_enabled;
}
void janus_ice_debugging_enable(void) {
	JANUS_LOG(LOG_VERB, "Enabling libnice debugging...\n");
	if(g_getenv("NICE_DEBUG") == NULL) {
		JANUS_LOG(LOG_WARN, "No NICE_DEBUG environment variable set, setting maximum debug\n");
		g_setenv("NICE_DEBUG", "all", TRUE);
	}
	if(g_getenv("G_MESSAGES_DEBUG") == NULL) {
		JANUS_LOG(LOG_WARN, "No G_MESSAGES_DEBUG environment variable set, setting maximum debug\n");
		g_setenv("G_MESSAGES_DEBUG", "all", TRUE);
	}
	JANUS_LOG(LOG_VERB, "Debugging NICE_DEBUG=%s G_MESSAGES_DEBUG=%s\n",
		g_getenv("NICE_DEBUG"), g_getenv("G_MESSAGES_DEBUG"));
	janus_ice_debugging_enabled = TRUE;
	nice_debug_enable(strstr(g_getenv("NICE_DEBUG"), "all") || strstr(g_getenv("NICE_DEBUG"), "stun"));
}
void janus_ice_debugging_disable(void) {
	JANUS_LOG(LOG_VERB, "Disabling libnice debugging...\n");
	janus_ice_debugging_enabled = FALSE;
	nice_debug_disable(TRUE);
}


/* NAT 1:1 stuff 1对1 nat的一些东西 */
static gboolean nat_1_1_enabled = FALSE;
static gboolean keep_private_host = FALSE;
void janus_ice_enable_nat_1_1(gboolean kph) {
	nat_1_1_enabled = TRUE;
	keep_private_host = kph;
}

/* Interface/IP enforce/ignore lists 强制使用/忽略的 地址 */
GList *janus_ice_enforce_list = NULL, *janus_ice_ignore_list = NULL;
janus_mutex ice_list_mutex;

/**
 * @brief 强制使用接口
 * 
 * @param ip 
 */
void janus_ice_enforce_interface(const char *ip) {
	if(ip == NULL)
		return;
	/* Is this an IP or an interface? */
	janus_mutex_lock(&ice_list_mutex);
	janus_ice_enforce_list = g_list_append(janus_ice_enforce_list, (gpointer)ip);
	janus_mutex_unlock(&ice_list_mutex);
}

/**
 * @brief 判断这个地址是否强制使用
 * 
 * @param ip 
 * @return gboolean 
 */
gboolean janus_ice_is_enforced(const char *ip) {
	if(ip == NULL || janus_ice_enforce_list == NULL)
		return false;
	janus_mutex_lock(&ice_list_mutex);
	GList *temp = janus_ice_enforce_list;
	while(temp) {
		const char *enforced = (const char *)temp->data;
		if(enforced != NULL && strstr(ip, enforced) == ip) {
			janus_mutex_unlock(&ice_list_mutex);
			return true;
		}
		temp = temp->next;
	}
	janus_mutex_unlock(&ice_list_mutex);
	return false;
}

/**
 * @brief 强制忽略接口
 * 
 * @param ip 
 */
void janus_ice_ignore_interface(const char *ip) {
	if(ip == NULL)
		return;
	/* Is this an IP or an interface? */
	janus_mutex_lock(&ice_list_mutex);
	janus_ice_ignore_list = g_list_append(janus_ice_ignore_list, (gpointer)ip);
	if(janus_ice_enforce_list != NULL) {
		JANUS_LOG(LOG_WARN, "Added %s to the ICE ignore list, but the ICE enforce list is not empty: the ICE ignore list will not be used\n", ip);
	}
	janus_mutex_unlock(&ice_list_mutex);
}

/**
 * @brief ip地址是否被忽略
 * 
 * @param ip 
 * @return gboolean 
 */
gboolean janus_ice_is_ignored(const char *ip) {
	if(ip == NULL || janus_ice_ignore_list == NULL)
		return false;
	janus_mutex_lock(&ice_list_mutex);
	GList *temp = janus_ice_ignore_list;
	while(temp) {
		const char *ignored = (const char *)temp->data;
		if(ignored != NULL && strstr(ip, ignored) == ip) {
			janus_mutex_unlock(&ice_list_mutex);
			return true;
		}
		temp = temp->next;
	}
	janus_mutex_unlock(&ice_list_mutex);
	return false;
}


/* Frequency of statistics via event handlers (one second by default) 
统计通过事件处理的频率（默认一秒）
*/
static int janus_ice_event_stats_period = 1;
void janus_ice_set_event_stats_period(int period) {
	janus_ice_event_stats_period = period;
}
int janus_ice_get_event_stats_period(void) {
	return janus_ice_event_stats_period;
}

/* How to handle media statistic events (one per media or one per peerConnection)
如何去处理媒体统计信息事件（每一个媒体或者每一个peerConnection）*/
static gboolean janus_ice_event_combine_media_stats = false;
void janus_ice_event_set_combine_media_stats(gboolean combine_media_stats_to_one_event) {
	janus_ice_event_combine_media_stats = combine_media_stats_to_one_event;
}
gboolean janus_ice_event_get_combine_media_stats(void) {
	return janus_ice_event_combine_media_stats;
}

/* RTP/RTCP port range RTP/RTCP端口范围*/
uint16_t rtp_range_min = 0;
uint16_t rtp_range_max = 0;


#define JANUS_ICE_PACKET_AUDIO	0
#define JANUS_ICE_PACKET_VIDEO	1
#define JANUS_ICE_PACKET_TEXT	2
#define JANUS_ICE_PACKET_BINARY	3
#define JANUS_ICE_PACKET_SCTP	4
/* Janus enqueued (S)RTP/(S)RTCP packet to send 
Janus 要入队发送的 (S)RTP/(S)RTCP 包 */
typedef struct janus_ice_queued_packet {
	char *data;
	char *label;
	char *protocol;
	gint length;
	gint type;
	gboolean control;
	gboolean retransmission;
	gboolean encrypted;
	gint64 added;
} janus_ice_queued_packet;
/* A few static, fake, messages we use as a trigger: e.g., to start a
 * new DTLS handshake, hangup a PeerConnection or close a handle 
 初始化一些静态结构,分别去处理不同的包 */
static janus_ice_queued_packet
	janus_ice_start_gathering,
	janus_ice_add_candidates,
	janus_ice_dtls_handshake,
	janus_ice_media_stopped,
	janus_ice_hangup_peerconnection,
	janus_ice_detach_handle,
	janus_ice_data_ready;

/* Janus NACKed packet we're tracking (to avoid duplicates) 
我们在跟踪的Janus NACKed 包（去避免重复）*/
typedef struct janus_ice_nacked_packet {
	janus_ice_handle *handle;
	int vindex;
	guint16 seq_number;
	guint source_id;
} janus_ice_nacked_packet;

/**
 * @brief 清理nacked 包
 * 
 * @param user_data 
 * @return gboolean 
 */
static gboolean janus_ice_nacked_packet_cleanup(gpointer user_data) {
	janus_ice_nacked_packet *pkt = (janus_ice_nacked_packet *)user_data;

	if(pkt->handle->stream){
		JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Cleaning up NACKed packet %"SCNu16" (SSRC %"SCNu32", vindex %d)...\n",
			pkt->handle->handle_id, pkt->seq_number, pkt->handle->stream->video_ssrc_peer[pkt->vindex], pkt->vindex);
		/* 清理掉该序列号所对应的nacked包和它所待办的回调函数 */
		g_hash_table_remove(pkt->handle->stream->rtx_nacked[pkt->vindex], GUINT_TO_POINTER(pkt->seq_number));
		g_hash_table_remove(pkt->handle->stream->pending_nacked_cleanup, GUINT_TO_POINTER(pkt->source_id));
	}

	return G_SOURCE_REMOVE;
}

/* Deallocation helpers for handles and related structs handle和相关结构的释放助手 */
static void janus_ice_handle_free(const janus_refcount *handle_ref);
/*释放handle中的一些webRTC的东西*/
static void janus_ice_webrtc_free(janus_ice_handle *handle);
static void janus_ice_plugin_session_free(const janus_refcount *app_handle_ref);
static void janus_ice_stream_free(const janus_refcount *handle_ref);
static void janus_ice_component_free(const janus_refcount *handle_ref);

/* Custom GSource for outgoing traffic 用于传出流量的自定义 GSource */
typedef struct janus_ice_outgoing_traffic {
	GSource parent;
	janus_ice_handle *handle;
	GDestroyNotify destroy;
} janus_ice_outgoing_traffic;
static gboolean janus_ice_outgoing_rtcp_handle(gpointer user_data);
static gboolean janus_ice_outgoing_stats_handle(gpointer user_data);
static gboolean janus_ice_outgoing_traffic_handle(janus_ice_handle *handle, janus_ice_queued_packet *pkt);
/**
 * @brief 该source是否有用于传出的流量
 * 
 * @param source 
 * @param timeout 
 * @return gboolean 
 */
static gboolean janus_ice_outgoing_traffic_prepare(GSource *source, gint *timeout) {
	janus_ice_outgoing_traffic *t = (janus_ice_outgoing_traffic *)source;
	return (g_async_queue_length(t->handle->queued_packets) > 0);
}

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

/**
 * @brief 
 * 
 * @param source 
 */
static void janus_ice_outgoing_traffic_finalize(GSource *source) {
	janus_ice_outgoing_traffic *t = (janus_ice_outgoing_traffic *)source;
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Finalizing loop source\n", t->handle->handle_id);
	if(static_event_loops > 0) {
		/* This handle was sharing an event loop with others 
		此 handle 与其他人共享事件循环*/
		janus_ice_webrtc_free(t->handle);
		janus_refcount_decrease(&t->handle->ref);
	} else if(t->handle->mainloop != NULL && g_main_loop_is_running(t->handle->mainloop)) {
		/* This handle had a dedicated event loop, quit it 
		这个 handle 有一个专门的事件循环，退出它 */
		g_main_loop_quit(t->handle->mainloop);
	}
	janus_refcount_decrease(&t->handle->ref);
}
static GSourceFuncs janus_ice_outgoing_traffic_funcs = {
	janus_ice_outgoing_traffic_prepare,
	NULL,	/* We don't need check */
	janus_ice_outgoing_traffic_dispatch,
	janus_ice_outgoing_traffic_finalize,
	NULL, NULL
};
/**
 * @brief 传出流量、循环 RTCP 和统计信息（以及可选的 TWCC）的 GLib 源 创建
 * 
 * @param handle 
 * @param destroy 
 * @return GSource* 
 */
static GSource *janus_ice_outgoing_traffic_create(janus_ice_handle *handle, GDestroyNotify destroy) {
	GSource *source = g_source_new(&janus_ice_outgoing_traffic_funcs, sizeof(janus_ice_outgoing_traffic));
	janus_ice_outgoing_traffic *t = (janus_ice_outgoing_traffic *)source;
	char name[255];
	g_snprintf(name, sizeof(name), "source-%"SCNu64, handle->handle_id);
	g_source_set_name(source, name);
	janus_refcount_increase(&handle->ref);
	t->handle = handle;
	t->destroy = destroy;
	return source;
}

/* Time, in seconds, that should pass with no media (audio or video) being
 * received before Janus notifies you about this with a receiving=false 
 时间 秒 当经过多少秒没有接收到音视频消息之后，进行通知，告诉你没有接收到东西 */
#define DEFAULT_NO_MEDIA_TIMER	1
static uint no_media_timer = DEFAULT_NO_MEDIA_TIMER;
void janus_set_no_media_timer(uint timer) {
	no_media_timer = timer;
	if(no_media_timer == 0)
		JANUS_LOG(LOG_VERB, "Disabling no-media timer\n");
	else
		JANUS_LOG(LOG_VERB, "Setting no-media timer to %us\n", no_media_timer);
}
uint janus_get_no_media_timer(void) {
	return no_media_timer;
}

/* Number of lost packets per seconds on a media stream (uplink or downlink,
 * audio or video), that should result in a slow-link event to the user.
 * By default the feature is disabled (threshold=0), as it can be quite
 * verbose and is often redundant information, since the same info on lost
 * packets (in and out) can already be retrieved via client-side stats 
 * 每一秒媒体的丢包数量（上行或者下行，音频或者视频）会在slow-link事件里通知
 * 默认这是关闭的，因为它可能非常冗长并且通常是冗余信息，
 * 因为通过客户端也可以统计出 上行或者下行的 丢包数量
 * */
#define DEFAULT_SLOWLINK_THRESHOLD	0
static uint slowlink_threshold = DEFAULT_SLOWLINK_THRESHOLD;
void janus_set_slowlink_threshold(uint packets) {
	slowlink_threshold = packets;
	if(slowlink_threshold == 0)
		JANUS_LOG(LOG_VERB, "Disabling slow-link events\n");
	else
		JANUS_LOG(LOG_VERB, "Setting slowlink-threshold to %u packets\n", slowlink_threshold);
}
uint janus_get_slowlink_threshold(void) {
	return slowlink_threshold;
}

/* Period, in milliseconds, to refer to for sending TWCC feedback 
间隔，单位毫秒，发送拥塞控制反馈信息 */
#define DEFAULT_TWCC_PERIOD		200
static uint twcc_period = DEFAULT_TWCC_PERIOD;
void janus_set_twcc_period(uint period) {
	twcc_period = period;
	if(twcc_period == 0) {
		JANUS_LOG(LOG_WARN, "Invalid TWCC period, falling back to default\n");
		twcc_period = DEFAULT_TWCC_PERIOD;
	} else {
		JANUS_LOG(LOG_VERB, "Setting TWCC period to %ds\n", twcc_period);
	}
}
uint janus_get_twcc_period(void) {
	return twcc_period;
}

/* DSCP value, which we can set via libnice: it's disabled by default 
DSCP的值，我们可以通过libnice设置，默认这是禁止的 */
static int dscp_ef = 0;
void janus_set_dscp(int dscp) {
	dscp_ef = dscp;
	if(dscp_ef > 0) {
		JANUS_LOG(LOG_VERB, "Setting DSCP EF to %d\n", dscp_ef);
	}
}
int janus_get_dscp(void) {
	return dscp_ef;
}

/**
 * @brief 释放RTP包资源
 * 
 * @param pkt 
 */
static inline void janus_ice_free_rtp_packet(janus_rtp_packet *pkt) {
	if(pkt == NULL) {
		return;
	}

	g_free(pkt->data);
	g_free(pkt);
}


/**
 * @brief 释放ICE队列包
 * 
 * @param pkt 
 */
static void janus_ice_free_queued_packet(janus_ice_queued_packet *pkt) {
	if(pkt == NULL || pkt == &janus_ice_start_gathering ||
			pkt == &janus_ice_add_candidates ||
			pkt == &janus_ice_dtls_handshake ||
			pkt == &janus_ice_media_stopped ||
			pkt == &janus_ice_hangup_peerconnection ||
			pkt == &janus_ice_detach_handle ||
			pkt == &janus_ice_data_ready) {
		return;
	}
	g_free(pkt->data);
	g_free(pkt->label);
	g_free(pkt->protocol);
	g_free(pkt);
}

/* Minimum and maximum value, in milliseconds, for the NACK queue/retransmissions (default=200ms/1000ms) 
最大值和最小值，单位毫秒，对于NACK 队列/重传 */
#define DEFAULT_MIN_NACK_QUEUE	200
#define DEFAULT_MAX_NACK_QUEUE	1000
/* Maximum ignore count after retransmission (200ms)
重传后的最大忽略计数 */
#define MAX_NACK_IGNORE			200000

static gboolean nack_optimizations = FALSE;
void janus_set_nack_optimizations_enabled(gboolean optimize) {
	nack_optimizations = optimize;
}
gboolean janus_is_nack_optimizations_enabled(void) {
	return nack_optimizations;
}

static uint16_t min_nack_queue = DEFAULT_MIN_NACK_QUEUE;
void janus_set_min_nack_queue(uint16_t mnq) {
	min_nack_queue = mnq < DEFAULT_MAX_NACK_QUEUE ? mnq : DEFAULT_MAX_NACK_QUEUE;
	if(min_nack_queue == 0)
		JANUS_LOG(LOG_VERB, "Disabling NACK queue\n");
	else
		JANUS_LOG(LOG_VERB, "Setting min NACK queue to %dms\n", min_nack_queue);
}
uint16_t janus_get_min_nack_queue(void) {
	return min_nack_queue;
}
/* Helper to clean old NACK packets in the buffer when they exceed the queue time limit 
帮助程序在超过队列时间限制时清除缓冲区中的旧 NACK 数据包 */
static void janus_cleanup_nack_buffer(gint64 now, janus_ice_stream *stream, gboolean audio, gboolean video) {
	if(stream && stream->component) {
		janus_ice_component *component = stream->component;
		if(audio && component->audio_retransmit_buffer) {
			janus_rtp_packet *p = (janus_rtp_packet *)g_queue_peek_head(component->audio_retransmit_buffer);
			while(p && (!now || (now - p->created >= (gint64)stream->nack_queue_ms*1000))) {
				/* Packet is too old, get rid of it 包太旧了，丢了吧*/
				g_queue_pop_head(component->audio_retransmit_buffer);
				/* Remove from hashtable too 从hashTable移除 */
				janus_rtp_header *header = (janus_rtp_header *)p->data;
				guint16 seq = ntohs(header->seq_number);
				g_hash_table_remove(component->audio_retransmit_seqs, GUINT_TO_POINTER(seq));
				/* Free the packet 释放包内存 */
				janus_ice_free_rtp_packet(p);
				p = (janus_rtp_packet *)g_queue_peek_head(component->audio_retransmit_buffer);
			}
		}
		if(video && component->video_retransmit_buffer) {
			janus_rtp_packet *p = (janus_rtp_packet *)g_queue_peek_head(component->video_retransmit_buffer);
			while(p && (!now || (now - p->created >= (gint64)stream->nack_queue_ms*1000))) {
				/* Packet is too old, get rid of it 包太旧了，丢了吧*/
				g_queue_pop_head(component->video_retransmit_buffer);
				/* Remove from hashtable too 从hashTable移除*/
				janus_rtp_header *header = (janus_rtp_header *)p->data;
				guint16 seq = ntohs(header->seq_number);
				g_hash_table_remove(component->video_retransmit_seqs, GUINT_TO_POINTER(seq));
				/* Free the packet 释放包内存*/
				janus_ice_free_rtp_packet(p);
				p = (janus_rtp_packet *)g_queue_peek_head(component->video_retransmit_buffer);
			}
		}
	}
}


#define SEQ_MISSING_WAIT 12000 /*  12ms */
#define SEQ_NACKED_WAIT 155000 /* 155ms */
/* janus_seq_info list functions 创建序列号列表*/
static void janus_seq_append(janus_seq_info **head, janus_seq_info *new_seq) {
	if(*head == NULL) {
		/*头节点为空，新节点作为头结点*/
		new_seq->prev = new_seq;
		new_seq->next = new_seq;
		*head = new_seq;
	} else {
		/*头节点不为空，存储头节点的上节点，
		  新节点成为头节点的上一个节点，
		  头节点的上节点成为新节点的上一个节点
		
		head.prev <- head
		         ||      
		head.prev <- new_seq <- head */
		janus_seq_info *last_seq = (*head)->prev;
		new_seq->prev = last_seq;
		new_seq->next = *head;
		(*head)->prev = new_seq;
		last_seq->next = new_seq;
	}
}
static janus_seq_info *janus_seq_pop_head(janus_seq_info **head) {
	janus_seq_info *pop_seq = *head;
	if(pop_seq) {
		janus_seq_info *new_head = pop_seq->next;
		if(pop_seq == new_head || new_head == NULL) {
			*head = NULL;
		} else {
			*head = new_head;
			new_head->prev = pop_seq->prev;
			new_head->prev->next = new_head;
		}
	}
	return pop_seq;
}
void janus_seq_list_free(janus_seq_info **head) {
	if(!*head)
		return;
	janus_seq_info *cur = *head;
	do {
		janus_seq_info *next = cur->next;
		g_free(cur);
		cur = next;
	} while(cur != *head);
	*head = NULL;
}
/**
 * @brief 当序列号大于开始序列号是，序列号需要在开始序列号+长度之间 或者  
 * 
 * @param seqn 
 * @param start 
 * @param len 
 * @return int 
 */
static int janus_seq_in_range(guint16 seqn, guint16 start, guint16 len) {
	/* Supports wrapping sequence (easier with int range) */
	int n = seqn;
	int nh = (1<<16) + n;
	int s = start;
	int e = s + len;
	return (s <= n && n < e) || (s <= nh && nh < e);
}


/* Internal method for relaying RTCP messages, optionally filtering them in case they come from plugins
转发 RTCP 消息的内部方法，可选择过滤它们 如果它们来自插件 */
void janus_ice_relay_rtcp_internal(janus_ice_handle *handle, janus_plugin_rtcp *packet, gboolean filter_rtcp);


/* Map of active plugin sessions 活跃的插件session map */
static GHashTable *plugin_sessions;
static janus_mutex plugin_sessions_mutex;
gboolean janus_plugin_session_is_alive(janus_plugin_session *plugin_session) {
	if(plugin_session == NULL || plugin_session < (janus_plugin_session *)0x1000 ||
			g_atomic_int_get(&plugin_session->stopped))
		return FALSE;
	/* Make sure this plugin session is still alive 确保session处于活跃状态 */
	janus_mutex_lock_nodebug(&plugin_sessions_mutex);
	janus_plugin_session *result = g_hash_table_lookup(plugin_sessions, plugin_session);
	janus_mutex_unlock_nodebug(&plugin_sessions_mutex);
	if(result == NULL) {
		JANUS_LOG(LOG_ERR, "Invalid plugin session (%p)\n", plugin_session);
	}
	return (result != NULL);
}
static void janus_plugin_session_dereference(janus_plugin_session *plugin_session) {
	if(plugin_session)
		janus_refcount_decrease(&plugin_session->ref);
}

/**
 * @brief 清除队列中的candidate
 * 
 * @param handle 
 */
static void janus_ice_clear_queued_candidates(janus_ice_handle *handle) {
	if(handle == NULL || handle->queued_candidates == NULL) {
		return;
	}
	while(g_async_queue_length(handle->queued_candidates) > 0) {
		(void)g_async_queue_try_pop(handle->queued_candidates);
	}
}
/**
 * @brief 清除队列中的包
 * 
 * @param handle 
 */
static void janus_ice_clear_queued_packets(janus_ice_handle *handle) {
	if(handle == NULL || handle->queued_packets == NULL) {
		return;
	}
	janus_ice_queued_packet *pkt = NULL;
	while(g_async_queue_length(handle->queued_packets) > 0) {
		pkt = g_async_queue_try_pop(handle->queued_packets);
		janus_ice_free_queued_packet(pkt);
	}
}

/*向客户端发送trickle请求重新协商ICE*/
static void janus_ice_notify_trickle(janus_ice_handle *handle, char *buffer) {
	if(handle == NULL)
		return;
	char cbuffer[200];
	if(buffer != NULL)
		g_snprintf(cbuffer, sizeof(cbuffer), "candidate:%s", buffer);
	/* Send a "trickle" event to the browser 发送trickle事件到浏览器 */
	janus_session *session = (janus_session *)handle->session;
	if(session == NULL)
		return;
	json_t *event = json_object();
	json_object_set_new(event, "janus", json_string("trickle"));
	json_object_set_new(event, "session_id", json_integer(session->session_id));
	json_object_set_new(event, "sender", json_integer(handle->handle_id));
	if(opaqueid_in_api && handle->opaque_id != NULL)
		json_object_set_new(event, "opaque_id", json_string(handle->opaque_id));
	json_t *candidate = json_object();
	if(buffer != NULL) {
		json_object_set_new(candidate, "sdpMid", json_string(handle->stream_mid));
		json_object_set_new(candidate, "sdpMLineIndex", json_integer(0));
		json_object_set_new(candidate, "candidate", json_string(cbuffer));
	} else {
		json_object_set_new(candidate, "completed", json_true());
	}
	json_object_set_new(event, "candidate", candidate);
	/* Send the event */
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Sending trickle event (%s) to transport...\n",
		handle->handle_id, buffer ? "candidate" : "end-of-candidates");
	janus_session_notify_event(session, event);
}

/**
 * @brief 向客户端发送media相关信息
 * 
 * @param handle 
 * @param video 音频或者视频
 * @param substream 
 * @param up 上行还是下行
 */
static void janus_ice_notify_media(janus_ice_handle *handle, gboolean video, int substream, gboolean up) {
	if(handle == NULL)
		return;
	/* Prepare JSON event to notify user/application */
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Notifying that we %s receiving %s\n",
		handle->handle_id, up ? "are" : "are NOT", video ? "video" : "audio");
	janus_session *session = (janus_session *)handle->session;
	if(session == NULL)
		return;
	json_t *event = json_object();
	json_object_set_new(event, "janus", json_string("media"));
	json_object_set_new(event, "session_id", json_integer(session->session_id));
	json_object_set_new(event, "sender", json_integer(handle->handle_id));
	if(opaqueid_in_api && handle->opaque_id != NULL)
		json_object_set_new(event, "opaque_id", json_string(handle->opaque_id));
	json_object_set_new(event, "type", json_string(video ? "video" : "audio"));
	if(video && handle->stream && handle->stream->video_rtcp_ctx[1] != NULL)
		json_object_set_new(event, "substream", json_integer(substream));
	json_object_set_new(event, "receiving", up ? json_true() : json_false());
	if(!up && no_media_timer > 1)
		json_object_set_new(event, "seconds", json_integer(no_media_timer));
	/* Send the event */
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Sending event to transport...\n", handle->handle_id);
	janus_session_notify_event(session, event);
	/* Notify event handlers as well 如果开启事件通知，则一并同步消息*/
	if(janus_events_is_enabled()) {
		json_t *info = json_object();
		json_object_set_new(info, "media", json_string(video ? "video" : "audio"));
		if(video && handle->stream && handle->stream->video_rtcp_ctx[1] != NULL)
			json_object_set_new(info, "substream", json_integer(substream));
		json_object_set_new(info, "receiving", up ? json_true() : json_false());
		if(!up && no_media_timer > 1)
			json_object_set_new(info, "seconds", json_integer(no_media_timer));
		janus_events_notify_handlers(JANUS_EVENT_TYPE_MEDIA, JANUS_EVENT_SUBTYPE_MEDIA_STATE,
			session->session_id, handle->handle_id, handle->opaque_id, info);
	}
}
/*向客户端发送hangup相关信息*/
void janus_ice_notify_hangup(janus_ice_handle *handle, const char *reason) {
	if(handle == NULL)
		return;
	/* Prepare JSON event to notify user/application */
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Notifying WebRTC hangup; %p\n", handle->handle_id, handle);
	janus_session *session = (janus_session *)handle->session;
	if(session == NULL)
		return;
	json_t *event = json_object();
	json_object_set_new(event, "janus", json_string("hangup"));
	json_object_set_new(event, "session_id", json_integer(session->session_id));
	json_object_set_new(event, "sender", json_integer(handle->handle_id));
	if(opaqueid_in_api && handle->opaque_id != NULL)
		json_object_set_new(event, "opaque_id", json_string(handle->opaque_id));
	if(reason != NULL)
		json_object_set_new(event, "reason", json_string(reason));
	/* Send the event */
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Sending event to transport...; %p\n", handle->handle_id, handle);
	janus_session_notify_event(session, event);
	/* Notify event handlers as well 如果开启事件通知，则一并同步消息*/
	if(janus_events_is_enabled()) {
		json_t *info = json_object();
		json_object_set_new(info, "connection", json_string("hangup"));
		if(reason != NULL)
			json_object_set_new(info, "reason", json_string(reason));
		janus_events_notify_handlers(JANUS_EVENT_TYPE_WEBRTC, JANUS_EVENT_SUBTYPE_WEBRTC_STATE,
			session->session_id, handle->handle_id, handle->opaque_id, info);
	}
}


/* Trickle helpers 创建一个新的trickle */
janus_ice_trickle *janus_ice_trickle_new(const char *transaction, json_t *candidate) {
	if(transaction == NULL || candidate == NULL)
		return NULL;
	janus_ice_trickle *trickle = g_malloc(sizeof(janus_ice_trickle));
	trickle->handle = NULL;
	trickle->received = janus_get_monotonic_time();
	trickle->transaction = g_strdup(transaction);
	trickle->candidate = json_deep_copy(candidate);
	return trickle;
}
/**
 * @brief 解析candidate
 * 
 * @param handle 
 * @param candidate 
 * @param error 
 * @return gint 
 */
gint janus_ice_trickle_parse(janus_ice_handle *handle, json_t *candidate, const char **error) {
	const char *ignore_error = NULL;
	if(error == NULL) {
		error = &ignore_error;
	}
	if(handle == NULL) {
		*error = "Invalid handle";
		return JANUS_ERROR_HANDLE_NOT_FOUND;
	}
	/* Parse trickle candidate 解析candidate */
	if(!json_is_object(candidate) || json_object_get(candidate, "completed") != NULL) {
		/*如果candidate不是一个json对象，或者candidate的completed的值不等于空*/
		JANUS_LOG(LOG_VERB, "No more remote candidates for handle %"SCNu64"!\n", handle->handle_id);
		janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALL_TRICKLES);
	} else {
		/* Handle remote candidate 获取sdpMid*/
		json_t *mid = json_object_get(candidate, "sdpMid");
		if(mid && !json_is_string(mid)) {
			/*如果sdpMid不是一个字符串*/
			*error = "Trickle error: invalid element type (sdpMid should be a string)";
			return JANUS_ERROR_INVALID_ELEMENT_TYPE;
		}
		/*获取sdpMLineIndex*/
		json_t *mline = json_object_get(candidate, "sdpMLineIndex");
		if(mline && (!json_is_integer(mline) || json_integer_value(mline) < 0)) {
			/*如果sdpMLineIndex不是数字或者sdpMLineIndex为负数*/
			*error = "Trickle error: invalid element type (sdpMLineIndex should be a positive integer)";
			return JANUS_ERROR_INVALID_ELEMENT_TYPE;
		}
		if(!mid && !mline) {
			/*缺失sdpMid or sdpMLineIndex*/
			*error = "Trickle error: missing mandatory element (sdpMid or sdpMLineIndex)";
			return JANUS_ERROR_MISSING_MANDATORY_ELEMENT;
		}
		/*获取candidate*/
		json_t *rc = json_object_get(candidate, "candidate");
		if(!rc) {
			/*缺失candidate*/
			*error = "Trickle error: missing mandatory element (candidate)";
			return JANUS_ERROR_MISSING_MANDATORY_ELEMENT;
		}
		if(!json_is_string(rc)) {
			/*如果candidate不是一个字符串*/
			*error = "Trickle error: invalid element type (candidate should be a string)";
			return JANUS_ERROR_INVALID_ELEMENT_TYPE;
		}
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] Trickle candidate (%s): %s\n", handle->handle_id, json_string_value(mid), json_string_value(rc));
		/* Parse it */
		int sdpMLineIndex = mline ? json_integer_value(mline) : -1;
		const char *sdpMid = json_string_value(mid);
		if(sdpMLineIndex > 0 || (handle->stream_mid && sdpMid && strcmp(handle->stream_mid, sdpMid))) {
			/* FIXME We bundle everything, so we ignore candidates for anything beyond the first m-line 
			我们做了一些限制，所以我们忽略了m-line以外的任何候选对象*/
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] Got a mid='%s' candidate (index %d) but we're bundling, ignoring...\n",
				handle->handle_id, json_string_value(mid), sdpMLineIndex);
			return 0;
		}
		janus_ice_stream *stream = handle->stream;
		if(stream == NULL) {
			*error = "Trickle error: invalid element type (no such stream)";
			return JANUS_ERROR_TRICKE_INVALID_STREAM;
		}
		/*解析candidate到handle->stream*/
		int res = janus_sdp_parse_candidate(stream, json_string_value(rc), 1);
		if(res != 0) {
			JANUS_LOG(LOG_ERR, "[%"SCNu64"] Failed to parse candidate... (%d)\n", handle->handle_id, res);
			/* FIXME Should we return an error? */
		}
	}
	return 0;
}

void janus_ice_trickle_destroy(janus_ice_trickle *trickle) {
	if(trickle == NULL)
		return;
	g_free(trickle->transaction);
	trickle->transaction = NULL;
	if(trickle->candidate)
		json_decref(trickle->candidate);
	trickle->candidate = NULL;
	g_free(trickle);
}


/* libnice initialization 初始化libnice */
void janus_ice_init(gboolean ice_lite, gboolean ice_tcp, gboolean full_trickle, gboolean ignore_mdns,
		gboolean ipv6, gboolean ipv6_linklocal, uint16_t rtp_min_port, uint16_t rtp_max_port) {
	janus_ice_lite_enabled = ice_lite;
	janus_ice_tcp_enabled = ice_tcp;
	janus_full_trickle_enabled = full_trickle;
	janus_mdns_enabled = !ignore_mdns;
	janus_ipv6_enabled = ipv6;
	if(ipv6)
		janus_ipv6_linklocal_enabled = ipv6_linklocal;
	JANUS_LOG(LOG_INFO, "Initializing ICE stuff (%s mode, ICE-TCP candidates %s, %s-trickle, IPv6 support %s)\n",
		janus_ice_lite_enabled ? "Lite" : "Full",
		janus_ice_tcp_enabled ? "enabled" : "disabled",
		janus_full_trickle_enabled ? "full" : "half",
		janus_ipv6_enabled ? "enabled" : "disabled");
	if(janus_ice_tcp_enabled) {
#ifndef HAVE_LIBNICE_TCP
		JANUS_LOG(LOG_WARN, "libnice version < 0.1.8, disabling ICE-TCP support\n");
		janus_ice_tcp_enabled = FALSE;
#else
		if(!janus_ice_lite_enabled) {
			JANUS_LOG(LOG_WARN, "You may experience problems when having ICE-TCP enabled without having ICE Lite enabled too in libnice\n");
		}
#endif
	}
	/* libnice debugging is disabled unless explicitly stated 
	除非明确说明，否则禁用 libnice 调试 */
	nice_debug_disable(TRUE);

	/*! \note The RTP/RTCP port range configuration may be just a placeholder: for
	 * instance, libnice supports this since 0.1.0, but the 0.1.3 on Fedora fails
	 * when linking with an undefined reference to \c nice_agent_set_port_range
	 * so this is checked by the install.sh script in advance. 
	 * RTP/RTCP 的端口范围配置可能只是一个占位符：
	 * 例如，libnice 自 0.1.0 起就支持此功能，
	 * 但在 Fedora 上的 0.1.3 会失败，因此由 install.sh 脚本检查提前
	 * */
	rtp_range_min = rtp_min_port;
	rtp_range_max = rtp_max_port;
	if(rtp_range_max < rtp_range_min) {
		JANUS_LOG(LOG_WARN, "Invalid ICE port range: %"SCNu16" > %"SCNu16"\n", rtp_range_min, rtp_range_max);
	} else if(rtp_range_min > 0 || rtp_range_max > 0) {
#ifndef HAVE_PORTRANGE
		JANUS_LOG(LOG_WARN, "nice_agent_set_port_range unavailable, port range disabled\n");
#else
		JANUS_LOG(LOG_INFO, "ICE port range: %"SCNu16"-%"SCNu16"\n", rtp_range_min, rtp_range_max);
#endif
	}
	if(!janus_mdns_enabled)
		JANUS_LOG(LOG_WARN, "mDNS resolution disabled, .local candidates will be ignored\n");

	/* We keep track of plugin sessions to avoid problems 
	我们跟踪插件session以避免出现问题 */
	plugin_sessions = g_hash_table_new_full(NULL, NULL, NULL, (GDestroyNotify)janus_plugin_session_dereference);
	janus_mutex_init(&plugin_sessions_mutex);

#ifdef HAVE_TURNRESTAPI
	/* Initialize the TURN REST API client stack, whether we're going to use it or not 
	初始化 TURN REST API 客户端堆栈，无论我们是否要使用它 */
	janus_turnrest_init();
#endif

}

void janus_ice_deinit(void) {
#ifdef HAVE_TURNRESTAPI
	janus_turnrest_deinit();
#endif
}

/**
 * @brief 检查 STUN 服务器是否可达
 * 
 * @param addr 
 * @param port 
 * @param local_port 
 * @param public_addr 
 * @param public_port 
 * @return int 
 */
int janus_ice_test_stun_server(janus_network_address *addr, uint16_t port,
		uint16_t local_port, janus_network_address *public_addr, uint16_t *public_port) {
	if(!addr || !public_addr)
		return -1;
	/* Test the STUN server 检查 STUN 服务器是否可达*/
	StunAgent stun;
	stun_agent_init (&stun, STUN_ALL_KNOWN_ATTRIBUTES, STUN_COMPATIBILITY_RFC5389, 0);
	StunMessage msg;
	uint8_t buf[1500];
	size_t len = stun_usage_bind_create(&stun, &msg, buf, 1500);
	JANUS_LOG(LOG_INFO, "Testing STUN server: message is of %zu bytes\n", len);
	/* Use the janus_network_address info to drive the socket creation 
	使用 janus_network_address 信息来驱动套接字创建 */
	int fd = socket(addr->family, SOCK_DGRAM, 0);
	if(fd < 0) {
		JANUS_LOG(LOG_FATAL, "Error creating socket for STUN BINDING test\n");
		return -1;
	}
	struct sockaddr *address = NULL, *remote = NULL;
	struct sockaddr_in address4 = { 0 }, remote4 = { 0 };
	struct sockaddr_in6 address6 = { 0 }, remote6 = { 0 };
	socklen_t addrlen = 0;
	if(addr->family == AF_INET) {
		memset(&address4, 0, sizeof(address4));
		address4.sin_family = AF_INET;
		address4.sin_port = htons(local_port);
		address4.sin_addr.s_addr = INADDR_ANY;
		memset(&remote4, 0, sizeof(remote4));
		remote4.sin_family = AF_INET;
		remote4.sin_port = htons(port);
		memcpy(&remote4.sin_addr, &addr->ipv4, sizeof(addr->ipv4));
		address = (struct sockaddr *)(&address4);
		remote = (struct sockaddr *)(&remote4);
		addrlen = sizeof(remote4);
	} else if(addr->family == AF_INET6) {
		memset(&address6, 0, sizeof(address6));
		address6.sin6_family = AF_INET6;
		address6.sin6_port = htons(local_port);
		address6.sin6_addr = in6addr_any;
		memset(&remote6, 0, sizeof(remote6));
		remote6.sin6_family = AF_INET6;
		remote6.sin6_port = htons(port);
		memcpy(&remote6.sin6_addr, &addr->ipv6, sizeof(addr->ipv6));
		remote6.sin6_addr = addr->ipv6;
		address = (struct sockaddr *)(&address6);
		remote = (struct sockaddr *)(&remote6);
		addrlen = sizeof(remote6);
	}
	if(bind(fd, address, addrlen) < 0) {
		JANUS_LOG(LOG_FATAL, "Bind failed for STUN BINDING test: %d (%s)\n", errno, g_strerror(errno));
		close(fd);
		return -1;
	}
	int bytes = sendto(fd, buf, len, 0, remote, addrlen);
	if(bytes < 0) {
		JANUS_LOG(LOG_FATAL, "Error sending STUN BINDING test\n");
		close(fd);
		return -1;
	}
	JANUS_LOG(LOG_VERB, "  >> Sent %d bytes, waiting for reply...\n", bytes);
	struct timeval timeout;
	fd_set readfds;
	FD_ZERO(&readfds);
	FD_SET(fd, &readfds);
	timeout.tv_sec = 5;	/* FIXME Don't wait forever 别一直等 */
	timeout.tv_usec = 0;
	int err = select(fd+1, &readfds, NULL, NULL, &timeout);
	if(err < 0) {
		JANUS_LOG(LOG_FATAL, "Error waiting for a response to our STUN BINDING test: %d (%s)\n", errno, g_strerror(errno));
		close(fd);
		return -1;
	}
	if(!FD_ISSET(fd, &readfds)) {
		JANUS_LOG(LOG_FATAL, "No response to our STUN BINDING test\n");
		close(fd);
		return -1;
	}
	bytes = recvfrom(fd, buf, 1500, 0, remote, &addrlen);
	JANUS_LOG(LOG_VERB, "  >> Got %d bytes...\n", bytes);
	close(fd);
	if(bytes < 0) {
		JANUS_LOG(LOG_FATAL, "Failed to receive STUN\n");
		return -1;
	}
	if(stun_agent_validate (&stun, &msg, buf, bytes, NULL, NULL) != STUN_VALIDATION_SUCCESS) {
		JANUS_LOG(LOG_FATAL, "Failed to validate STUN BINDING response\n");
		return -1;
	}
	StunClass class = stun_message_get_class(&msg);
	StunMethod method = stun_message_get_method(&msg);
	if(class != STUN_RESPONSE || method != STUN_BINDING) {
		JANUS_LOG(LOG_FATAL, "Unexpected STUN response: %d/%d\n", class, method);
		return -1;
	}
	StunMessageReturn ret = stun_message_find_xor_addr(&msg, STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS, (struct sockaddr_storage *)address, &addrlen);
	JANUS_LOG(LOG_VERB, "  >> XOR-MAPPED-ADDRESS: %d\n", ret);
	if(ret == STUN_MESSAGE_RETURN_SUCCESS) {
		if(janus_network_address_from_sockaddr(address, public_addr) != 0) {
			JANUS_LOG(LOG_ERR, "Could not resolve XOR-MAPPED-ADDRESS...\n");
			return -1;
		}
		if(public_port != NULL) {
			if(address->sa_family == AF_INET) {
				struct sockaddr_in *addr = (struct sockaddr_in *)address;
				*public_port = ntohs(addr->sin_port);
			} else if(address->sa_family == AF_INET6) {
				struct sockaddr_in6 *addr = (struct sockaddr_in6 *)address;
				*public_port = ntohs(addr->sin6_port);
			}
		}
		return 0;
	}
	ret = stun_message_find_addr(&msg, STUN_ATTRIBUTE_MAPPED_ADDRESS, (struct sockaddr_storage *)address, &addrlen);
	JANUS_LOG(LOG_VERB, "  >> MAPPED-ADDRESS: %d\n", ret);
	if(ret == STUN_MESSAGE_RETURN_SUCCESS) {
		if(janus_network_address_from_sockaddr(address, public_addr) != 0) {
			JANUS_LOG(LOG_ERR, "Could not resolve MAPPED-ADDRESS...\n");
			return -1;
		}
		if(public_port != NULL) {
			if(address->sa_family == AF_INET) {
				struct sockaddr_in *addr = (struct sockaddr_in *)address;
				*public_port = ntohs(addr->sin_port);
			} else if(address->sa_family == AF_INET6) {
				struct sockaddr_in6 *addr = (struct sockaddr_in6 *)address;
				*public_port = ntohs(addr->sin6_port);
			}
		}
		return 0;
	}
	/* No usable attribute? 无可用属性 */
	JANUS_LOG(LOG_ERR, "No XOR-MAPPED-ADDRESS or MAPPED-ADDRESS...\n");
	return -1;
}

/**
 * @brief 设置stun服务
 * 
 * @param stun_server 
 * @param stun_port 
 * @return int 
 */
int janus_ice_set_stun_server(gchar *stun_server, uint16_t stun_port) {
	if(stun_server == NULL)
		return 0;	/* No initialization needed */
	if(stun_port == 0)
		stun_port = 3478;
	JANUS_LOG(LOG_INFO, "STUN server to use: %s:%u\n", stun_server, stun_port);
	/* Resolve address to get an IP */
	struct addrinfo *res = NULL;
	janus_network_address addr;
	janus_network_address_string_buffer addr_buf;
	if(getaddrinfo(stun_server, NULL, NULL, &res) != 0 ||
			janus_network_address_from_sockaddr(res->ai_addr, &addr) != 0 ||
			janus_network_address_to_string_buffer(&addr, &addr_buf) != 0) {
		JANUS_LOG(LOG_ERR, "Could not resolve %s...\n", stun_server);
		if(res)
			freeaddrinfo(res);
		return -1;
	}
	freeaddrinfo(res);
	janus_stun_server = g_strdup(janus_network_address_string_from_buffer(&addr_buf));
	if(janus_stun_server == NULL) {
		JANUS_LOG(LOG_ERR, "Could not resolve %s...\n", stun_server);
		return -1;
	}
	janus_stun_port = stun_port;
	JANUS_LOG(LOG_INFO, "  >> %s:%u (%s)\n", janus_stun_server, janus_stun_port, addr.family == AF_INET ? "IPv4" : "IPv6");

	/* Test the STUN server */
	janus_network_address public_addr = { 0 };
	if(janus_ice_test_stun_server(&addr, janus_stun_port, 0, &public_addr, NULL) < 0) {
		g_free(janus_stun_server);
		janus_stun_server = NULL;
		return -1;
	}
	if(janus_network_address_to_string_buffer(&public_addr, &addr_buf) != 0) {
		JANUS_LOG(LOG_ERR, "Could not resolve public address...\n");
		g_free(janus_stun_server);
		janus_stun_server = NULL;
		return -1;
	}
	const char *public_ip = janus_network_address_string_from_buffer(&addr_buf);
	JANUS_LOG(LOG_INFO, "  >> Our public address is %s\n", public_ip);
	janus_add_public_ip(public_ip);
	return 0;
}

/**
 * @brief 设置turn服务
 * 
 * @param turn_server 
 * @param turn_port 
 * @param turn_type 
 * @param turn_user 
 * @param turn_pwd 
 * @return int 
 */
int janus_ice_set_turn_server(gchar *turn_server, uint16_t turn_port, gchar *turn_type, gchar *turn_user, gchar *turn_pwd) {
	if(turn_server == NULL)
		return 0;	/* No initialization needed */
	if(turn_type == NULL)
		turn_type = (char *)"udp";
	if(turn_port == 0)
		turn_port = 3478;
	JANUS_LOG(LOG_INFO, "TURN server to use: %s:%u (%s)\n", turn_server, turn_port, turn_type);
	if(!strcasecmp(turn_type, "udp")) {
		janus_turn_type = NICE_RELAY_TYPE_TURN_UDP;
	} else if(!strcasecmp(turn_type, "tcp")) {
		janus_turn_type = NICE_RELAY_TYPE_TURN_TCP;
	} else if(!strcasecmp(turn_type, "tls")) {
		janus_turn_type = NICE_RELAY_TYPE_TURN_TLS;
	} else {
		JANUS_LOG(LOG_ERR, "Unsupported relay type '%s'...\n", turn_type);
		return -1;
	}
	/* Resolve address to get an IP */
	struct addrinfo *res = NULL;
	janus_network_address addr;
	janus_network_address_string_buffer addr_buf;
	if(getaddrinfo(turn_server, NULL, NULL, &res) != 0 ||
			janus_network_address_from_sockaddr(res->ai_addr, &addr) != 0 ||
			janus_network_address_to_string_buffer(&addr, &addr_buf) != 0) {
		JANUS_LOG(LOG_ERR, "Could not resolve %s...\n", turn_server);
		if(res)
			freeaddrinfo(res);
		return -1;
	}
	freeaddrinfo(res);
	g_free(janus_turn_server);
	janus_turn_server = g_strdup(janus_network_address_string_from_buffer(&addr_buf));
	if(janus_turn_server == NULL) {
		JANUS_LOG(LOG_ERR, "Could not resolve %s...\n", turn_server);
		return -1;
	}
	janus_turn_port = turn_port;
	JANUS_LOG(LOG_VERB, "  >> %s:%u\n", janus_turn_server, janus_turn_port);
	g_free(janus_turn_user);
	janus_turn_user = NULL;
	if(turn_user)
		janus_turn_user = g_strdup(turn_user);
	g_free(janus_turn_pwd);
	janus_turn_pwd = NULL;
	if(turn_pwd)
		janus_turn_pwd = g_strdup(turn_pwd);
	return 0;
}

/**
 * @brief 设置turn rest api
 * 
 * @param api_server 
 * @param api_key 
 * @param api_method 
 * @param api_timeout 
 * @return int 
 */
int janus_ice_set_turn_rest_api(gchar *api_server, gchar *api_key, gchar *api_method, uint api_timeout) {
#ifndef HAVE_TURNRESTAPI
	JANUS_LOG(LOG_ERR, "Janus has been built with no libcurl support, TURN REST API unavailable\n");
	return -1;
#else
	if(api_server != NULL &&
			(strstr(api_server, "http://") != api_server && strstr(api_server, "https://") != api_server)) {
		JANUS_LOG(LOG_ERR, "Invalid TURN REST API backend: not an HTTP address\n");
		return -1;
	}
	janus_turnrest_set_backend(api_server, api_key, api_method, api_timeout);
	JANUS_LOG(LOG_INFO, "TURN REST API backend: %s\n", api_server ? api_server : "(disabled)");
#endif
	return 0;
}


/* ICE stuff */
static const gchar *janus_ice_state_name[] =
{
	"disconnected",
	"gathering",
	"connecting",
	"connected",
	"ready",
	"failed"
};
const gchar *janus_get_ice_state_name(gint state) {
	if(state < 0 || state > 5)
		return NULL;
	return janus_ice_state_name[state];
}


/* Thread to take care of the handle loop 
去处理handle循环的线程
*/
static void *janus_ice_handle_thread(void *data) {
	janus_ice_handle *handle = data;
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Handle thread started; %p\n", handle->handle_id, handle);
	if(handle->mainloop == NULL) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] Invalid loop...\n", handle->handle_id);
		janus_refcount_decrease(&handle->ref);
		g_thread_unref(g_thread_self());
		return NULL;
	}
	JANUS_LOG(LOG_DBG, "[%"SCNu64"] Looping...\n", handle->handle_id);
	g_main_loop_run(handle->mainloop);
	janus_ice_webrtc_free(handle);
	handle->thread = NULL;
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Handle thread ended! %p\n", handle->handle_id, handle);
	/* Unref the handle */
	janus_refcount_decrease(&handle->ref);
	g_thread_unref(g_thread_self());
	return NULL;
}

/**
 * @brief 创建插件
 * 
 */
janus_ice_handle *janus_ice_handle_create(void *core_session, const char *opaque_id, const char *token) {
	if(core_session == NULL)
		return NULL;
	janus_session *session = (janus_session *)core_session;
	janus_ice_handle *handle = NULL;
	guint64 handle_id = 0;
	while(handle_id == 0) {
		handle_id = janus_random_uint64();
		handle = janus_session_handles_find(session, handle_id);
		if(handle != NULL) {
			/* Handle ID already taken, try another one 
			handle ID已被占用，尝试另一个*/
			janus_refcount_decrease(&handle->ref);	/* janus_session_handles_find increases it */
			handle_id = 0;
		}
	}
	handle = (janus_ice_handle *)g_malloc0(sizeof(janus_ice_handle));
	JANUS_LOG(LOG_INFO, "Creating new handle in session %"SCNu64": %"SCNu64"; %p %p\n", session->session_id, handle_id, core_session, handle);
	janus_refcount_init(&handle->ref, janus_ice_handle_free);
	janus_refcount_increase(&session->ref);
	handle->session = core_session;
	if(opaque_id)
		handle->opaque_id = g_strdup(opaque_id);
	if(token)
		handle->token = g_strdup(token);
	handle->created = janus_get_monotonic_time();
	handle->handle_id = handle_id;
	handle->app = NULL;
	handle->app_handle = NULL;
	handle->queued_candidates = g_async_queue_new();
	handle->queued_packets = g_async_queue_new();
	janus_mutex_init(&handle->mutex);
	janus_session_handles_insert(session, handle);
	return handle;
}

/**
 * @brief 加载插件到session
 * 
 * @param core_session 
 * @param handle 
 * @param plugin 
 * @param loop_index 
 * @return gint 
 */
gint janus_ice_handle_attach_plugin(void *core_session, janus_ice_handle *handle, janus_plugin *plugin, int loop_index) {
	if(core_session == NULL)
		return JANUS_ERROR_SESSION_NOT_FOUND;
	janus_session *session = (janus_session *)core_session;
	if(plugin == NULL)
		return JANUS_ERROR_PLUGIN_NOT_FOUND;
	if(handle == NULL)
		return JANUS_ERROR_HANDLE_NOT_FOUND;
	if(handle->app != NULL) {
		/* This handle is already attached to a plugin 
		这个handle已经添加到插件上了 */
		return JANUS_ERROR_PLUGIN_ATTACH;
	}
	int error = 0;
	janus_plugin_session *session_handle = g_malloc(sizeof(janus_plugin_session));
	session_handle->gateway_handle = handle;
	session_handle->plugin_handle = NULL;
	g_atomic_int_set(&session_handle->stopped, 0);
	plugin->create_session(session_handle, &error);
	if(error) {
		/* TODO Make error struct to pass verbose information 制作error结构以传递详细信息*/
		g_free(session_handle);
		return error;
	}
	janus_refcount_init(&session_handle->ref, janus_ice_plugin_session_free);
	/* Handle and plugin session reference each other 
	Handle和插件会话相互引用
	*/
	janus_refcount_increase(&session_handle->ref);
	janus_refcount_increase(&handle->ref);
	handle->app = plugin;
	handle->app_handle = session_handle;
	/* Add this plugin session to active sessions map 
	添加插件session去激活session map */
	janus_mutex_lock(&plugin_sessions_mutex);
	g_hash_table_insert(plugin_sessions, session_handle, session_handle);
	janus_mutex_unlock(&plugin_sessions_mutex);
	/* Create a new context, loop, and source 
	创建glib 上下文，循环，source */
	if(static_event_loops == 0) {
		handle->mainctx = g_main_context_new();
		handle->mainloop = g_main_loop_new(handle->mainctx, FALSE);
	} else {
		/* We're actually using static event loops, pick one from the list 
		我们配置了静态事件循环，从list里选择一个进行使用
		*/
		if(!allow_loop_indication && loop_index > -1) {
			JANUS_LOG(LOG_WARN, "[%"SCNu64"] Manual allocation of event loops forbidden, ignoring provided loop index %d\n", handle->handle_id, loop_index);
		}
		janus_refcount_increase(&handle->ref);
		janus_mutex_lock(&event_loops_mutex);
		gboolean automatic_selection = TRUE;
		if(allow_loop_indication && loop_index != -1) {
			/* The API can drive the selection and an index was provided, check if it exists 
			使用loop_index选择一个事件循环进行使用
			*/
			janus_ice_static_event_loop *loop = g_slist_nth_data(event_loops, loop_index);
			if(loop == NULL) {
				JANUS_LOG(LOG_WARN, "[%"SCNu64"] Invalid loop index %d, picking event loop automatically\n", handle->handle_id, loop_index);
			} else {
				automatic_selection = FALSE;
				handle->mainctx = loop->mainctx;
				handle->mainloop = loop->mainloop;
				JANUS_LOG(LOG_VERB, "[%"SCNu64"] Manually added handle to loop #%d\n", handle->handle_id, loop->id);
			}
		}
		if(automatic_selection) {
			/* Pick an available loop automatically (round robin) 
			如果没有提供loop_index 那么随机挑选一个事件循环 */
			janus_ice_static_event_loop *loop = (janus_ice_static_event_loop *)current_loop->data;
			handle->mainctx = loop->mainctx;
			handle->mainloop = loop->mainloop;
			current_loop = current_loop->next;
			if(current_loop == NULL)
				current_loop = event_loops;
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] Automatically added handle to loop #%d\n", handle->handle_id, loop->id);
		}
		janus_mutex_unlock(&event_loops_mutex);
	}
	/* 创建一个ICE传出流量源 */
	handle->rtp_source = janus_ice_outgoing_traffic_create(handle, (GDestroyNotify)g_free);
	g_source_set_priority(handle->rtp_source, G_PRIORITY_DEFAULT);
	g_source_attach(handle->rtp_source, handle->mainctx);
	if(static_event_loops == 0) {
		/* Now spawn a thread for this loop 
		如果没有为这个handle添加静态事件循环，那么我们创建一个线程去处理该handle的ICE事件 */
		GError *terror = NULL;
		char tname[16];
		g_snprintf(tname, sizeof(tname), "hloop %"SCNu64, handle->handle_id);
		janus_refcount_increase(&handle->ref);
		handle->thread = g_thread_try_new(tname, &janus_ice_handle_thread, handle, &terror);
		if(terror != NULL) {
			/* FIXME We should clear some resources...如果发生了错误，我们需要释放一些资源 */
			JANUS_LOG(LOG_ERR, "[%"SCNu64"] Got error %d (%s) trying to launch the handle thread...\n",
				handle->handle_id, terror->code, terror->message ? terror->message : "??");
			g_error_free(terror);
			janus_refcount_decrease(&handle->ref);	/* This is for the thread reference we just added 这是我们刚刚添加的线程引用 */
			janus_ice_handle_destroy(session, handle);
			return -1;
		}
	}
	/* Notify event handlers 如果需要，触发通知事件*/
	if(janus_events_is_enabled())
		janus_events_notify_handlers(JANUS_EVENT_TYPE_HANDLE, JANUS_EVENT_SUBTYPE_NONE,
			session->session_id, handle->handle_id, "attached", plugin->get_package(), handle->opaque_id, handle->token);
	return 0;
}

/**
 * @brief 销毁ICE handle
 * 
 * @param core_session 
 * @param handle 
 * @return gint 
 */
gint janus_ice_handle_destroy(void *core_session, janus_ice_handle *handle) {
	/* session->mutex has to be locked when calling this function 
	对handle进行销毁的时候，对session进行加锁，防止并发操作对数据造成影响 */
	janus_session *session = (janus_session *)core_session;
	if(session == NULL)
		return JANUS_ERROR_SESSION_NOT_FOUND;
	if(handle == NULL)
		return JANUS_ERROR_HANDLE_NOT_FOUND;
	if(!g_atomic_int_compare_and_exchange(&handle->destroyed, 0, 1))
		return 0;
	/* First of all, hangup the PeerConnection, if any 处理销毁handle之前，先挂断PeerConnection 如果有 */
	janus_ice_webrtc_hangup(handle, "Detach");
	janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP);
	/* Remove the session from active sessions map
	把该handle的session从plugin_sessions map中移除 */
	janus_mutex_lock(&plugin_sessions_mutex);
	gboolean found = g_hash_table_remove(plugin_sessions, handle->app_handle);
	if(!found) {
		janus_mutex_unlock(&plugin_sessions_mutex);
		return JANUS_ERROR_HANDLE_NOT_FOUND;
	}
	janus_mutex_unlock(&plugin_sessions_mutex);
	janus_plugin *plugin_t = (janus_plugin *)handle->app;
	if(plugin_t == NULL) {
		/* There was no plugin attached, probably something went wrong there 
		虽然要我销毁插件，但是没有发现插件,可能有什么地方出错了
		*/
		janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT);
		janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP);
		if(handle->mainloop != NULL) {
			if(static_event_loops == 0 && handle->mainloop != NULL && g_main_loop_is_running(handle->mainloop)) {
				g_main_loop_quit(handle->mainloop);
			}
		}
		janus_refcount_decrease(&handle->ref);
		return 0;
	}
	JANUS_LOG(LOG_INFO, "Detaching handle from %s; %p %p %p %p\n", plugin_t->get_name(), handle, handle->app_handle, handle->app_handle->gateway_handle, handle->app_handle->plugin_handle);
	/* Actually detach handle... 真实移除插件 */
	if(g_atomic_int_compare_and_exchange(&handle->app_handle->stopped, 0, 1)) {
		/* Notify the plugin that the session's over (the plugin will
		 * remove the other reference to the plugin session handle) 
		 通知插件会话结束（插件将删除对插件会话handle的其他引用）*/
		g_async_queue_push(handle->queued_packets, &janus_ice_detach_handle);
		g_main_context_wakeup(handle->mainctx);
	}
	/* Get rid of the handle now 立即脱离handle */
	if(g_atomic_int_compare_and_exchange(&handle->dump_packets, 1, 0)) {
		janus_text2pcap_close(handle->text2pcap);
		g_clear_pointer(&handle->text2pcap, janus_text2pcap_free);
	}
	/* We only actually destroy the handle later 我们会稍后真实销毁handle */
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Handle detached, scheduling destruction\n", handle->handle_id);
	/* Unref the handle: we only unref the session too when actually freeing the handle, so that it is freed before that */
	janus_refcount_decrease(&handle->ref);
	return 0;
}

/**
 * @brief 释放handle内存
 * 
 * @param handle_ref 
 */
static void janus_ice_handle_free(const janus_refcount *handle_ref) {
	janus_ice_handle *handle = janus_refcount_containerof(handle_ref, janus_ice_handle, ref);
	/* This stack can be destroyed, free all the resources 
	释放handle的所有内存
	*/
	janus_mutex_lock(&handle->mutex);
	if(handle->queued_candidates != NULL) {
		janus_ice_clear_queued_candidates(handle);
		g_async_queue_unref(handle->queued_candidates);
	}
	if(handle->queued_packets != NULL) {
		janus_ice_clear_queued_packets(handle);
		g_async_queue_unref(handle->queued_packets);
	}
	if(static_event_loops == 0 && handle->mainloop != NULL) {
		g_main_loop_unref(handle->mainloop);
		handle->mainloop = NULL;
	}
	if(static_event_loops == 0 && handle->mainctx != NULL) {
		g_main_context_unref(handle->mainctx);
		handle->mainctx = NULL;
	}
	janus_mutex_unlock(&handle->mutex);
	/*释放handle中的一些webRTC的东西*/
	janus_ice_webrtc_free(handle);
	JANUS_LOG(LOG_INFO, "[%"SCNu64"] Handle and related resources freed; %p %p\n", handle->handle_id, handle, handle->session);
	/* Finally, unref the session and free the handle 
	最后释放该插件的session */
	if(handle->session != NULL) {
		janus_session *session = (janus_session *)handle->session;
		janus_refcount_decrease(&session->ref);
	}
	g_free(handle->opaque_id);
	g_free(handle->token);
	g_free(handle);
}

#ifdef HAVE_CLOSE_ASYNC
static void janus_ice_cb_agent_closed(GObject *src, GAsyncResult *result, gpointer data) {
	janus_ice_outgoing_traffic *t = (janus_ice_outgoing_traffic *)data;
	janus_ice_handle *handle = t->handle;

	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Disposing nice agent %p\n", handle->handle_id, handle->agent);
	g_object_unref(handle->agent);
	handle->agent = NULL;
	g_source_unref((GSource *)t);
	janus_refcount_decrease(&handle->ref);
}
#endif

/**
 * @brief 释放插件session内存
 * 
 * @param app_handle_ref 
 */
static void janus_ice_plugin_session_free(const janus_refcount *app_handle_ref) {
	janus_plugin_session *app_handle = janus_refcount_containerof(app_handle_ref, janus_plugin_session, ref);
	/* This app handle can be destroyed, free all the resources
	这个app handle 可以被销毁，释放所有资源 */
	if(app_handle->gateway_handle != NULL) {
		janus_ice_handle *handle = (janus_ice_handle *)app_handle->gateway_handle;
		app_handle->gateway_handle = NULL;
		handle->app_handle = NULL;
		janus_refcount_decrease(&handle->ref);
	}
	g_free(app_handle);
}

/**
 * @brief 先挂断PeerConnection
 * 
 * @param handle 
 * @param reason 
 */
void janus_ice_webrtc_hangup(janus_ice_handle *handle, const char *reason) {
	if(handle == NULL)
		return;
	g_atomic_int_set(&handle->closepc, 0);
	if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT))
		return;
	janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT);
	janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_CLEANING);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_GOT_OFFER);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_GOT_ANSWER);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_NEGOTIATED);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_AUDIO);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_VIDEO);
	/* User will be notified only after the actual hangup 
	只有在实际挂断后才会通知用户*/
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Hanging up PeerConnection because of a %s\n",
		handle->handle_id, reason);
	handle->hangup_reason = reason;
	/* Let's message the loop, we'll notify the plugin from there 
	让我们向循环发送消息，我们将从那里通知插件
*/
	if(handle->queued_packets != NULL) {
#if GLIB_CHECK_VERSION(2, 46, 0)
		g_async_queue_push_front(handle->queued_packets, &janus_ice_hangup_peerconnection);
#else
		g_async_queue_push(handle->queued_packets, &janus_ice_hangup_peerconnection);
#endif
		g_main_context_wakeup(handle->mainctx);
	}
}

/**
 * @brief 释放handle中的一些webRTC的东西
 * 
 * @param handle 
 */
static void janus_ice_webrtc_free(janus_ice_handle *handle) {
	if(handle == NULL)
		return;
	janus_mutex_lock(&handle->mutex);
	if(!handle->agent_created) {
		/* 清除标识位 */
		janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_NEW_DATACHAN_SDP);
		janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_READY);
		janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_CLEANING);
		janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_AGENT);
		janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_E2EE);
		janus_mutex_unlock(&handle->mutex);
		return;
	}
	handle->agent_created = 0;
	if(handle->stream != NULL) {
		/* 仅销毁由 Janus ICE handle 分配的特定ICE stream 的资源 */
		janus_ice_stream_destroy(handle->stream);
		handle->stream = NULL;
	}
	if(handle->agent != NULL) {
#ifdef HAVE_CLOSE_ASYNC
		if(G_IS_OBJECT(handle->agent)) {
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] Removing stream %d from agent %p\n",
				handle->handle_id, handle->stream_id, handle->agent);
			nice_agent_remove_stream(handle->agent, handle->stream_id);
			handle->stream_id = 0;
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] Closing nice agent %p\n", handle->handle_id, handle->agent);
			janus_refcount_increase(&handle->ref);
			if(handle->rtp_source != NULL) {
				/* Destroy the agent asynchronously 异步销毁代理 */
				g_source_ref(handle->rtp_source);
				nice_agent_close_async(handle->agent, janus_ice_cb_agent_closed, handle->rtp_source);
			} else {
				/* No traffic source, destroy it right away 没有传输源,销毁他*/
				if(G_IS_OBJECT(handle->agent))
					g_object_unref(handle->agent);
				handle->agent = NULL;
				janus_refcount_decrease(&handle->ref);
			}
		}
#else
		if(G_IS_OBJECT(handle->agent))
			g_object_unref(handle->agent);
		handle->agent = NULL;
#endif
	}
	if(handle->pending_trickles) {
		while(handle->pending_trickles) {
			GList *temp = g_list_first(handle->pending_trickles);
			handle->pending_trickles = g_list_remove_link(handle->pending_trickles, temp);
			janus_ice_trickle *trickle = (janus_ice_trickle *)temp->data;
			g_list_free(temp);
			/*销毁 janus_ice_trickle 实例*/
			janus_ice_trickle_destroy(trickle);
		}
	}
	handle->pending_trickles = NULL;
	/*清除队列中的candidate*/
	janus_ice_clear_queued_candidates(handle);
	g_free(handle->rtp_profile);
	handle->rtp_profile = NULL;
	g_free(handle->local_sdp);
	handle->local_sdp = NULL;
	g_free(handle->remote_sdp);
	handle->remote_sdp = NULL;
	handle->stream_mid = NULL;
	g_free(handle->audio_mid);
	handle->audio_mid = NULL;
	g_free(handle->video_mid);
	handle->video_mid = NULL;
	g_free(handle->data_mid);
	handle->data_mid = NULL;
	handle->thread = NULL;
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_NEW_DATACHAN_SDP);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_READY);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_CLEANING);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_AGENT);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_E2EE);
	if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP) && handle->hangup_reason) {
		/*过 Janus API 通知 WebRTC 挂断*/
		janus_ice_notify_hangup(handle, handle->hangup_reason);
	}
	handle->hangup_reason = NULL;
	janus_mutex_unlock(&handle->mutex);
	JANUS_LOG(LOG_INFO, "[%"SCNu64"] WebRTC resources freed; %p %p\n", handle->handle_id, handle, handle->session);
}

/**
 * @brief 仅销毁由 Janus ICE handle 分配的特定ICE stream 的资源
 * 
 * @param stream 
 */
void janus_ice_stream_destroy(janus_ice_stream *stream) {
	if(stream == NULL)
		return;
	if(stream->component != NULL) {
		/*仅销毁由 Janus ICE handle 分配的特定ICE component 的资源*/
		janus_ice_component_destroy(stream->component);
		stream->component = NULL;
	}
	/*代办的 Nacked 包 清理回调函数的Map*/
	if(stream->pending_nacked_cleanup && g_hash_table_size(stream->pending_nacked_cleanup) > 0) {
		GHashTableIter iter;
		gpointer val;
		g_hash_table_iter_init(&iter, stream->pending_nacked_cleanup);
		while(g_hash_table_iter_next(&iter, NULL, &val)) {
			GSource *source = val;
			g_source_destroy(source);
		}
		g_hash_table_destroy(stream->pending_nacked_cleanup);
	}
	stream->pending_nacked_cleanup = NULL;
	janus_ice_handle *handle = stream->handle;
	if(handle != NULL) {
		janus_refcount_decrease(&handle->ref);
		stream->handle = NULL;
	}
	janus_refcount_decrease(&stream->ref);
}

/**
 * @brief 释放ice stream 使用的内存
 * 
 * @param stream_ref 
 */
static void janus_ice_stream_free(const janus_refcount *stream_ref) {
	janus_ice_stream *stream = janus_refcount_containerof(stream_ref, janus_ice_stream, ref);
	/* This stream can be destroyed, free all the resources 这个流可以被销毁，释放所有资源*/
	stream->handle = NULL;
	g_free(stream->remote_hashing);
	stream->remote_hashing = NULL;
	g_free(stream->remote_fingerprint);
	stream->remote_fingerprint = NULL;
	g_free(stream->ruser);
	stream->ruser = NULL;
	g_free(stream->rpass);
	stream->rpass = NULL;
	g_free(stream->rid[0]);
	stream->rid[0] = NULL;
	g_free(stream->rid[1]);
	stream->rid[1] = NULL;
	g_free(stream->rid[2]);
	stream->rid[2] = NULL;
	g_list_free(stream->audio_payload_types);
	stream->audio_payload_types = NULL;
	g_list_free(stream->video_payload_types);
	stream->video_payload_types = NULL;
	if(stream->rtx_payload_types != NULL)
		g_hash_table_destroy(stream->rtx_payload_types);
	stream->rtx_payload_types = NULL;
	if(stream->clock_rates != NULL)
		g_hash_table_destroy(stream->clock_rates);
	stream->clock_rates = NULL;
	g_free(stream->audio_codec);
	stream->audio_codec = NULL;
	g_free(stream->video_codec);
	stream->video_codec = NULL;
	g_free(stream->audio_rtcp_ctx);
	stream->audio_rtcp_ctx = NULL;
	g_free(stream->video_rtcp_ctx[0]);
	stream->video_rtcp_ctx[0] = NULL;
	g_free(stream->video_rtcp_ctx[1]);
	stream->video_rtcp_ctx[1] = NULL;
	g_free(stream->video_rtcp_ctx[2]);
	stream->video_rtcp_ctx[2] = NULL;
	if(stream->rtx_nacked[0])
		g_hash_table_destroy(stream->rtx_nacked[0]);
	stream->rtx_nacked[0] = NULL;
	if(stream->rtx_nacked[1])
		g_hash_table_destroy(stream->rtx_nacked[1]);
	stream->rtx_nacked[1] = NULL;
	if(stream->rtx_nacked[2])
		g_hash_table_destroy(stream->rtx_nacked[2]);
	stream->rtx_nacked[2] = NULL;
	g_slist_free_full(stream->transport_wide_received_seq_nums, (GDestroyNotify)g_free);
	stream->transport_wide_received_seq_nums = NULL;
	stream->audio_first_ntp_ts = 0;
	stream->audio_first_rtp_ts = 0;
	stream->video_first_ntp_ts[0] = 0;
	stream->video_first_ntp_ts[1] = 0;
	stream->video_first_ntp_ts[2] = 0;
	stream->video_first_rtp_ts[0] = 0;
	stream->video_first_rtp_ts[1] = 0;
	stream->video_first_rtp_ts[2] = 0;
	stream->audio_last_rtp_ts = 0;
	stream->audio_last_ntp_ts = 0;
	stream->video_last_rtp_ts = 0;
	stream->video_last_ntp_ts = 0;
	g_free(stream);
	stream = NULL;
}

/**
 * @brief 仅销毁由 Janus ICE handle 分配的特定ICE component 的资源
 * 
 * @param component 
 */
void janus_ice_component_destroy(janus_ice_component *component) {
	if(component == NULL)
		return;
	janus_ice_stream *stream = component->stream;
	if(stream != NULL) {
		janus_refcount_decrease(&stream->ref);
		component->stream = NULL;
	}
	/*销毁 janus_dtls_srtp 实例*/
	janus_dtls_srtp_destroy(component->dtls);
	janus_refcount_decrease(&component->ref);
}

/**
 * @brief 仅释放由 Janus ICE handle 分配的特定ICE component 的内存
 * 
 * @param component_ref 
 */
static void janus_ice_component_free(const janus_refcount *component_ref) {
	janus_ice_component *component = janus_refcount_containerof(component_ref, janus_ice_component, ref);
	// ((type *)((char *)(refptr) - offsetof(type, member)))
	if(component->icestate_source != NULL) {
		g_source_destroy(component->icestate_source);
		g_source_unref(component->icestate_source);
		component->icestate_source = NULL;
	}
	if(component->dtlsrt_source != NULL) {
		g_source_destroy(component->dtlsrt_source);
		g_source_unref(component->dtlsrt_source);
		component->dtlsrt_source = NULL;
	}
	if(component->dtls != NULL) {
		/* 销毁 janus_dtls_srtp 实例*/
		janus_dtls_srtp_destroy(component->dtls);
		janus_refcount_decrease(&component->dtls->ref);
		component->dtls = NULL;
	}
	/* 如果有先前发送的 janus_rtp_packet RTP 数据包列表，用来我们作为丢包重传使用，我们也把它删除 */
	if(component->audio_retransmit_buffer != NULL) {
		janus_rtp_packet *p = NULL;
		while((p = (janus_rtp_packet *)g_queue_pop_head(component->audio_retransmit_buffer)) != NULL) {
			/* Remove from hashtable too 同时从seq hashtable也删除 */
			janus_rtp_header *header = (janus_rtp_header *)p->data;
			guint16 seq = ntohs(header->seq_number);
			g_hash_table_remove(component->audio_retransmit_seqs, GUINT_TO_POINTER(seq));
			/* Free the packet 释放RTP包的内存 */
			janus_ice_free_rtp_packet(p);
		}
		g_queue_free(component->audio_retransmit_buffer);
		g_hash_table_destroy(component->audio_retransmit_seqs);
	}
	/* 如果有先前发送的 janus_rtp_packet RTP 数据包列表，用来我们作为丢包重传使用，我们也把它删除 */
	if(component->video_retransmit_buffer != NULL) {
		janus_rtp_packet *p = NULL;
		while((p = (janus_rtp_packet *)g_queue_pop_head(component->video_retransmit_buffer)) != NULL) {
			/* Remove from hashtable too 同时从seq hashtable也删除 */
			janus_rtp_header *header = (janus_rtp_header *)p->data;
			guint16 seq = ntohs(header->seq_number);
			g_hash_table_remove(component->video_retransmit_seqs, GUINT_TO_POINTER(seq));
			/* Free the packet 释放RTP包的内存 */
			janus_ice_free_rtp_packet(p);
		}
		g_queue_free(component->video_retransmit_buffer);
		g_hash_table_destroy(component->video_retransmit_seqs);
	}
	/*判断此组件的 libnice 远程candidate的列表是否为空*/
	if(component->candidates != NULL) {
		/*释放candidate内存*/
		GSList *i = NULL, *candidates = component->candidates;
		for(i = candidates; i; i = i->next) {
			NiceCandidate *c = (NiceCandidate *) i->data;
			if(c != NULL) {
				nice_candidate_free(c);
				c = NULL;
			}
		}
		g_slist_free(candidates);
		candidates = NULL;
	}
	component->candidates = NULL;
	/*判断此组件的本地candidate的 GLib 列表是否为空*/
	if(component->local_candidates != NULL) {
		/*释放candidate内存*/
		GSList *i = NULL, *candidates = component->local_candidates;
		for(i = candidates; i; i = i->next) {
			gchar *c = (gchar *) i->data;
			g_free(c);
		}
		g_slist_free(candidates);
		candidates = NULL;
	}
	component->local_candidates = NULL;
	/*判断此组件的远端candidate的 GLib 列表是否为空*/
	if(component->remote_candidates != NULL) {
		/*释放candidate内存*/
		GSList *i = NULL, *candidates = component->remote_candidates;
		for(i = candidates; i; i = i->next) {
			gchar *c = (gchar *) i->data;
			g_free(c);
		}
		g_slist_free(candidates);
		candidates = NULL;
	}
	component->remote_candidates = NULL;
	g_free(component->selected_pair);
	component->selected_pair = NULL;
	if(component->last_seqs_audio)
		janus_seq_list_free(&component->last_seqs_audio);
	if(component->last_seqs_video[0])
		janus_seq_list_free(&component->last_seqs_video[0]);
	if(component->last_seqs_video[1])
		janus_seq_list_free(&component->last_seqs_video[1]);
	if(component->last_seqs_video[2])
		janus_seq_list_free(&component->last_seqs_video[2]);
	g_free(component);
	//~ janus_mutex_unlock(&handle->mutex);
}

/* Call plugin slow_link callback if a minimum of lost packets are detected within a second 
如果在一秒钟内检测到最少的丢失数据包，则调用插件 slow_link 回调 */
static void janus_slow_link_update(janus_ice_component *component, janus_ice_handle *handle,
		gboolean video, gboolean uplink, guint lost) {
	/* We keep the counters in different janus_ice_stats objects, depending on the direction 
	我们将计数器保存在不同的 janus_ice_stats 对象中，具体取决于方向 */
	guint sl_lost_last_count = uplink ?
		(video ? component->in_stats.sl_lost_count_video : component->in_stats.sl_lost_count_audio) :
		(video ? component->out_stats.sl_lost_count_video : component->out_stats.sl_lost_count_audio);
	guint sl_lost_recently = (lost >= sl_lost_last_count) ? (lost - sl_lost_last_count) : 0;
	if(slowlink_threshold > 0 && sl_lost_recently >= slowlink_threshold) {
		/* Tell the plugin 通知插件 */
		janus_plugin *plugin = (janus_plugin *)handle->app;
		if(plugin && plugin->slow_link && janus_plugin_session_is_alive(handle->app_handle) &&
				!g_atomic_int_get(&handle->destroyed))
			plugin->slow_link(handle->app_handle, uplink, video);
		/* Notify the user/application too 也通知用户/应用程序 */
		janus_session *session = (janus_session *)handle->session;
		if(session != NULL) {
			json_t *event = json_object();
			json_object_set_new(event, "janus", json_string("slowlink"));
			json_object_set_new(event, "session_id", json_integer(session->session_id));
			json_object_set_new(event, "sender", json_integer(handle->handle_id));
			if(opaqueid_in_api && handle->opaque_id != NULL)
				json_object_set_new(event, "opaque_id", json_string(handle->opaque_id));
			json_object_set_new(event, "media", json_string(video ? "video" : "audio"));
			json_object_set_new(event, "uplink", uplink ? json_true() : json_false());
			json_object_set_new(event, "lost", json_integer(sl_lost_recently));
			/* Send the event 发送插件事件通知 */
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] Sending event to transport...; %p\n", handle->handle_id, handle);
			janus_session_notify_event(session, event);
			/* Finally, notify event handlers 最后发送广播事件 */
			if(janus_events_is_enabled()) {
				json_t *info = json_object();
				json_object_set_new(info, "media", json_string(video ? "video" : "audio"));
				json_object_set_new(info, "slow_link", json_string(uplink ? "uplink" : "downlink"));
				json_object_set_new(info, "lost_lastsec", json_integer(sl_lost_recently));
				janus_events_notify_handlers(JANUS_EVENT_TYPE_MEDIA, JANUS_EVENT_SUBTYPE_MEDIA_SLOWLINK,
					session->session_id, handle->handle_id, handle->opaque_id, info);
			}
		}
	}
	/* Update the counter 更新计数器 */
	if(uplink) {
		if(video)
			component->in_stats.sl_lost_count_video = lost;
		else
			component->in_stats.sl_lost_count_audio = lost;
	} else {
		if(video)
			component->out_stats.sl_lost_count_video = lost;
		else
			component->out_stats.sl_lost_count_audio = lost;
	}
}


/* ICE state check timer (needed to check if a failed really is definitive or if things can still improve) 
ICE 状态检查计时器（需要检查失败是否真的是确定的，或者情况是否仍然可以改善）*/
static gboolean janus_ice_check_failed(gpointer data) {
	janus_ice_component *component = (janus_ice_component *)data;
	if(component == NULL)
		return FALSE;
	janus_ice_stream *stream = component->stream;
	if(!stream)
		goto stoptimer;
	janus_ice_handle *handle = stream->handle;
	if(!handle)
		goto stoptimer;
	if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP) ||
			janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT))
		goto stoptimer;
	if(component->state == NICE_COMPONENT_STATE_CONNECTED || component->state == NICE_COMPONENT_STATE_READY) {
		/* ICE succeeded in the meanwhile, get rid of this timer ICE成功了，去掉这个定时器 */
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] ICE succeeded, disabling ICE state check timer!\n", handle->handle_id);
		goto stoptimer;
	}
	/* Still in the failed state, how much time passed since we first detected it? 
	仍然处于失败状态，距离我们第一次检测到它已经过去了多少时间？*/
	if(janus_get_monotonic_time() - component->icefailed_detected < 5*G_USEC_PER_SEC) {
		/* Let's wait a little longer 让我们再等等 */
		return TRUE;
	}
	/* If we got here it means the timer expired, and we should check if this is a failure 
	如果我们到达这里，则意味着计时器已过期，我们应该检查这是否失败 */
	gboolean trickle_recv = (!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_TRICKLE) || janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALL_TRICKLES));
	gboolean answer_recv = janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_GOT_ANSWER);
	gboolean alert_set = janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT);
	/* We may still be waiting for something... but we don't wait forever 
	我们可能还在等待什么……但我们不会永远等待 */
	gboolean do_wait = TRUE;
	if(janus_get_monotonic_time() - component->icefailed_detected >= 15*G_USEC_PER_SEC) {
		do_wait = FALSE;
	}
	if(!do_wait || (handle && trickle_recv && answer_recv && !alert_set)) {
		/* FIXME Should we really give up for what may be a failure in only one of the media? */
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] ICE failed for component %d in stream %d...\n",
			handle->handle_id, component->component_id, stream->stream_id);
		janus_ice_webrtc_hangup(handle, "ICE failed");
		goto stoptimer;
	}
	/* Let's wait a little longer 让我们再等等 */
	JANUS_LOG(LOG_WARN, "[%"SCNu64"] ICE failed for component %d in stream %d, but we're still waiting for some info so we don't care... (trickle %s, answer %s, alert %s)\n",
		handle->handle_id, component->component_id, stream->stream_id,
		trickle_recv ? "received" : "pending",
		answer_recv ? "received" : "pending",
		alert_set ? "set" : "not set");
	return TRUE;

stoptimer:
	if(component->icestate_source != NULL) {
		g_source_destroy(component->icestate_source);
		g_source_unref(component->icestate_source);
		component->icestate_source = NULL;
	}
	return FALSE;
}

/* Callbacks */
static void janus_ice_cb_candidate_gathering_done(NiceAgent *agent, guint stream_id, gpointer user_data) {
	janus_ice_handle *handle = (janus_ice_handle *)user_data;
	if(!handle)
		return;
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Gathering done for stream %d\n", handle->handle_id, stream_id);
	handle->cdone++;
	janus_ice_stream *stream = handle->stream;
	if(!stream || stream->stream_id != stream_id) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"]  No stream %d??\n", handle->handle_id, stream_id);
		return;
	}
	stream->cdone = 1;
	/* If we're doing full-trickle, send an event to the user too */
	if(janus_full_trickle_enabled) {
		/* Send a "trickle" event with completed:true to the browser */
		janus_ice_notify_trickle(handle, NULL);
	}
}

/**
 * @brief ICE组件状态改变了的回调函数
 * 
 * @param agent 
 * @param stream_id 
 * @param component_id 
 * @param state 
 * @param ice 
 */
static void janus_ice_cb_component_state_changed(NiceAgent *agent, guint stream_id, guint component_id, guint state, gpointer ice) {
	janus_ice_handle *handle = (janus_ice_handle *)ice;
	if(!handle)
		return;
	if(component_id > 1) {
		/* State changed for a component we don't need anymore (rtcp-mux) 一些我们不需要的组件被改变了状态 */
		return;
	}
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Component state changed for component %d in stream %d: %d (%s)\n",
		handle->handle_id, component_id, stream_id, state, janus_get_ice_state_name(state));
	janus_ice_stream *stream = handle->stream;
	if(!stream || stream->stream_id != stream_id) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"]     No stream %d??\n", handle->handle_id, stream_id);
		return;
	}
	janus_ice_component *component = stream->component;
	if(!component || component->component_id != component_id) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"]     No component %d in stream %d??\n", handle->handle_id, component_id, stream_id);
		return;
	}
	component->state = state;
	/* Notify event handlers 通知事件handlers 广播*/
	if(janus_events_is_enabled()) {
		janus_session *session = (janus_session *)handle->session;
		json_t *info = json_object();
		json_object_set_new(info, "ice", json_string(janus_get_ice_state_name(state)));
		json_object_set_new(info, "stream_id", json_integer(stream_id));
		json_object_set_new(info, "component_id", json_integer(component_id));
		janus_events_notify_handlers(JANUS_EVENT_TYPE_WEBRTC, JANUS_EVENT_SUBTYPE_WEBRTC_ICE,
			session->session_id, handle->handle_id, handle->opaque_id, info);
	}
	/* FIXME Even in case the state is 'connected', we wait for the 'new-selected-pair' callback to do anything 
	即使状态是“已连接”，我们也会等待“new-selected-pair”回调来做一些事情 */
	if(state == NICE_COMPONENT_STATE_FAILED) {
		/* Failed doesn't mean necessarily we need to give up: we may be trickling 
		失败并不意味着我们必须放弃, 我们可能正在trickling */
		gboolean alert_set = janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT);
		if(alert_set)
			return;
		gboolean trickle_recv = (!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_TRICKLE) || janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALL_TRICKLES));
		gboolean answer_recv = janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_GOT_ANSWER);
		JANUS_LOG(LOG_WARN, "[%"SCNu64"] ICE failed for component %d in stream %d, but let's give it some time... (trickle %s, answer %s, alert %s)\n",
			handle->handle_id, component_id, stream_id,
			trickle_recv ? "received" : "pending",
			answer_recv ? "received" : "pending",
			alert_set ? "set" : "not set");
		/* In case we haven't started a timer yet, let's do it now 
		以防我们没有开始定时器，让我们开始
		*/
		if(component->icestate_source == NULL && component->icefailed_detected == 0) {
			component->icefailed_detected = janus_get_monotonic_time();
			component->icestate_source = g_timeout_source_new(500);
			g_source_set_callback(component->icestate_source, janus_ice_check_failed, component, NULL);
			guint id = g_source_attach(component->icestate_source, handle->mainctx);
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] Creating ICE state check timer with ID %u\n", handle->handle_id, id);
		}
	}
}

#ifndef HAVE_LIBNICE_TCP
static void janus_ice_cb_new_selected_pair (NiceAgent *agent, guint stream_id, guint component_id, gchar *local, gchar *remote, gpointer ice) {
#else
static void janus_ice_cb_new_selected_pair (NiceAgent *agent, guint stream_id, guint component_id, NiceCandidate *local, NiceCandidate *remote, gpointer ice) {
#endif
	janus_ice_handle *handle = (janus_ice_handle *)ice;
	if(!handle)
		return;
	if(component_id > 1) {
		/* New selected pair for a component we don't need anymore (rtcp-mux) */
		return;
	}
#ifndef HAVE_LIBNICE_TCP
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] New selected pair for component %d in stream %d: %s <-> %s\n", handle ? handle->handle_id : 0, component_id, stream_id, local, remote);
#else
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] New selected pair for component %d in stream %d: %s <-> %s\n", handle ? handle->handle_id : 0, component_id, stream_id, local->foundation, remote->foundation);
#endif
	janus_ice_stream *stream = handle->stream;
	if(!stream || stream->stream_id != stream_id) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"]     No stream %d??\n", handle->handle_id, stream_id);
		return;
	}
	janus_ice_component *component = stream->component;
	if(!component || component->component_id != component_id) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"]     No component %d in stream %d??\n", handle->handle_id, component_id, stream_id);
		return;
	}
	char sp[200];
#ifndef HAVE_LIBNICE_TCP
	g_snprintf(sp, 200, "%s <-> %s", local, remote);
#else
	gchar laddress[NICE_ADDRESS_STRING_LEN], raddress[NICE_ADDRESS_STRING_LEN];
	gint lport = 0, rport = 0;
	nice_address_to_string(&(local->addr), (gchar *)&laddress);
	nice_address_to_string(&(remote->addr), (gchar *)&raddress);
	lport = nice_address_get_port(&(local->addr));
	rport = nice_address_get_port(&(remote->addr));
	const char *ltype = NULL, *rtype = NULL;
	switch(local->type) {
		case NICE_CANDIDATE_TYPE_HOST:
			ltype = "host";
			break;
		case NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE:
			ltype = "srflx";
			break;
		case NICE_CANDIDATE_TYPE_PEER_REFLEXIVE:
			ltype = "prflx";
			break;
		case NICE_CANDIDATE_TYPE_RELAYED:
			ltype = "relay";
			break;
		default:
			break;
	}
	switch(remote->type) {
		case NICE_CANDIDATE_TYPE_HOST:
			rtype = "host";
			break;
		case NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE:
			rtype = "srflx";
			break;
		case NICE_CANDIDATE_TYPE_PEER_REFLEXIVE:
			rtype = "prflx";
			break;
		case NICE_CANDIDATE_TYPE_RELAYED:
			rtype = "relay";
			break;
		default:
			break;
	}
	g_snprintf(sp, sizeof(sp), "%s:%d [%s,%s] <-> %s:%d [%s,%s]",
		laddress, lport, ltype, local->transport == NICE_CANDIDATE_TRANSPORT_UDP ? "udp" : "tcp",
		raddress, rport, rtype, remote->transport == NICE_CANDIDATE_TRANSPORT_UDP ? "udp" : "tcp");
#endif
	gboolean newpair = FALSE;
	if(component->selected_pair == NULL || strcmp(sp, component->selected_pair)) {
		newpair = TRUE;
		gchar *prev_selected_pair = component->selected_pair;
		component->selected_pair = g_strdup(sp);
		g_clear_pointer(&prev_selected_pair, g_free);
	}
	/* Notify event handlers */
	if(newpair && janus_events_is_enabled()) {
		janus_session *session = (janus_session *)handle->session;
		json_t *info = json_object();
		json_object_set_new(info, "selected-pair", json_string(sp));
#ifdef HAVE_LIBNICE_TCP
		json_t *candidates = json_object();
		json_t *lcand = json_object();
		json_object_set_new(lcand, "address", json_string(laddress));
		json_object_set_new(lcand, "port", json_integer(lport));
		json_object_set_new(lcand, "type", json_string(ltype));
		json_object_set_new(lcand, "transport", json_string(local->transport == NICE_CANDIDATE_TRANSPORT_UDP ? "udp" : "tcp"));
		json_object_set_new(lcand, "family", json_integer(nice_address_ip_version(&local->addr)));
		json_object_set_new(candidates, "local", lcand);
		json_t *rcand = json_object();
		json_object_set_new(rcand, "address", json_string(raddress));
		json_object_set_new(rcand, "port", json_integer(rport));
		json_object_set_new(rcand, "type", json_string(rtype));
		json_object_set_new(rcand, "transport", json_string(remote->transport == NICE_CANDIDATE_TRANSPORT_UDP ? "udp" : "tcp"));
		json_object_set_new(rcand, "family", json_integer(nice_address_ip_version(&remote->addr)));
		json_object_set_new(candidates, "remote", rcand);
		json_object_set_new(info, "candidates", candidates);
#endif
		json_object_set_new(info, "stream_id", json_integer(stream_id));
		json_object_set_new(info, "component_id", json_integer(component_id));
		janus_events_notify_handlers(JANUS_EVENT_TYPE_WEBRTC, JANUS_EVENT_SUBTYPE_WEBRTC_PAIR,
			session->session_id, handle->handle_id, handle->opaque_id, info);
	}
	/* Have we been here before? (might happen, when trickling) */
	if(component->component_connected > 0)
		return;
	/* FIXME Clear the queue */
	janus_ice_clear_queued_packets(handle);
	/* Now we can start the DTLS handshake (FIXME This was on the 'connected' state notification, before) */
	JANUS_LOG(LOG_VERB, "[%"SCNu64"]   Component is ready enough, starting DTLS handshake...\n", handle->handle_id);
	component->component_connected = janus_get_monotonic_time();
	/* Start the DTLS handshake, at last */
#if GLIB_CHECK_VERSION(2, 46, 0)
	g_async_queue_push_front(handle->queued_packets, &janus_ice_dtls_handshake);
#else
	g_async_queue_push(handle->queued_packets, &janus_ice_dtls_handshake);
#endif
	g_main_context_wakeup(handle->mainctx);
}

/* Candidates management candidates管理的一些方法 */
static int janus_ice_candidate_to_string(janus_ice_handle *handle, NiceCandidate *c, char *buffer, int buflen, gboolean log_candidate, gboolean force_private, guint public_ip_index);
#ifndef HAVE_LIBNICE_TCP
static void janus_ice_cb_new_local_candidate (NiceAgent *agent, guint stream_id, guint component_id, gchar *foundation, gpointer ice) {
#else
static void janus_ice_cb_new_local_candidate (NiceAgent *agent, NiceCandidate *candidate, gpointer ice) {
#endif
	if(!janus_full_trickle_enabled) {
		/* Ignore if we're not full-trickling: for half-trickle
		 * janus_ice_candidates_to_sdp() is used instead */
		return;
	}
	janus_ice_handle *handle = (janus_ice_handle *)ice;
	if(!handle)
		return;
#ifndef HAVE_LIBNICE_TCP
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Discovered new local candidate for component %d in stream %d: foundation=%s\n", handle ? handle->handle_id : 0, component_id, stream_id, foundation);
#else
	const char *ctype = NULL;
	switch(candidate->type) {
		case NICE_CANDIDATE_TYPE_HOST:
			ctype = "host";
			break;
		case NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE:
			ctype = "srflx";
			break;
		case NICE_CANDIDATE_TYPE_PEER_REFLEXIVE:
			ctype = "prflx";
			break;
		case NICE_CANDIDATE_TYPE_RELAYED:
			ctype = "relay";
			break;
		default:
			break;
	}
	guint stream_id = candidate->stream_id;
	guint component_id = candidate->component_id;
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Discovered new local candidate for component %d in stream %d: type=%s\n", handle ? handle->handle_id : 0, component_id, stream_id, ctype);
#endif
	if(component_id > 1) {
		/* New remote candidate for a component we don't need anymore (rtcp-mux) */
		return;
	}
	janus_ice_stream *stream = handle->stream;
	if(!stream || stream->stream_id != stream_id) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"]     No stream %d??\n", handle->handle_id, stream_id);
		return;
	}
	janus_ice_component *component = stream->component;
	if(!component || component->component_id != component_id) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"]     No component %d in stream %d??\n", handle->handle_id, component_id, stream_id);
		return;
	}
#ifndef HAVE_LIBNICE_TCP
	/* Get local candidates and look for the related foundation */
	NiceCandidate *candidate = NULL;
	GSList *candidates = nice_agent_get_local_candidates(agent, component_id, stream_id), *tmp = candidates;
	while(tmp) {
		NiceCandidate *c = (NiceCandidate *)tmp->data;
		/* Check if this is what we're looking for */
		if(!candidate && !strcasecmp(c->foundation, foundation)) {
			/* It is! */
			candidate = c;
		} else {
			nice_candidate_free(c);
		}
		tmp = tmp->next;
	}
	g_slist_free(candidates);
	if(candidate == NULL) {
		JANUS_LOG(LOG_WARN, "Candidate with foundation %s not found?\n", foundation);
		return;
	}
#endif
	char buffer[200];
	guint public_ip_index = 0;
	gboolean ipv6 = (nice_address_ip_version(&candidate->addr) == 6);
	gboolean same_family = (!ipv6 && janus_has_public_ipv4_ip()) || (ipv6 && janus_has_public_ipv6_ip());
	do {
		if(janus_ice_candidate_to_string(handle, candidate, buffer, sizeof(buffer), TRUE, FALSE, public_ip_index) == 0) {
			/* Candidate encoded, send a "trickle" event to the browser (but only if it's not a 'prflx') */
			if(candidate->type == NICE_CANDIDATE_TYPE_PEER_REFLEXIVE) {
				JANUS_LOG(LOG_VERB, "[%"SCNu64"] Skipping prflx candidate...\n", handle->handle_id);
			} else {
				if(strlen(buffer) > 0)
					janus_ice_notify_trickle(handle, buffer);
				/* If nat-1-1 is enabled but we want to keep the private host, add another candidate */
				if(nat_1_1_enabled && public_ip_index == 0 && (keep_private_host || !same_family) &&
						janus_ice_candidate_to_string(handle, candidate, buffer, sizeof(buffer), TRUE, TRUE, public_ip_index) == 0) {
					if(candidate->type == NICE_CANDIDATE_TYPE_PEER_REFLEXIVE) {
						JANUS_LOG(LOG_VERB, "[%"SCNu64"] Skipping prflx candidate...\n", handle->handle_id);
					} else if(strlen(buffer) > 0) {
						janus_ice_notify_trickle(handle, buffer);
					}
				}
			}
		}
		public_ip_index++;
		if(!same_family) {
			/* We don't have any nat-1-1 address of the same family as this candidate, we're done */
			break;
		}
	} while (public_ip_index < janus_get_public_ip_count());

#ifndef HAVE_LIBNICE_TCP
	nice_candidate_free(candidate);
#endif
}

#ifndef HAVE_LIBNICE_TCP
static void janus_ice_cb_new_remote_candidate (NiceAgent *agent, guint stream_id, guint component_id, gchar *foundation, gpointer ice) {
#else
static void janus_ice_cb_new_remote_candidate (NiceAgent *agent, NiceCandidate *candidate, gpointer ice) {
#endif
	janus_ice_handle *handle = (janus_ice_handle *)ice;
	if(!handle)
		return;
#ifndef HAVE_LIBNICE_TCP
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Discovered new remote candidate for component %d in stream %d: foundation=%s\n", handle ? handle->handle_id : 0, component_id, stream_id, foundation);
#else
	const char *ctype = NULL;
	switch(candidate->type) {
		case NICE_CANDIDATE_TYPE_HOST:
			ctype = "host";
			break;
		case NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE:
			ctype = "srflx";
			break;
		case NICE_CANDIDATE_TYPE_PEER_REFLEXIVE:
			ctype = "prflx";
			break;
		case NICE_CANDIDATE_TYPE_RELAYED:
			ctype = "relay";
			break;
		default:
			break;
	}
	guint stream_id = candidate->stream_id;
	guint component_id = candidate->component_id;
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Discovered new remote candidate for component %d in stream %d: type=%s\n", handle ? handle->handle_id : 0, component_id, stream_id, ctype);
#endif
	if(component_id > 1) {
		/* New remote candidate for a component we don't need anymore (rtcp-mux) */
		return;
	}
	janus_ice_stream *stream = handle->stream;
	if(!stream || stream->stream_id != stream_id) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"]     No stream %d??\n", handle->handle_id, stream_id);
		return;
	}
	janus_ice_component *component = stream->component;
	if(!component || component->component_id != component_id) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"]     No component %d in stream %d??\n", handle->handle_id, component_id, stream_id);
		return;
	}
#ifndef HAVE_LIBNICE_TCP
	/* Get remote candidates and look for the related foundation */
	NiceCandidate *candidate = NULL;
	GSList *candidates = nice_agent_get_remote_candidates(agent, component_id, stream_id), *tmp = candidates;
	while(tmp) {
		NiceCandidate *c = (NiceCandidate *)tmp->data;
		if(candidate == NULL) {
			/* Check if this is what we're looking for */
			if(!strcasecmp(c->foundation, foundation)) {
				/* It is! */
				candidate = c;
				tmp = tmp->next;
				continue;
			}
		}
		nice_candidate_free(c);
		tmp = tmp->next;
	}
	g_slist_free(candidates);
	if(candidate == NULL) {
		JANUS_LOG(LOG_WARN, "Candidate with foundation %s not found?\n", foundation);
		return;
	}
#endif
	/* Render the candidate and add it to the remote_candidates cache for the admin API */
	if(candidate->type != NICE_CANDIDATE_TYPE_PEER_REFLEXIVE) {
		/* ... but only if it's 'prflx', the others we add ourselves */
		goto candidatedone;
	}
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Stream #%d, Component #%d\n", handle->handle_id, candidate->stream_id, candidate->component_id);
	gchar address[NICE_ADDRESS_STRING_LEN], base_address[NICE_ADDRESS_STRING_LEN];
	gint port = 0, base_port = 0;
	nice_address_to_string(&(candidate->addr), (gchar *)&address);
	port = nice_address_get_port(&(candidate->addr));
	nice_address_to_string(&(candidate->base_addr), (gchar *)&base_address);
	base_port = nice_address_get_port(&(candidate->base_addr));
	JANUS_LOG(LOG_VERB, "[%"SCNu64"]   Address:    %s:%d\n", handle->handle_id, address, port);
	JANUS_LOG(LOG_VERB, "[%"SCNu64"]   Priority:   %d\n", handle->handle_id, candidate->priority);
	JANUS_LOG(LOG_VERB, "[%"SCNu64"]   Foundation: %s\n", handle->handle_id, candidate->foundation);
	char buffer[200];
	if(candidate->transport == NICE_CANDIDATE_TRANSPORT_UDP) {
		g_snprintf(buffer, sizeof(buffer),
			"%s %d %s %d %s %d typ prflx raddr %s rport %d\r\n",
				candidate->foundation,
				candidate->component_id,
				"udp",
				candidate->priority,
				address,
				port,
				base_address,
				base_port);
	} else {
		if(!janus_ice_tcp_enabled) {
			/* ICETCP support disabled */
			JANUS_LOG(LOG_WARN, "[%"SCNu64"] Skipping prflx TCP candidate, ICETCP support disabled...\n", handle->handle_id);
			goto candidatedone;
		}
#ifndef HAVE_LIBNICE_TCP
		/* TCP candidates are only supported since libnice 0.1.8 */
		JANUS_LOG(LOG_WARN, "[%"SCNu64"] Skipping prflx TCP candidate, the libnice version doesn't support it...\n", handle->handle_id);
			goto candidatedone;
#else
		const char *type = NULL;
		switch(candidate->transport) {
			case NICE_CANDIDATE_TRANSPORT_TCP_ACTIVE:
				type = "active";
				break;
			case NICE_CANDIDATE_TRANSPORT_TCP_PASSIVE:
				type = "passive";
				break;
			case NICE_CANDIDATE_TRANSPORT_TCP_SO:
				type = "so";
				break;
			default:
				break;
		}
		if(type == NULL) {
			/* FIXME Unsupported transport */
			JANUS_LOG(LOG_WARN, "[%"SCNu64"] Unsupported transport, skipping nonUDP/TCP prflx candidate...\n", handle->handle_id);
			goto candidatedone;
		} else {
			g_snprintf(buffer, sizeof(buffer),
				"%s %d %s %d %s %d typ prflx raddr %s rport %d tcptype %s\r\n",
					candidate->foundation,
					candidate->component_id,
					"tcp",
					candidate->priority,
					address,
					port,
					base_address,
					base_port,
					type);
		}
#endif
	}

	/* Now parse the candidate as if we received it from the Janus API */
	int res = janus_sdp_parse_candidate(stream, buffer, 1);
	if(res != 0) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] Failed to parse prflx candidate... (%d)\n", handle->handle_id, res);
	}

candidatedone:
#ifndef HAVE_LIBNICE_TCP
	nice_candidate_free(candidate);
#endif
	return;
}

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
	/*ICE组件*/
	janus_ice_component *component = (janus_ice_component *)ice;
	if(!component) {
		JANUS_LOG(LOG_ERR, "No component %d in stream %d??\n", component_id, stream_id);
		return;
	}
	janus_ice_stream *stream = component->stream;
	if(!stream) {
		JANUS_LOG(LOG_ERR, "No stream %d??\n", stream_id);
		return;
	}
	janus_ice_handle *handle = stream->handle;
	if(!handle) {
		JANUS_LOG(LOG_ERR, "No handle for stream %d??\n", stream_id);
		return;
	}
	janus_session *session = (janus_session *)handle->session;
	if(!component->dtls) {	/* Still waiting for the DTLS stack dtls握手还没完成，不处理数据*/
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] Still waiting for the DTLS stack for component %d in stream %d...\n", handle->handle_id, component_id, stream_id);
		return;
	}
	if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP) || janus_is_stopping()) {
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] Forced to stop it here...\n", handle->handle_id);
		return;
	}
	/* What is this? 判断是dtls数据 */
	if(janus_is_dtls(buf) || (!janus_is_rtp(buf, len) && !janus_is_rtcp(buf, len))) {
		/* This is DTLS: either handshake stuff, or data coming from SCTP DataChannels 
		这是 DTLS：要么是握手的东西，要么是来自 SCTP 数据通道的数据 */
		JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Looks like DTLS!\n", handle->handle_id);
		janus_dtls_srtp_incoming_msg(component->dtls, buf, len);
		/* Update stats (TODO Do the same for the last second window as well) 
		更新统计信息（也对最后一秒窗口执行相同操作）
		*/
		component->in_stats.data.packets++;
		component->in_stats.data.bytes += len;
		return;
	}
	/* Not DTLS... RTP or RTCP? (http://tools.ietf.org/html/rfc5761#section-4) 
	不是DTLS数据，判断是RTP还是RTCP */
	if(janus_is_rtp(buf, len)) {
		/* This is RTP 收到RTP数据包*/
		if(janus_is_webrtc_encryption_enabled() && (!component->dtls || !component->dtls->srtp_valid || !component->dtls->srtp_in)) {
			//如果数据是加密的，且缺失srtp_valid
			JANUS_LOG(LOG_WARN, "[%"SCNu64"]     Missing valid SRTP session (packet arrived too early?), skipping...\n", handle->handle_id);
		} else {
			/*数据不加密，或者持有秘钥 */
			janus_rtp_header *header = (janus_rtp_header *)buf;
			guint32 packet_ssrc = ntohl(header->ssrc);
			/* Is this audio or video? 判断是视频还是音频*/
			int video = 0, vindex = 0, rtx = 0;
			/* Bundled streams, check SSRC */
			video = ((stream->video_ssrc_peer[0] == packet_ssrc
				|| stream->video_ssrc_peer_rtx[0] == packet_ssrc
				|| stream->video_ssrc_peer[1] == packet_ssrc
				|| stream->video_ssrc_peer_rtx[1] == packet_ssrc
				|| stream->video_ssrc_peer[2] == packet_ssrc
				|| stream->video_ssrc_peer_rtx[2] == packet_ssrc) ? 1 : 0);
			if(!video && stream->audio_ssrc_peer != packet_ssrc) {
				/* Apparently we were not told the peer SSRCs, try the RTP mid extension (or payload types)
				显然我们没有被告知 peer SSRCs，尝试 RTP mid 扩展（或有效负载类型） */
				gboolean found = FALSE;
				if(handle->stream->mid_ext_id > 0) {
					char sdes_item[16];
					/*解析mid拓展*/
					if(janus_rtp_header_extension_parse_mid(buf, len, handle->stream->mid_ext_id, sdes_item, sizeof(sdes_item)) == 0) {
						if(handle->audio_mid && !strcmp(handle->audio_mid, sdes_item)) {
							/* It's audio 如果该插件的音频mid等于该rtp的mid */
							JANUS_LOG(LOG_VERB, "[%"SCNu64"] Unadvertized SSRC (%"SCNu32") is audio! (mid %s)\n", handle->handle_id, packet_ssrc, sdes_item);
							video = 0;
							stream->audio_ssrc_peer = packet_ssrc;
							found = TRUE;
						} else if(handle->video_mid && !strcmp(handle->video_mid, sdes_item)) {
							/* It's video 如果该插件的视频mid等于该rtp的mid */
							JANUS_LOG(LOG_VERB, "[%"SCNu64"] Unadvertized SSRC (%"SCNu32") is video! (mid %s)\n", handle->handle_id, packet_ssrc, sdes_item);
							video = 1;
							/* Check if simulcasting is involved 检查是否涉及simulcasting*/
							if(stream->rid[0] == NULL || stream->rid_ext_id < 1) {
								// rid为空，说明不涉及simulcasting
								stream->video_ssrc_peer[0] = packet_ssrc;
								found = TRUE;
							} else {
								if(janus_rtp_header_extension_parse_rid(buf, len, stream->rid_ext_id, sdes_item, sizeof(sdes_item)) == 0) {
									/* Try the RTP stream ID 查看RTP数据中的RTP拓展头中以rid_ext_id为id的的rid数据是否和stream中的rid[0]，rid[1]，rid[2]某一个相同，说明是来自其中一个RTP数据*/
									if(stream->rid[0] != NULL && !strcmp(stream->rid[0], sdes_item)) {
										JANUS_LOG(LOG_VERB, "[%"SCNu64"]  -- Simulcasting: rid=%s\n", handle->handle_id, sdes_item);
										stream->video_ssrc_peer[0] = packet_ssrc;
										vindex = 0;
										found = TRUE;
									} else if(stream->rid[1] != NULL && !strcmp(stream->rid[1], sdes_item)) {
										JANUS_LOG(LOG_VERB, "[%"SCNu64"]  -- Simulcasting #1: rid=%s\n", handle->handle_id, sdes_item);
										stream->video_ssrc_peer[1] = packet_ssrc;
										vindex = 1;
										found = TRUE;
									} else if(stream->rid[2] != NULL && !strcmp(stream->rid[2], sdes_item)) {
										JANUS_LOG(LOG_VERB, "[%"SCNu64"]  -- Simulcasting #2: rid=%s\n", handle->handle_id, sdes_item);
										stream->video_ssrc_peer[2] = packet_ssrc;
										vindex = 2;
										found = TRUE;
									} else {
										JANUS_LOG(LOG_WARN, "[%"SCNu64"]  -- Simulcasting: unknown rid %s..?\n", handle->handle_id, sdes_item);
									}
								} else if(stream->ridrtx_ext_id > 0 &&
										janus_rtp_header_extension_parse_rid(buf, len, stream->ridrtx_ext_id, sdes_item, sizeof(sdes_item)) == 0) {
									/* Try the repaired RTP stream ID 查看RTP数据中的RTP拓展头中以ridrtx_ext_id为id的的rid数据是否和stream中的rid[0]，rid[1]，rid[2]某一个相同，说明是来自其中一个RTP数据*/
									if(stream->rid[0] != NULL && !strcmp(stream->rid[0], sdes_item)) {
										JANUS_LOG(LOG_VERB, "[%"SCNu64"]  -- Simulcasting: rid=%s (rtx)\n", handle->handle_id, sdes_item);
										stream->video_ssrc_peer_rtx[0] = packet_ssrc;
										vindex = 0;
										rtx = 1;
										found = TRUE;
									} else if(stream->rid[1] != NULL && !strcmp(stream->rid[1], sdes_item)) {
										JANUS_LOG(LOG_VERB, "[%"SCNu64"]  -- Simulcasting #1: rid=%s (rtx)\n", handle->handle_id, sdes_item);
										stream->video_ssrc_peer_rtx[1] = packet_ssrc;
										vindex = 1;
										rtx = 1;
										found = TRUE;
									} else if(stream->rid[2] != NULL && !strcmp(stream->rid[2], sdes_item)) {
										JANUS_LOG(LOG_VERB, "[%"SCNu64"]  -- Simulcasting #2: rid=%s (rtx)\n", handle->handle_id, sdes_item);
										stream->video_ssrc_peer_rtx[2] = packet_ssrc;
										vindex = 2;
										rtx = 1;
										found = TRUE;
									} else {
										JANUS_LOG(LOG_WARN, "[%"SCNu64"]  -- Simulcasting: unknown rid %s..?\n", handle->handle_id, sdes_item);
									}
								}
							}
						}
					}
				}
				if(!found) {
					/*没有找到任何音视频数据*/
					JANUS_LOG(LOG_WARN, "[%"SCNu64"] Not video and not audio? dropping (SSRC %"SCNu32")...\n", handle->handle_id, packet_ssrc);
					return;
				}
			}
			/* Make sure we're prepared to receive this media packet
			确保我们需要接收音视频数据
			 */
			if((!video && !stream->audio_recv) || (video && !stream->video_recv))
				return;
			/* If this is video, check if this is simulcast and/or a retransmission using RFC4588 
			如果这是视频，请检查这是否是simulcast 或使用 RFC4588 重新传输*/
			if(video) {
				if(stream->video_ssrc_peer[1] == packet_ssrc) {
					/* FIXME Simulcast (1) */
					JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Simulcast #1 (SSRC %"SCNu32")...\n", handle->handle_id, packet_ssrc);
					vindex = 1;
				} else if(stream->video_ssrc_peer[2] == packet_ssrc) {
					/* FIXME Simulcast (2) */
					JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Simulcast #2 (SSRC %"SCNu32")...\n", handle->handle_id, packet_ssrc);
					vindex = 2;
				} else {
					/* Maybe a video retransmission using RFC4588? 
					也许使用 RFC4588 重新传输视频 */
					if(stream->video_ssrc_peer_rtx[0] == packet_ssrc) {
						rtx = 1;
						vindex = 0;
						JANUS_LOG(LOG_HUGE, "[%"SCNu64"] RFC4588 rtx packet on video (SSRC %"SCNu32")...\n",
							handle->handle_id, packet_ssrc);
					} else if(stream->video_ssrc_peer_rtx[1] == packet_ssrc) {
						rtx = 1;
						vindex = 1;
						JANUS_LOG(LOG_HUGE, "[%"SCNu64"] RFC4588 rtx packet on video #%d (SSRC %"SCNu32")...\n",
							handle->handle_id, vindex, packet_ssrc);
					} else if(stream->video_ssrc_peer_rtx[2] == packet_ssrc) {
						rtx = 1;
						vindex = 2;
						JANUS_LOG(LOG_HUGE, "[%"SCNu64"] RFC4588 rtx packet on video #%d (SSRC %"SCNu32")...\n",
							handle->handle_id, vindex, packet_ssrc);
					}
				}
			}

			int buflen = len;
			/*是否开启webRTC加密，如果开启了，判断秘钥是否有效*/
			srtp_err_status_t res = janus_is_webrtc_encryption_enabled() ? srtp_unprotect(component->dtls->srtp_in, buf, &buflen) : srtp_err_status_ok;
			if(res != srtp_err_status_ok) {
				if(res != srtp_err_status_replay_fail && res != srtp_err_status_replay_old) {
					/* Only print the error if it's not a 'replay fail' or 'replay old' (which is probably just the result of us NACKing a packet) */
					guint32 timestamp = ntohl(header->timestamp);
					guint16 seq = ntohs(header->seq_number);
					JANUS_LOG(LOG_ERR, "[%"SCNu64"]     SRTP unprotect error: %s (len=%d-->%d, ts=%"SCNu32", seq=%"SCNu16")\n", handle->handle_id, janus_srtp_error_str(res), len, buflen, timestamp, seq);
				}
			} else {
				if(video) {
					if(stream->video_ssrc_peer[0] == 0) {
						stream->video_ssrc_peer[0] = ntohl(header->ssrc);
						JANUS_LOG(LOG_VERB, "[%"SCNu64"]     Peer video SSRC: %u\n", handle->handle_id, stream->video_ssrc_peer[0]);
					}
				} else {
					if(stream->audio_ssrc_peer == 0) {
						stream->audio_ssrc_peer = ntohl(header->ssrc);
						JANUS_LOG(LOG_VERB, "[%"SCNu64"]     Peer audio SSRC: %u\n", handle->handle_id, stream->audio_ssrc_peer);
					}
				}
				/* Do we need to dump this packet for debugging? 我们是否需要转储此数据包以进行调试？*/
				if(g_atomic_int_get(&handle->dump_packets))
					janus_text2pcap_dump(handle->text2pcap, JANUS_TEXT2PCAP_RTP, TRUE, buf, buflen,
						"[session=%"SCNu64"][handle=%"SCNu64"]", session->session_id, handle->handle_id);
				/* If this is a retransmission using RFC4588, we have to do something first to get the original packet
				如果这是使用 RFC4588 的重传，我们必须先做一些事情来获取原始数据包 */
				janus_rtp_header *header = (janus_rtp_header *)buf;
				int plen = 0;
				char *payload = janus_rtp_payload(buf, buflen, &plen);
				if (!payload) {
					  JANUS_LOG(LOG_ERR, "[%"SCNu64"]     Error accessing the RTP payload len=%d\n", handle->handle_id, buflen);
				}
				if(rtx) {
					/* RFC4588 的重传操作*/
					/* The original sequence number is in the first two bytes of the payload
					原始序列号在payload的前两个字节中 */
					/* Rewrite the header with the info from the original packet (payload type, SSRC, sequence number) 
					使用原始数据包中的信息（payload类型、SSRC、序列号）重写header */
					header->type = stream->video_payload_type;
					packet_ssrc = stream->video_ssrc_peer[vindex];
					header->ssrc = htonl(packet_ssrc);
					if(plen > 0) {
						memcpy(&header->seq_number, payload, 2);
						/* Finally, remove the original sequence number from the payload: move the whole
						 * payload back two bytes rather than shifting the header forward (avoid misaligned access) 
						   最后，从payload中删除原始序列号：将整个payload向后移动两个字节，而不是将header向前移动（避免未对齐的访问）*/
						buflen -= 2;
						plen -= 2;
						memmove(payload, payload+2, plen);
						header = (janus_rtp_header *)buf;
						if(stream->rid_ext_id > 1 && stream->ridrtx_ext_id > 1) {
							/* Replace the 'repaired' extension ID as well with the 'regular' one 
							   将“repaired”扩展 ID 替换为“regular”扩展 ID*/
							janus_rtp_header_extension_replace_id(buf, buflen, stream->ridrtx_ext_id, stream->rid_ext_id);
						}
					}
				}
				/* Check if we need to handle transport wide cc 检查我们是否需要处理拥塞控制 */
				if(stream->do_transport_wide_cc) {
					guint16 transport_seq_num;
					/* Get transport wide seq num 获取拥塞传输序列号 */
					if(janus_rtp_header_extension_parse_transport_wide_cc(buf, buflen, stream->transport_wide_cc_ext_id, &transport_seq_num)==0) {
						/* Get current timestamp */
						struct timeval now;
						gettimeofday(&now,0);
						/* Create <seq num, time> pair */
						janus_rtcp_transport_wide_cc_stats *stats = g_malloc0(sizeof(janus_rtcp_transport_wide_cc_stats));
						/* Check if we have a sequence wrap 检查我们是否有序列换行 */
						if(transport_seq_num<0x0FFF && (stream->transport_wide_cc_last_seq_num&0xFFFF)>0xF000) {
							/* Increase cycles 增加周期 */
							stream->transport_wide_cc_cycles++;
						}
						/* Get extended value 获取拓展值 */
						guint32 transport_ext_seq_num = stream->transport_wide_cc_cycles<<16 | transport_seq_num;
						/* Store last received transport seq num 存储最后接收的拥塞传输序列号 */
						stream->transport_wide_cc_last_seq_num = transport_seq_num;
						/* Set stats values 设置状态值 */
						stats->transport_seq_num = transport_ext_seq_num;
						stats->timestamp = (((guint64)now.tv_sec)*1E6+now.tv_usec);
						/* Lock and append to received list */
						janus_mutex_lock(&stream->mutex);
						stream->transport_wide_received_seq_nums = g_slist_prepend(stream->transport_wide_received_seq_nums, stats);
						janus_mutex_unlock(&stream->mutex);
					}
				}
				if(video) {
					/* Check if this packet is a duplicate: can happen with RFC4588 检查此数据包是否重复：可能发生在 RFC4588 中 */
					guint16 seqno = ntohs(header->seq_number);
					int nstate = stream->rtx_nacked[vindex] ?
						GPOINTER_TO_INT(g_hash_table_lookup(stream->rtx_nacked[vindex], GUINT_TO_POINTER(seqno))) : 0;
					if(nstate == 1) {
						/* Packet was NACKed and this is the first time we receive it: change state to received 
						数据包被确认，这是我们第一次收到它：将状态更改为收到 */
						JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Received NACKed packet %"SCNu16" (SSRC %"SCNu32", vindex %d)...\n",
							handle->handle_id, seqno, packet_ssrc, vindex);
						g_hash_table_insert(stream->rtx_nacked[vindex], GUINT_TO_POINTER(seqno), GUINT_TO_POINTER(2));
					} else if(nstate == 2) {
						/* We already received this packet: drop it 我们已经接收到这个包了，把它丢弃*/
						JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Detected duplicate packet %"SCNu16" (SSRC %"SCNu32", vindex %d)...\n",
							handle->handle_id, seqno, packet_ssrc, vindex);
						return;
					} else if(rtx && nstate == 0) {
						/* We received a retransmission for a packet we didn't NACK: drop it
						 * FIXME This seems to happen with Chrome when RFC4588 is enabled: in that case,
						 * Chrome sends the first packet ~8 times as a retransmission, probably to ensure
						 * we receive it, since the first packet cannot be NACKed (NACKs are triggered
						 * when there's a gap in between two packets, and the first doesn't have a reference)
						 * Rather than dropping, we should add a better check in the future
						 * 我们收到了一个我们没有 "需要丢包重传" 的数据包的重传：丢弃它
						 * 启用 RFC4588 时，Chrome 似乎会发生这种情况
						 * 在这种情况下，Chrome 发送第一个数据包约 8 次作为重传，可能是为了确保我们接收到它。
						 * 因为第一个数据包不能被触发丢包重传而是会被丢弃（当两个数据包之间存在间隙时会触发丢包重传，而第一个数据包没有参考）
						 * 我们应该在未来添加一个更好的检查
						 *  */
						JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Got a retransmission for non-NACKed packet %"SCNu16" (SSRC %"SCNu32", vindex %d)...\n",
							handle->handle_id, seqno, packet_ssrc, vindex);
						return;
					}
				}
				/* Backup the RTP header before passing it to the proper RTP switching context 
				在将 RTP 标头传递给正确的 RTP context 之前备份它 */
				janus_rtp_header backup = *header;
				if(!video) {
					if(stream->audio_ssrc_peer_orig == 0)
						stream->audio_ssrc_peer_orig = packet_ssrc;
					janus_rtp_header_update(header, &stream->rtp_ctx[0], FALSE, 0);
					header->ssrc = htonl(stream->audio_ssrc_peer_orig);
				} else {
					if(stream->video_ssrc_peer_orig[vindex] == 0)
						stream->video_ssrc_peer_orig[vindex] = packet_ssrc;
					janus_rtp_header_update(header, &stream->rtp_ctx[vindex], TRUE, 0);
					header->ssrc = htonl(stream->video_ssrc_peer_orig[vindex]);
				}
				/* Keep track of payload types too 保持对payload类型的追踪 */
				if(!video && stream->audio_payload_type < 0) {
					/*如果我们收到音频而且audio_payload_type未设置，我们把它进行更新，同时更新音频编解码类型*/
					stream->audio_payload_type = header->type;
					if(stream->audio_codec == NULL) {
						const char *codec = janus_get_codec_from_pt(handle->local_sdp, stream->audio_payload_type);
						if(codec != NULL)
							stream->audio_codec = g_strdup(codec);
					}
				} else if(video && stream->video_payload_type < 0) {
					/*如果我们收到视频而且video_payload_type未设置，我们把它进行更新，同时更新视频编解码类型*/
					stream->video_payload_type = header->type;
					if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RFC4588_RTX) &&
							stream->rtx_payload_types && g_hash_table_size(stream->rtx_payload_types) > 0) {
						stream->video_rtx_payload_type = GPOINTER_TO_INT(g_hash_table_lookup(stream->rtx_payload_types, GINT_TO_POINTER(stream->video_payload_type)));
						JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Retransmissions will have payload type %d\n",
							handle->handle_id, stream->video_rtx_payload_type);
					}
					if(stream->video_codec == NULL) {
						const char *codec = janus_get_codec_from_pt(handle->local_sdp, stream->video_payload_type);
						if(codec != NULL)
							stream->video_codec = g_strdup(codec);
					}
					if(stream->video_is_keyframe == NULL && stream->video_codec != NULL) {
						/*更新关键帧*/
						if(!strcasecmp(stream->video_codec, "vp8"))
							stream->video_is_keyframe = &janus_vp8_is_keyframe;
						else if(!strcasecmp(stream->video_codec, "vp9"))
							stream->video_is_keyframe = &janus_vp9_is_keyframe;
						else if(!strcasecmp(stream->video_codec, "h264"))
							stream->video_is_keyframe = &janus_h264_is_keyframe;
						else if(!strcasecmp(stream->video_codec, "av1"))
							stream->video_is_keyframe = &janus_av1_is_keyframe;
						else if(!strcasecmp(stream->video_codec, "h265"))
							stream->video_is_keyframe = &janus_h265_is_keyframe;
					}
				}
				/* Prepare the data to pass to the responsible plugin 
				准备要传递给负责插件的RTP数据 */
				janus_plugin_rtp rtp = { .video = video, .buffer = buf, .length = buflen };
				janus_plugin_rtp_extensions_reset(&rtp.extensions);
				/* Parse RTP extensions before involving the plugin
				在处理插件之前解析RTP拓展
				 */
				if(stream->audiolevel_ext_id != -1) {
					gboolean vad = FALSE;
					int level = -1;
					if(janus_rtp_header_extension_parse_audio_level(buf, buflen,
							stream->audiolevel_ext_id, &vad, &level) == 0) {
						rtp.extensions.audio_level = level;
						rtp.extensions.audio_level_vad = vad;
					}
				}
				if(stream->videoorientation_ext_id != -1) {
					gboolean c = FALSE, f = FALSE, r1 = FALSE, r0 = FALSE;
					if(janus_rtp_header_extension_parse_video_orientation(buf, buflen,
							stream->videoorientation_ext_id, &c, &f, &r1, &r0) == 0) {
						rtp.extensions.video_rotation = 0;
						if(r1 && r0)
							rtp.extensions.video_rotation = 270;
						else if(r1)
							rtp.extensions.video_rotation = 180;
						else if(r0)
							rtp.extensions.video_rotation = 90;
						rtp.extensions.video_back_camera = c;
						rtp.extensions.video_flipped = f;
					}
				}
				/* Pass the packet to the plugin 把数据传输给插件 */
				janus_plugin *plugin = (janus_plugin *)handle->app;
				if(plugin && plugin->incoming_rtp && handle->app_handle &&
						!g_atomic_int_get(&handle->app_handle->stopped) &&
						!g_atomic_int_get(&handle->destroyed))
					plugin->incoming_rtp(handle->app_handle, &rtp);
				/* Restore the header for the stats (plugins may have messed with it)
				恢复header的统计信息（插件可能对header做了一些操作） */
				*header = backup;
				/* Update stats (overall data received, and data received in the last second) 
				更新统计信息（收到的整体数据，以及最后一秒收到的数据）*/
				if(buflen > 0) {
					gint64 now = janus_get_monotonic_time();
					if(!video) {
						/*处理音频*/
						if(component->in_stats.audio.bytes == 0 || component->in_stats.audio.notified_lastsec) {
							/* We either received our first audio packet, or we started receiving it again after missing more than a second 
							这是我们收到的第一个音频包 或者是 在它丢失超过一秒后再次开始接收它
							我们会通知客户端它上传了音频 通知时机：第一次收到音频包 或者 丢失了数据超过一秒之后重新收到数据
							*/
							component->in_stats.audio.notified_lastsec = FALSE;
							janus_ice_notify_media(handle, FALSE, 0, TRUE);
						}
						/* Overall audio data 更新音频数据*/
						component->in_stats.audio.packets++;
						component->in_stats.audio.bytes += buflen;
						/* Last second audio data 最后一秒的音频数据 */
						if(component->in_stats.audio.updated == 0)
							component->in_stats.audio.updated = now;
						if(now > component->in_stats.audio.updated &&
								now - component->in_stats.audio.updated >= G_USEC_PER_SEC) {
							component->in_stats.audio.bytes_lastsec = component->in_stats.audio.bytes_lastsec_temp;
							component->in_stats.audio.bytes_lastsec_temp = 0;
							component->in_stats.audio.updated = now;
						}
						component->in_stats.audio.bytes_lastsec_temp += buflen;
					} else {
						if(component->in_stats.video[vindex].bytes == 0 || component->in_stats.video[vindex].notified_lastsec) {
							/* We either received our first video packet, or we started receiving it again after missing more than a second 
							这是我们收到的第一个视频包 或者是 在它丢失超过一秒后再次开始接收它
							我们会通知客户端它上传了视频 通知时机：第一次收到视频包 或者 丢失了数据超过一秒之后重新收到数据 */
							component->in_stats.video[vindex].notified_lastsec = FALSE;
							janus_ice_notify_media(handle, TRUE, vindex, TRUE);
						}
						/* Overall video data for this SSRC 更新相对于SSRC的视频数据 */
						component->in_stats.video[vindex].packets++;
						component->in_stats.video[vindex].bytes += buflen;
						/* Last second video data for this SSRC */
						if(component->in_stats.video[vindex].updated == 0)
							component->in_stats.video[vindex].updated = now;
						if(now > component->in_stats.video[vindex].updated &&
								now - component->in_stats.video[vindex].updated >= G_USEC_PER_SEC) {
							component->in_stats.video[vindex].bytes_lastsec = component->in_stats.video[vindex].bytes_lastsec_temp;
							component->in_stats.video[vindex].bytes_lastsec_temp = 0;
							component->in_stats.video[vindex].updated = now;
						}
						component->in_stats.video[vindex].bytes_lastsec_temp += buflen;
					}
				}

				/* Update the RTCP context as well 同时更新RTCP内容 */
				/* 获取某一路视频或者是音频的RTCP信息 */
				rtcp_context *rtcp_ctx = video ? stream->video_rtcp_ctx[vindex] : stream->audio_rtcp_ctx;
				/* 我们是否需要对音频或者视频包做丢包重传 不需要则禁止丢包重传*/
				gboolean retransmissions_disabled = (!video && !component->do_audio_nacks) || (video && !component->do_video_nacks);
				/*通过RTCP控制进入的RTP数据*/
				janus_rtcp_process_incoming_rtp(rtcp_ctx, buf, buflen,
						(video && rtx) ? TRUE : FALSE,
						(video && janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RFC4588_RTX)),
						retransmissions_disabled, stream->clock_rates
				);

				/* Keep track of RTP sequence numbers, in case we need to NACK them */
				/* 	Note: unsigned int overflow/underflow wraps (defined behavior) 
				保持对RTP序列号的追踪，以防我们需要丢包重传
				做好无符号整形的上下溢出防控
				*/
				if(retransmissions_disabled) {
					/* ... unless NACKs are disabled for this medium 如果不需要丢包重传*/
					return;
				}
				/*获取该包序列号*/
				guint16 new_seqn = ntohs(header->seq_number);
				/* If this is video, check if this is a keyframe: if so, we empty our NACK queue 
				如果这是一个视频包，检查它是否是一个关键帧，如果是，我们清空丢包重传队列，因为关键帧可以帮助客户端恢复视频，之前保存的包可以不需要了 */
				if(video && stream->video_is_keyframe) {
					if(stream->video_is_keyframe(payload, plen)) {
						if(rtcp_ctx && (int16_t)(new_seqn - rtcp_ctx->max_seq_nr) > 0) {
							JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Keyframe received with a highest sequence number, resetting NACK queue\n", handle->handle_id);
							janus_seq_list_free(&component->last_seqs_video[vindex]);
						}
					}
				}
				/*新序列号*/
				guint16 cur_seqn;
				/*需要重新传输的序列号数量*/
				int last_seqs_len = 0;
				janus_mutex_lock(&component->mutex);
				/* 获取最后收到的序列号列表 如果获取不到，代表之前被清理了，目前处理的是一个关键帧*/
				janus_seq_info **last_seqs = video ? &component->last_seqs_video[vindex] : &component->last_seqs_audio;
				/*用一个临时变量存储序列号列表，cur_seq用来下面寻找上一个序列号使用 那么就不需要改变last_seqs的指向，方便后续对last_seqs进行释放*/
				janus_seq_info *cur_seq = *last_seqs;
				/*cur_seq 等于上一个序列号 */
				if(cur_seq) {
					/* cur_seqn 等于上一个序列号*/
					cur_seq = cur_seq->prev;
					cur_seqn = cur_seq->seq;
				} else {
					/* First seq, set up to add one seq 如果没有之前的序列号，那么cur_seqn等于目前处理的包序列号-1*/
					cur_seqn = new_seqn - (guint16)1; /* Can wrap */
				}
				/* 判断序列号是否在范围（ 当前序列号-上一个序列号是否小于160)*/
				if(!janus_seq_in_range(new_seqn, cur_seqn, LAST_SEQS_MAX_LEN) && !janus_seq_in_range(cur_seqn, new_seqn, 1000)) {
					/* Jump too big, start fresh 当前序列号比上一个存储的序列号大160以上，说明丢包过于严重，之前存储的包没有再发送的必要，否则客户端延时会加大*/
					JANUS_LOG(LOG_WARN, "[%"SCNu64"] Big sequence number jump %hu -> %hu (%s stream #%d)\n",
						handle->handle_id, cur_seqn, new_seqn, video ? "video" : "audio", vindex);
					janus_seq_list_free(last_seqs);
					cur_seq = NULL;
					cur_seqn = new_seqn - (guint16)1;
				}
				/*丢包重传列表*/
				GSList *nacks = NULL;
				gint64 now = janus_get_monotonic_time();
				if(janus_seq_in_range(new_seqn, cur_seqn, LAST_SEQS_MAX_LEN)) {
					/* Add new seq objs forward 如果缺失的序列号在范围内，把 cur_seqn - > new_seqn之间的序列号补全 */
					while(cur_seqn != new_seqn) {
						cur_seqn += (guint16)1; /* can wrap */
						/* 创建一个新序列号 */
						janus_seq_info *seq_obj = g_malloc0(sizeof(janus_seq_info));
						seq_obj->seq = cur_seqn;
						seq_obj->ts = now;
						/* 当 cur_seqn == new_seqn 不满足之前 说明都是补充的缺失序列号  */
						seq_obj->state = (cur_seqn == new_seqn) ? SEQ_RECVED : SEQ_MISSING;
						janus_seq_append(last_seqs, seq_obj);
						last_seqs_len++;
					}
				}
				if(cur_seq) {
					/* Scan old seq objs backwards 向后寻找旧序列objs 不包含上面创建的新janus_seq_info 因为创建时间和当前时间不会满足时间差 */
					while(cur_seq != NULL) {
						last_seqs_len++;
						if(cur_seq->seq == new_seqn) {
							/* 如果这是当前接收的序列 cur_seq->state 改为 接收（3） */
							JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Received missed sequence number %"SCNu16" (%s stream #%d)\n",
								handle->handle_id, cur_seq->seq, video ? "video" : "audio", vindex);
							cur_seq->state = SEQ_RECVED;
						} else if(cur_seq->state == SEQ_MISSING && now - cur_seq->ts > SEQ_MISSING_WAIT) {
							/* 如果这是缺失的序列号，而且 序列号生产的时间跟现在的时间相差12ms  cur_seq->state 改为 需要丢包重传（1）这次发送了下次可能还会重新被要求重传*/
							JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Missed sequence number %"SCNu16" (%s stream #%d), sending 1st NACK\n",
								handle->handle_id, cur_seq->seq, video ? "video" : "audio", vindex);
							/*添加到丢包重传队列，创建一个新的指针指向cur_seq->seq 放到队列中（将uint类型转换成gpointer类型）*/
							nacks = g_slist_prepend(nacks, GUINT_TO_POINTER(cur_seq->seq));
							cur_seq->state = SEQ_NACKED;
							if(video && janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RFC4588_RTX)) {
								/* 如果这是视频而且是使用RFC4588传输 */
								/* Keep track of this sequence number, we need to avoid duplicates 保持对序列号的追踪，我们需要避免重复 */
								JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Tracking NACKed packet %"SCNu16" (SSRC %"SCNu32", vindex %d)...\n",
									handle->handle_id, cur_seq->seq, packet_ssrc, vindex);
								if(stream->rtx_nacked[vindex] == NULL)
									stream->rtx_nacked[vindex] = g_hash_table_new(NULL, NULL);
								g_hash_table_insert(stream->rtx_nacked[vindex], GUINT_TO_POINTER(cur_seq->seq), GINT_TO_POINTER(1));
								/* We don't track it forever, though: add a timed source to remove it in a few seconds 
								但是，我们不会永远跟踪它：添加一个定时源以在几秒钟内将其删除 */
								janus_ice_nacked_packet *np = g_malloc(sizeof(janus_ice_nacked_packet));
								np->handle = handle;
								np->seq_number = cur_seq->seq;
								np->vindex = vindex;
								if(stream->pending_nacked_cleanup == NULL)
									stream->pending_nacked_cleanup = g_hash_table_new(NULL, NULL);
								GSource *timeout_source = g_timeout_source_new_seconds(5);
								g_source_set_callback(timeout_source, janus_ice_nacked_packet_cleanup, np, (GDestroyNotify)g_free);
								np->source_id = g_source_attach(timeout_source, handle->mainctx);
								g_source_unref(timeout_source);
								g_hash_table_insert(stream->pending_nacked_cleanup, GUINT_TO_POINTER(np->source_id), timeout_source);
							}
						} else if(cur_seq->state == SEQ_NACKED  && now - cur_seq->ts > SEQ_NACKED_WAIT) {
							/* 如果这是 已经丢包重传 的序列号，而且 序列号生产的时间跟现在的时间相差155ms cur_seq->state 改为 放弃（2） 这次发送了下次就不会再处理该数据 */
							JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Missed sequence number %"SCNu16" (%s stream #%d), sending 2nd NACK\n",
								handle->handle_id, cur_seq->seq, video ? "video" : "audio", vindex);
							/*添加到丢包重传队列，创建一个新的指针指向cur_seq->seq 放到队列中（将uint类型转换成gpointer类型）*/
							nacks = g_slist_prepend(nacks, GUINT_TO_POINTER(cur_seq->seq));
							cur_seq->state = SEQ_GIVEUP;
						}
						if(cur_seq == *last_seqs) {
							/* Just processed head */
							break;
						}
						cur_seq = cur_seq->prev;
					}
				}
				while(last_seqs_len > LAST_SEQS_MAX_LEN) {
					/*让存储的序列号列表大小保留在160*/
					janus_seq_info *node = janus_seq_pop_head(last_seqs);
					g_free(node);
					last_seqs_len--;
				}
                /*丢包重传的包数量*/
				guint nacks_count = g_slist_length(nacks);
				if(nacks_count) {
					/* Generate a NACK and send it 发送需要丢包重传的包*/
					JANUS_LOG(LOG_DBG, "[%"SCNu64"] Now sending NACK for %u missed packets (%s stream #%d)\n",
						handle->handle_id, nacks_count, video ? "video" : "audio", vindex);
					char nackbuf[120];
					/* 组装RTCP 丢包重传 包  */
					int res = janus_rtcp_nacks(nackbuf, sizeof(nackbuf), nacks);
					if(res > 0) {
						/* Set the right local and remote SSRC in the RTCP packet
						在 RTCP 数据包中设置正确的本地和远程 SSRC  */
						janus_rtcp_fix_ssrc(NULL, nackbuf, res, 1,
							video ? stream->video_ssrc : stream->audio_ssrc,
							video ? stream->video_ssrc_peer[vindex] : stream->audio_ssrc_peer);
						janus_plugin_rtcp rtcp = { .video = video, .buffer = nackbuf, .length = res };
						/*转发 RTCP 消息的内部方法，可选择过滤它们 如果它们来自插件*/
						janus_ice_relay_rtcp_internal(handle, &rtcp, FALSE);
					}
					/* Update stats 更新统计信息 */
					component->nack_sent_recent_cnt += nacks_count;
					if(video) {
						component->out_stats.video[vindex].nacks += nacks_count;
					} else {
						component->out_stats.audio.nacks += nacks_count;
					}
				}
				if(component->nack_sent_recent_cnt && (now - component->nack_sent_log_ts) > 5*G_USEC_PER_SEC) {
					JANUS_LOG(LOG_VERB, "[%"SCNu64"] Sent NACKs for %u missing packets (%s stream #%d)\n",
						handle->handle_id, component->nack_sent_recent_cnt, video ? "video" : "audio", vindex);
					component->nack_sent_recent_cnt = 0;
					component->nack_sent_log_ts = now;
				}
				janus_mutex_unlock(&component->mutex);
				g_slist_free(nacks);
				nacks = NULL;
			}
		}
		return;
	} else if(janus_is_rtcp(buf, len)) {
		/* This is RTCP 如果是RTCP数据 */
		JANUS_LOG(LOG_HUGE, "[%"SCNu64"]  Got an RTCP packet\n", handle->handle_id);
		/* 我们看看我们是否打开了加密，SRTCP，看看能不能解密*/
		if(janus_is_webrtc_encryption_enabled() && (!component->dtls || !component->dtls->srtp_valid || !component->dtls->srtp_in)) {
			/*缺失解密配置，或者包来的太早了，还没有准备好配置*/
			JANUS_LOG(LOG_WARN, "[%"SCNu64"]     Missing valid SRTP session (packet arrived too early?), skipping...\n", handle->handle_id);
		} else {
			int buflen = len;
			/*如果没有打开加密，那没事，如果打开了加密，看看能不能解密成功*/
			srtp_err_status_t res = janus_is_webrtc_encryption_enabled() ? srtp_unprotect_rtcp(component->dtls->srtp_in, buf, &buflen) : srtp_err_status_ok;
			if(res != srtp_err_status_ok) {
				/*解密失败*/
				JANUS_LOG(LOG_ERR, "[%"SCNu64"]     SRTCP unprotect error: %s (len=%d-->%d)\n", handle->handle_id, janus_srtp_error_str(res), len, buflen);
			} else {
				/* Do we need to dump this packet for debugging? 我们是否需要打印包用于debugging */
				if(g_atomic_int_get(&handle->dump_packets))
					janus_text2pcap_dump(handle->text2pcap, JANUS_TEXT2PCAP_RTCP, TRUE, buf, buflen,
						"[session=%"SCNu64"][handle=%"SCNu64"]", session->session_id, handle->handle_id);
				/* Check if there's an RTCP BYE: in case, let's log it 
				检查这是否是一个RTCP BYE数据，以防万一，我们打印一下
				*/
				if(janus_rtcp_has_bye(buf, buflen)) {
					/* Note: we used to use this as a trigger to close the PeerConnection, but not anymore
					 * Discussion here, https://groups.google.com/forum/#!topic/meetecho-janus/4XtfbYB7Jvc 
					 我们曾经使用它作为关闭 PeerConnection 的触发器，但现在不在这里讨论 */
					JANUS_LOG(LOG_VERB, "[%"SCNu64"] Got RTCP BYE on stream %u (component %u)\n", handle->handle_id, stream->stream_id, component->component_id);
				}
				/* Is this audio or video?  判断是音频还是视频 */
				int video = 0, vindex = 0;
				if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RFC4588_RTX)) {
					/*我们现在通过RFC4588进行传输*/
					janus_rtcp_swap_report_blocks(buf, buflen, stream->video_ssrc_rtx);
				}
				/* Bundled streams, should we check the SSRCs? 绑定流，我们是否应该检查一下SSRCs */
				if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_AUDIO)) {
					/* No audio has been negotiated, definitely video 没有音频被协商 */
					JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Incoming RTCP, bundling: this is video (no audio has been negotiated)\n", handle->handle_id);
					if(stream->video_ssrc_peer[0] == 0) {
						/* We don't know the remote SSRC: this can happen for recvonly clients
						 * (see https://groups.google.com/forum/#!topic/discuss-webrtc/5yuZjV7lkNc)
						 * Check the local SSRC, compare it to what we have
						 * 我们不知道远程 SSRC：recvonly 客户端可能会发生这种情况，
						 * 不发送数据的客户端可能会设置成recvonly，于是也就stream->video_ssrc_peer[0] == 0
						 * 检查本地 SSRC，将其与我们拥有的进行比较 */
						guint32 rtcp_ssrc = janus_rtcp_get_receiver_ssrc(buf, buflen);
						if(rtcp_ssrc == 0) {
							/* No SSRC, maybe an empty RR? 没有SSRC数据 */
							return;
						}
						if(rtcp_ssrc == stream->video_ssrc) {
							/* 如果远端SSRC和本地SSRC相同 */
							video = 1;
						} else if(rtcp_ssrc == stream->video_ssrc_rtx) {
							/* rtx SSRC, we don't care 
							如果远端SSRC和本地SSRC_RTX相同 我们不处理这个*/
							return;
						} else if(janus_rtcp_has_fir(buf, buflen) || janus_rtcp_has_pli(buf, buflen) || janus_rtcp_get_remb(buf, buflen)) {
							/* Mh, no SR or RR? Try checking if there's any FIR, PLI or REMB 
							如果SSRC和本地SSRC，SSRC_RTX都不相同 尝试检查是否有任何 FIR、PLI 或 REMB*/
							video = 1;
						} else {
							/*传来的SSRC没有和任何一个想要的数据匹配上*/
							JANUS_LOG(LOG_VERB, "[%"SCNu64"] Dropping RTCP packet with unknown SSRC (%"SCNu32")\n", handle->handle_id, rtcp_ssrc);
							return;
						}
						JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Incoming RTCP, bundling: this is %s (local SSRC: video=%"SCNu32", got %"SCNu32")\n",
							handle->handle_id, video ? "video" : "audio", stream->video_ssrc, rtcp_ssrc);
					} else {
						/* Check the remote SSRC, compare it to what we have: in case
							* we're simulcasting, let's compare to the other SSRCs too 
							如果 stream->video_ssrc_peer[0] ！= 0 说明我们至少有一路视频流
							检查远程 SSRC，将其与我们拥有的进行比较：如果我们正在simulcasting，让我们也与其他 SSRC 进行比较
							*/
						guint32 rtcp_ssrc = janus_rtcp_get_sender_ssrc(buf, buflen);
						if(rtcp_ssrc == 0) {
							/* No SSRC, maybe an empty RR? 没有SSRC数据*/
							return;
						}
						if(stream->video_ssrc_peer[0] && rtcp_ssrc == stream->video_ssrc_peer[0]) {
							video = 1;
							vindex = 0;
						} else if(stream->video_ssrc_peer[1] && rtcp_ssrc == stream->video_ssrc_peer[1]) {
							video = 1;
							vindex = 1;
						} else if(stream->video_ssrc_peer[2] && rtcp_ssrc == stream->video_ssrc_peer[2]) {
							video = 1;
							vindex = 2;
						} else {
							JANUS_LOG(LOG_VERB, "[%"SCNu64"] Dropping RTCP packet with unknown SSRC (%"SCNu32")\n", handle->handle_id, rtcp_ssrc);
							return;
						}
						JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Incoming RTCP, bundling: this is %s (remote SSRC: video=%"SCNu32" #%d, got %"SCNu32")\n",
							handle->handle_id, video ? "video" : "audio", stream->video_ssrc_peer[vindex], vindex, rtcp_ssrc);
					}
				} else if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_VIDEO)) {
					/* No video has been negotiated, definitely audio 没有视频被协商 */
					JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Incoming RTCP, bundling: this is audio (no video has been negotiated)\n", handle->handle_id);
					video = 0;
				} else {
					if(stream->audio_ssrc_peer == 0 || stream->video_ssrc_peer[0] == 0) {
						/* We don't know the remote SSRC: this can happen for recvonly clients
						 * (see https://groups.google.com/forum/#!topic/discuss-webrtc/5yuZjV7lkNc)
						 * Check the local SSRC, compare it to what we have
						 * 我们不知道远程 SSRC：recvonly 客户端可能会发生这种情况，
						 * 不发送数据的客户端可能会设置成recvonly，于是也就stream->video_ssrc_peer[0] == 0
						 * 检查本地 SSRC，将其与我们拥有的进行比较 */
						guint32 rtcp_ssrc = janus_rtcp_get_receiver_ssrc(buf, buflen);
						if(rtcp_ssrc == 0) {
							/* No SSRC, maybe an empty RR? 没有SSRC数据 */
							return;
						}
						if(rtcp_ssrc == stream->audio_ssrc) {
							video = 0;
						} else if(rtcp_ssrc == stream->video_ssrc) {
							video = 1;
						} else if(rtcp_ssrc == stream->video_ssrc_rtx) {
						    /* rtx SSRC, we don't care 
							如果远端SSRC和本地SSRC_RTX相同 我们不处理这个*/
							return;
						} else if(janus_rtcp_has_fir(buf, buflen) || janus_rtcp_has_pli(buf, buflen) || janus_rtcp_get_remb(buf, buflen)) {
							/* Mh, no SR or RR? Try checking if there's any FIR, PLI or REMB 
							如果SSRC和本地SSRC，SSRC_RTX都不相同 尝试检查是否有任何 FIR、PLI 或 REMB*/
							video = 1;
						} else {
							JANUS_LOG(LOG_VERB, "[%"SCNu64"] Dropping RTCP packet with unknown SSRC (%"SCNu32")\n", handle->handle_id, rtcp_ssrc);
							return;
						}
						JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Incoming RTCP, bundling: this is %s (local SSRC: video=%"SCNu32", audio=%"SCNu32", got %"SCNu32")\n",
							handle->handle_id, video ? "video" : "audio", stream->video_ssrc, stream->audio_ssrc, rtcp_ssrc);
					} else {
						/* Check the remote SSRC, compare it to what we have: in case
							* we're simulcasting, let's compare to the other SSRCs too 
							如果 stream->video_ssrc_peer[0] ！= 0 说明我们至少有一路视频流
							检查远程 SSRC，将其与我们拥有的进行比较：如果我们正在simulcasting，让我们也与其他 SSRC 进行比较
							*/
						guint32 rtcp_ssrc = janus_rtcp_get_sender_ssrc(buf, buflen);
						if(rtcp_ssrc == 0) {
							/* No SSRC, maybe an empty RR? 没有SSRC数据*/
							return;
						}
						if(rtcp_ssrc == stream->audio_ssrc_peer) {
							video = 0;
						} else if(rtcp_ssrc == stream->video_ssrc_peer[0]) {
							video = 1;
						} else if(stream->video_ssrc_peer[1] && rtcp_ssrc == stream->video_ssrc_peer[1]) {
							video = 1;
							vindex = 1;
						} else if(stream->video_ssrc_peer[2] && rtcp_ssrc == stream->video_ssrc_peer[2]) {
							video = 1;
							vindex = 2;
						} else {
							JANUS_LOG(LOG_VERB, "[%"SCNu64"] Dropping RTCP packet with unknown SSRC (%"SCNu32")\n", handle->handle_id, rtcp_ssrc);
							return;
						}
						JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Incoming RTCP, bundling: this is %s (remote SSRC: video=%"SCNu32" #%d, audio=%"SCNu32", got %"SCNu32")\n",
							handle->handle_id, video ? "video" : "audio", stream->video_ssrc_peer[vindex], vindex, stream->audio_ssrc_peer, rtcp_ssrc);
					}
				}

				/* Let's process this RTCP (compound?) packet, and update the RTCP context for this stream in case
				让我们处理这个 RTCP数据包，并更新这个流的 RTCP 上下文，以防万一
				 */
				/* 获取音频或者视频流的RTCP上下文 根据RTCP前面解析的内容决定是音频还是视频，如果是视频，定位到具体的流（如果开启simulcasting） */
				rtcp_context *rtcp_ctx = video ? stream->video_rtcp_ctx[vindex] : stream->audio_rtcp_ctx;
				/* 预计往返时间 */
				uint32_t rtt = rtcp_ctx ? rtcp_ctx->rtt : 0;
				/*解析RTCP包并给RTCP上下文更新数据*/
				if(janus_rtcp_parse(rtcp_ctx, buf, buflen) < 0) {
					/* Drop the packet if the parsing function returns with an error 
					丢弃这个包，如果解析函数返回错误 */
					return;
				}
				if(rtcp_ctx && rtcp_ctx->rtt != rtt) {
					/* Check the current RTT, to see if we need to update the size of the queue: we take
					 * the highest RTT (audio or video) and add 100ms just to be conservative 
					 检查当前的 预计往返时间，看看我们是否需要更新队列的大小：我们取最高的 预计往返时间（音频或视频）并为了保守添加 100ms */
					uint32_t audio_rtt = janus_rtcp_context_get_rtt(stream->audio_rtcp_ctx);
					uint32_t video_rtt = janus_rtcp_context_get_rtt(stream->video_rtcp_ctx[0]);
					uint16_t nack_queue_ms = (audio_rtt > video_rtt ? audio_rtt : video_rtt) + 100;
					if(nack_queue_ms > DEFAULT_MAX_NACK_QUEUE)
						nack_queue_ms = DEFAULT_MAX_NACK_QUEUE;//1000
					else if(nack_queue_ms < min_nack_queue) //默认200 最大1000，取决于 janus.jcfg is中 min_nack_queue参数
						nack_queue_ms = min_nack_queue;
					uint16_t mavg = rtt ? ((7*stream->nack_queue_ms + nack_queue_ms)/8) : nack_queue_ms;
					if(mavg > DEFAULT_MAX_NACK_QUEUE)
						mavg = DEFAULT_MAX_NACK_QUEUE;
					else if(mavg < min_nack_queue)
						mavg = min_nack_queue;
					/*根据发送音频或者视频的往返时间，动态更新 丢包重传队列大小 如果延迟大 会增加队列长度*/
					stream->nack_queue_ms = mavg;
				}
				JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Got %s RTCP (%d bytes)\n", handle->handle_id, video ? "video" : "audio", buflen);
				/* See if there's any REMB bitrate to track */
				uint32_t bitrate = janus_rtcp_get_remb(buf, buflen);
				if(bitrate > 0)
					stream->remb_bitrate = bitrate;

				/* Now let's see if there are any NACKs to handle 现在我们看看是否有 丢包重传数据 需要去处理*/
				gint64 now = janus_get_monotonic_time();
				/*解析 RTCP NACK 消息*/
				GSList *nacks = janus_rtcp_get_nacks(buf, buflen);
				/*RTCP NACK 数量*/
				guint nacks_count = g_slist_length(nacks);
				if(nacks_count && ((!video && component->do_audio_nacks) || (video && component->do_video_nacks))) {
					/* Handle NACK 处理 */
					JANUS_LOG(LOG_HUGE, "[%"SCNu64"]     Just got some NACKS (%d) we should handle...\n", handle->handle_id, nacks_count);
					GHashTable *retransmit_seqs = (video ? component->video_retransmit_seqs : component->audio_retransmit_seqs);
					/*新建指针管理nacks，为了不对原数据造成影响 */
					GSList *list = (retransmit_seqs != NULL ? nacks : NULL);
					/*重新传输的包数量*/
					int retransmits_cnt = 0;
					janus_mutex_lock(&component->mutex);
					while(list) {
						/*获取需要丢包重传的序列号*/
						unsigned int seqnr = GPOINTER_TO_UINT(list->data);
						JANUS_LOG(LOG_DBG, "[%"SCNu64"]   >> %u\n", handle->handle_id, seqnr);
						int in_rb = 0;
						/* Check if we have the packet 检查我们是否有该序列包 */
						janus_rtp_packet *p = g_hash_table_lookup(retransmit_seqs, GUINT_TO_POINTER(seqnr));
						if(p == NULL) {
							/*无法丢包重传，因为我们已经丢失了该包*/
							JANUS_LOG(LOG_HUGE, "[%"SCNu64"]   >> >> Can't retransmit packet %u, we don't have it...\n", handle->handle_id, seqnr);
						} else {
							/* Should we retransmit this packet? 我们是否应该重新传输这个数据包 */
							if((p->last_retransmit > 0) && (now-p->last_retransmit < MAX_NACK_IGNORE)) {
								/*如果我们已经重传过该包，并且现在的时间距离上次重传时间已经超过200ms */
								JANUS_LOG(LOG_HUGE, "[%"SCNu64"]   >> >> Packet %u was retransmitted just %"SCNi64"ms ago, skipping\n", handle->handle_id, seqnr, now-p->last_retransmit);
								list = list->next;
								continue;
							}
							in_rb = 1;
							JANUS_LOG(LOG_HUGE, "[%"SCNu64"]   >> >> Scheduling %u for retransmission due to NACK\n", handle->handle_id, seqnr);
							/*更新重传时间为当前时间*/
							p->last_retransmit = now;
							retransmits_cnt++;
							/* Enqueue it */
							janus_ice_queued_packet *pkt = g_malloc(sizeof(janus_ice_queued_packet));
							pkt->data = g_malloc(p->length+SRTP_MAX_TAG_LEN);
							memcpy(pkt->data, p->data, p->length);
							pkt->length = p->length;
							pkt->type = video ? JANUS_ICE_PACKET_VIDEO : JANUS_ICE_PACKET_AUDIO;
							pkt->control = FALSE;
							pkt->retransmission = TRUE;
							pkt->label = NULL;
							pkt->protocol = NULL;
							pkt->added = janus_get_monotonic_time();
							/* What to send and how depends on whether we're doing RFC4588 or not 
							发送什么以及如何发送取决于我们是否在执行 RFC4588 */
							if(!video || !janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RFC4588_RTX)) {
								/* We're not: just clarify the packet was already encrypted before 
								这是不是一个视频，或者 我们没有执行 RFC4588
								*/
								pkt->encrypted = TRUE;
							} else {
								/* We are: overwrite the RTP header (which means we'll need a new SRTP encrypt) 
								重写 RTP 标头（这意味着我们需要新的 SRTP 加密）*/
								pkt->encrypted = FALSE;
								janus_rtp_header *header = (janus_rtp_header *)pkt->data;
								header->type = stream->video_rtx_payload_type;
								header->ssrc = htonl(stream->video_ssrc_rtx);
								component->rtx_seq_number++;
								header->seq_number = htons(component->rtx_seq_number);
							}
							if(handle->queued_packets != NULL) {
#if GLIB_CHECK_VERSION(2, 46, 0)
								g_async_queue_push_front(handle->queued_packets, pkt);
#else
                                /*异步队列重传RTP包*/
								g_async_queue_push(handle->queued_packets, pkt);
#endif
                                /*唤醒handle线程去处理RTP包*/
								g_main_context_wakeup(handle->mainctx);
							} else {
								janus_ice_free_queued_packet(pkt);
							}
						}
						if(rtcp_ctx != NULL && in_rb) {
							/* 增加RTCP上下文内容：重传次数*/
							g_atomic_int_inc(&rtcp_ctx->nack_count);
						}
						list = list->next;
					}
					component->retransmit_recent_cnt += retransmits_cnt;
					/* FIXME Remove the NACK compound packet, we've handled it 去掉 NACK 包，我们已经处理好了*/
					buflen = janus_rtcp_remove_nacks(buf, buflen);
					/* Update stats 更新统计信息 */
					if(video) {
						component->in_stats.video[vindex].nacks += nacks_count;
					} else {
						component->in_stats.audio.nacks += nacks_count;
					}
					janus_mutex_unlock(&component->mutex);
					g_slist_free(nacks);
					nacks = NULL;
				}
				if(component->retransmit_recent_cnt && now - component->retransmit_log_ts > 5*G_USEC_PER_SEC) {
					/* 间隔 5秒 打印重传信息 */
					JANUS_LOG(LOG_VERB, "[%"SCNu64"] Retransmitted %u packets due to NACK (%s stream #%d)\n",
						handle->handle_id, component->retransmit_recent_cnt, video ? "video" : "audio", vindex);
					component->retransmit_recent_cnt = 0;
					component->retransmit_log_ts = now;
				}

				/* Fix packet data for RTCP SR and RTCP RR 
				修复 RTCP SR 和 RTCP RR 的数据包数据 */
				janus_rtp_switching_context *rtp_ctx = video ? &stream->rtp_ctx[vindex] : &stream->rtp_ctx[0];
				uint32_t base_ts = video ? rtp_ctx->v_base_ts : rtp_ctx->a_base_ts;
				uint32_t base_ts_prev = video ? rtp_ctx->v_base_ts_prev : rtp_ctx->a_base_ts_prev;
				uint32_t ssrc_peer = video ? stream->video_ssrc_peer_orig[vindex] : stream->audio_ssrc_peer_orig;
				uint32_t ssrc_local = video ? stream->video_ssrc : stream->audio_ssrc;
				uint32_t ssrc_expected = video ? rtp_ctx->v_last_ssrc : rtp_ctx->a_last_ssrc;
				/*修复传入 RTCP SR 和 RR 数据*/
				if (janus_rtcp_fix_report_data(buf, buflen, base_ts, base_ts_prev, ssrc_peer, ssrc_local, ssrc_expected, video) < 0) {
					/* Drop packet in case of parsing error or SSRC different from the one expected. */
					/* This might happen at the very beginning of the communication or early after */
					/* a re-negotation has been concluded. */
					return;
				}

				janus_plugin_rtcp rtcp = { .video = video, .buffer = buf, .length = buflen };
				janus_plugin *plugin = (janus_plugin *)handle->app;
				/* 插件处理RTCP数据 */
				if(plugin && plugin->incoming_rtcp && handle->app_handle &&
						!g_atomic_int_get(&handle->app_handle->stopped) &&
						!g_atomic_int_get(&handle->destroyed))
					plugin->incoming_rtcp(handle->app_handle, &rtcp);
			}
		}
		return;
	} else {
		/* 不是RTP 也不是RTCP 数据，可能是一些其他数据*/
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] Not RTP and not RTCP... may these be data channels?\n", handle->handle_id);
		janus_dtls_srtp_incoming_msg(component->dtls, buf, len);
		/* Update stats (only overall data received) 更新统计信息（仅收到全部数据）*/
		if(len > 0) {
			component->in_stats.data.packets++;
			component->in_stats.data.bytes += len;
		}
		return;
	}
}


/**
 * @brief 处理ICE 传入的data数据
 * 
 * @param handle 
 * @param label 
 * @param protocol 
 * @param textdata 
 * @param buffer 
 * @param length 
 */
void janus_ice_incoming_data(janus_ice_handle *handle, char *label, char *protocol, gboolean textdata, char *buffer, int length) {
	if(handle == NULL || buffer == NULL || length <= 0)
		return;
	janus_plugin_data data = { .label = label, .protocol = protocol, .binary = !textdata, .buffer = buffer, .length = length };
	janus_plugin *plugin = (janus_plugin *)handle->app;
	if(plugin && plugin->incoming_data && handle->app_handle &&
			!g_atomic_int_get(&handle->app_handle->stopped) &&
			!g_atomic_int_get(&handle->destroyed))
		plugin->incoming_data(handle->app_handle, &data);
}


/* Helper: encoding local candidates to string/SDP 把本地candidate编码成SDP */
static int janus_ice_candidate_to_string(janus_ice_handle *handle, NiceCandidate *c, char *buffer, int buflen, gboolean log_candidate, gboolean force_private, guint public_ip_index) {
	if(!handle || !handle->agent || !c || !buffer || buflen < 1)
		return -1;
	janus_ice_stream *stream = handle->stream;
	if(!stream)
		return -2;
	janus_ice_component *component = stream->component;
	if(!component)
		return -3;
	char *host_ip = NULL;
	gboolean ipv6 = (nice_address_ip_version(&c->addr) == 6);
	if(nat_1_1_enabled && !force_private) {
		/* A 1:1 NAT mapping was specified, either overwrite all the host addresses with the public IP, or add new candidates 
		指定了 1:1 NAT 映射，要么用公共 IP 覆盖所有主机地址，要么添加新的candidates */
		host_ip = janus_get_public_ip(public_ip_index);
		gboolean host_ip_v6 = (strchr(host_ip, ':') != NULL);
		if(host_ip_v6 != ipv6) {
			/* nat-1-1 address and candidate are not the same address family, don't do anything 
			nat-1-1 地址和候选地址不是同一个地址簇，什么都不做 */
			buffer[0] = '\0';
			return 0;
		}
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] Public IP specified and 1:1 NAT mapping enabled (%s), using that as host address in the candidates\n", handle->handle_id, host_ip);
	}
	/* Encode the candidate to a string 把candidate编码成string */
	gchar address[NICE_ADDRESS_STRING_LEN], base_address[NICE_ADDRESS_STRING_LEN];
	gint port = 0, base_port = 0;
	nice_address_to_string(&(c->addr), (gchar *)&address);
	port = nice_address_get_port(&(c->addr));
	nice_address_to_string(&(c->base_addr), (gchar *)&base_address);
	base_port = nice_address_get_port(&(c->base_addr));
	JANUS_LOG(LOG_VERB, "[%"SCNu64"]   Address:    %s:%d\n", handle->handle_id, address, port);
	JANUS_LOG(LOG_VERB, "[%"SCNu64"]   Priority:   %d\n", handle->handle_id, c->priority);
	JANUS_LOG(LOG_VERB, "[%"SCNu64"]   Foundation: %s\n", handle->handle_id, c->foundation);
	/* Start 开始编码 */
	if(c->type == NICE_CANDIDATE_TYPE_HOST) {
		/* 'host' candidate 主机candidate */
		if(c->transport == NICE_CANDIDATE_TRANSPORT_UDP) {
			/* 如果candidate传输类型是UDP*/
			g_snprintf(buffer, buflen,
				"%s %d %s %d %s %d typ host",
					c->foundation, c->component_id,
					"udp", c->priority,
					host_ip ? host_ip : address, port);
		} else {
			/* 如果candidate传输类型是TCP*/
			if(!janus_ice_tcp_enabled) {
				/* ICE-TCP support disabled 如果TCP candidate被禁用*/
				JANUS_LOG(LOG_VERB, "[%"SCNu64"] Skipping host TCP candidate, ICE-TCP support disabled...\n", handle->handle_id);
				return -4;
			}
#ifndef HAVE_LIBNICE_TCP
			/* TCP candidates are only supported since libnice 0.1.8 TCP candidate 只有在libnice 0.1.8 中被支持 */
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] Skipping host TCP candidate, the libnice version doesn't support it...\n", handle->handle_id);
			return -4;
#else
			const char *type = NULL;
			switch(c->transport) {
				case NICE_CANDIDATE_TRANSPORT_TCP_ACTIVE:
					type = "active";
					break;
				case NICE_CANDIDATE_TRANSPORT_TCP_PASSIVE:
					type = "passive";
					break;
				case NICE_CANDIDATE_TRANSPORT_TCP_SO:
					type = "so";
					break;
				default:
					break;
			}
			if(type == NULL) {
				/* FIXME Unsupported transport 不支持的传输类型 */
				JANUS_LOG(LOG_WARN, "[%"SCNu64"] Unsupported transport, skipping non-UDP/TCP host candidate...\n", handle->handle_id);
				return -5;
			}
			g_snprintf(buffer, buflen,
				"%s %d %s %d %s %d typ host tcptype %s",
					c->foundation, c->component_id,
					"tcp", c->priority,
					host_ip ? host_ip : address, port, type);
#endif
		}
	} else if(c->type == NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE || c->type == NICE_CANDIDATE_TYPE_PEER_REFLEXIVE || c->type == NICE_CANDIDATE_TYPE_RELAYED) {
		/* 'srflx', 'prflx', or 'relay' candidate: what is this, exactly? 
		判断传输类型是srflx，prflx，relay中的哪一种 */
		const char *ltype = NULL;
		switch(c->type) {
			case NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE:
				ltype = "srflx";
				break;
			case NICE_CANDIDATE_TYPE_PEER_REFLEXIVE:
				ltype = "prflx";
				break;
			case NICE_CANDIDATE_TYPE_RELAYED:
				ltype = "relay";
				break;
			default:
				break;
		}
		if(ltype == NULL)
		    /* 不知名的传输类型 */
			return -5;
		if(c->transport == NICE_CANDIDATE_TRANSPORT_UDP) {
			/* 如果candidate传输类型是UDP*/
			nice_address_to_string(&(c->base_addr), (gchar *)&base_address);
			gint base_port = nice_address_get_port(&(c->base_addr));
			g_snprintf(buffer, buflen,
				"%s %d %s %d %s %d typ %s raddr %s rport %d",
					c->foundation, c->component_id,
					"udp", c->priority,
					address, port, ltype,
					base_address, base_port);
		} else {
			if(!janus_ice_tcp_enabled) {
				/* ICE-TCP support disabled 如果TCP candidate被禁用*/
				JANUS_LOG(LOG_VERB, "[%"SCNu64"] Skipping srflx TCP candidate, ICE-TCP support disabled...\n", handle->handle_id);
				return -4;
			}
#ifndef HAVE_LIBNICE_TCP
			/* TCP candidates are only supported since libnice 0.1.8 TCP candidate 只有在libnice 0.1.8 中被支持 */
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] Skipping srflx TCP candidate, the libnice version doesn't support it...\n", handle->handle_id);
			return -4;
#else
			const char *type = NULL;
			switch(c->transport) {
				case NICE_CANDIDATE_TRANSPORT_TCP_ACTIVE:
					type = "active";
					break;
				case NICE_CANDIDATE_TRANSPORT_TCP_PASSIVE:
					type = "passive";
					break;
				case NICE_CANDIDATE_TRANSPORT_TCP_SO:
					type = "so";
					break;
				default:
					break;
			}
			if(type == NULL) {
				/* FIXME Unsupported transport 不支持的传输类型 */
				JANUS_LOG(LOG_WARN, "[%"SCNu64"] Unsupported transport, skipping non-UDP/TCP srflx candidate...\n", handle->handle_id);
				return -5;
			} else {
				g_snprintf(buffer, buflen,
					"%s %d %s %d %s %d typ %s raddr %s rport %d tcptype %s",
						c->foundation, c->component_id,
						"tcp", c->priority,
						address, port, ltype,
						base_address, base_port, type);
			}
#endif
		}
	}
	JANUS_LOG(LOG_VERB, "[%"SCNu64"]     %s\n", handle->handle_id, buffer);
	if(log_candidate) {
		/* Save for the summary, in case we need it 保存一些概况，以防我们需要它们 */
		component->local_candidates = g_slist_append(component->local_candidates, g_strdup(buffer));
		/* Notify event handlers 通知事件 */
		if(janus_events_is_enabled()) {
			janus_session *session = (janus_session *)handle->session;
			json_t *info = json_object();
			json_object_set_new(info, "local-candidate", json_string(buffer));
			json_object_set_new(info, "stream_id", json_integer(stream->stream_id));
			json_object_set_new(info, "component_id", json_integer(component->component_id));
			janus_events_notify_handlers(JANUS_EVENT_TYPE_WEBRTC, JANUS_EVENT_SUBTYPE_WEBRTC_LCAND,
				session->session_id, handle->handle_id, handle->opaque_id, info);
		}
	}
	return 0;
}

/**
 * @brief 把candidate 编码成 sdp
 * 
 * @param handle 
 * @param mline 
 * @param stream_id 
 * @param component_id 
 */
void janus_ice_candidates_to_sdp(janus_ice_handle *handle, janus_sdp_mline *mline, guint stream_id, guint component_id) {
	if(!handle || !handle->agent || !mline)
		return;
	janus_ice_stream *stream = handle->stream;
	if(!stream || stream->stream_id != stream_id) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"]     No stream %d??\n", handle->handle_id, stream_id);
		return;
	}
	janus_ice_component *component = stream->component;
	if(!component || component->component_id != component_id) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"]     No component %d in stream %d??\n", handle->handle_id, component_id, stream_id);
		return;
	}
	/*ICE代理*/
	NiceAgent *agent = handle->agent;
	/* Iterate on all 迭代candidate*/
	gchar buffer[200];
	GSList *candidates, *i;
	/* 从handle的ICE代理中获取candidates */
	candidates = nice_agent_get_local_candidates (agent, stream_id, component_id);
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] We have %d candidates for Stream #%d, Component #%d\n", handle->handle_id, g_slist_length(candidates), stream_id, component_id);
	/*如果 此组件的本地候选者的 GLib 列表为空 log_candidates==ture 后续会 对local_candidates 进行赋值，否之则不会*/
	gboolean log_candidates = (component->local_candidates == NULL);
	for(i = candidates; i; i = i->next) {
		/*获取具体的candidat数据*/
		NiceCandidate *c = (NiceCandidate *) i->data;
		gboolean ipv6 = (nice_address_ip_version(&c->addr) == 6);
		gboolean same_family = (!ipv6 && janus_has_public_ipv4_ip()) || (ipv6 && janus_has_public_ipv6_ip());
		guint public_ip_index = 0;
		do {
			if(janus_ice_candidate_to_string(handle, c, buffer, sizeof(buffer), log_candidates, FALSE, public_ip_index) == 0) {
				/* Candidate encoded, add to the SDP (but only if it's not a 'prflx') 
				候选编码，添加到 SDP（但仅当它不是“prflx”时） */
				if(c->type == NICE_CANDIDATE_TYPE_PEER_REFLEXIVE) {
					JANUS_LOG(LOG_VERB, "[%"SCNu64"] Skipping prflx candidate...\n", handle->handle_id);
				} else {
					if(strlen(buffer) > 0) {
						janus_sdp_attribute *a = janus_sdp_attribute_create("candidate", "%s", buffer);
						mline->attributes = g_list_append(mline->attributes, a);
					}
					if(nat_1_1_enabled && public_ip_index == 0 && (keep_private_host || !same_family) &&
							janus_ice_candidate_to_string(handle, c, buffer, sizeof(buffer), log_candidates, TRUE, public_ip_index) == 0) {
						/* Candidate with private host encoded, add to the SDP (but only if it's not a 'prflx') 
						具有私有主机编码的Candidate，添加到 SDP（但仅当它不是“prflx”时）*/
						if(c->type == NICE_CANDIDATE_TYPE_PEER_REFLEXIVE) {
							JANUS_LOG(LOG_VERB, "[%"SCNu64"] Skipping prflx candidate...\n", handle->handle_id);
						} else if(strlen(buffer) > 0) {
							janus_sdp_attribute *a = janus_sdp_attribute_create("candidate", "%s", buffer);
							mline->attributes = g_list_append(mline->attributes, a);
						}
					}
				}
			}
			public_ip_index++;
			if(!same_family) {
				/* We don't have any nat-1-1 address of the same family as this candidate, we're done
				当我们配置了IPv4却没有IPv4地址或者我们配置了IPv6却没有IPv6地址时，离开*/
				break;
			}
		} while (public_ip_index < janus_get_public_ip_count());
		/*释放candidate内存*/
		nice_candidate_free(c);
	}
	/* Done  释放candidates内存 */
	g_slist_free(candidates);
}

/**
 * @brief 添加远端candidate到队列等待处理
 * 
 * @param handle 
 * @param c 
 */
void janus_ice_add_remote_candidate(janus_ice_handle *handle, NiceCandidate *c) {
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Queueing candidate %p\n", handle->handle_id, c);
	if(handle->queued_candidates != NULL)
		g_async_queue_push(handle->queued_candidates, c);
	if(handle->queued_packets != NULL) {
#if GLIB_CHECK_VERSION(2, 46, 0)
		g_async_queue_push_front(handle->queued_packets, &janus_ice_add_candidates);
#else
		g_async_queue_push(handle->queued_packets, &janus_ice_add_candidates);
#endif
		g_main_context_wakeup(handle->mainctx);
	}
}

/**
 * @brief 处理远程候选人并开始连接检查
 * 
 * @param handle 
 * @param stream_id 
 * @param component_id 
 */
void janus_ice_setup_remote_candidates(janus_ice_handle *handle, guint stream_id, guint component_id) {
	if(!handle || !handle->agent)
		return;
	janus_ice_stream *stream = handle->stream;
	if(!stream || stream->stream_id != stream_id) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] No such stream %d: cannot setup remote candidates for component %d\n", handle->handle_id, stream_id, component_id);
		return;
	}
	janus_ice_component *component = stream->component;
	if(!component || component->component_id != component_id) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] No such component %d in stream %d: cannot setup remote candidates\n", handle->handle_id, component_id, stream_id);
		return;
	}
	if(component->process_started) {
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] Component %d in stream %d has already been set up\n", handle->handle_id, component_id, stream_id);
		return;
	}
	if(!component->candidates || !component->candidates->data) {
		if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_TRICKLE)
				|| janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALL_TRICKLES)) {
			JANUS_LOG(LOG_ERR, "[%"SCNu64"] No remote candidates for component %d in stream %d: was the remote SDP parsed?\n", handle->handle_id, component_id, stream_id);
		}
		return;
	}
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] ## Setting remote candidates: stream %d, component %d (%u in the list)\n",
		handle->handle_id, stream_id, component_id, g_slist_length(component->candidates));
	/* Add all candidates */
	NiceCandidate *c = NULL;
	GSList *gsc = component->candidates;
	while(gsc) {
		c = (NiceCandidate *) gsc->data;
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] Queueing candidate %p (startup)\n", handle->handle_id, c);
		if(handle->queued_candidates != NULL)
			g_async_queue_push(handle->queued_candidates, c);
		gsc = gsc->next;
	}
	if(handle->queued_packets != NULL) {
#if GLIB_CHECK_VERSION(2, 46, 0)
		g_async_queue_push_front(handle->queued_packets, &janus_ice_add_candidates);
#else
		g_async_queue_push(handle->queued_packets, &janus_ice_add_candidates);
#endif
		g_main_context_wakeup(handle->mainctx);
	}
	component->process_started = TRUE;
}

/**
 * @brief 设置本地Description
 * 
 * @param handle 
 * @param offer 是否已经设置了offer
 * @param audio 
 * @param video 
 * @param data 
 * @param trickle 
 * @return int 
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
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Setting ICE locally: got %s (%d audios, %d videos)\n", handle->handle_id, offer ? "OFFER" : "ANSWER", audio, video);
	g_atomic_int_set(&handle->closepc, 0);
	/*设置标志为已经获取代理，清空其余标志（开始，协商，准备，停止，修改，清除，有音频，有视频，ICE重新协商，发送trickles）*/
	janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_AGENT);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_START);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_NEGOTIATED);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_READY);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_CLEANING);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_AUDIO);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_VIDEO);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ICE_RESTART);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RESEND_TRICKLES);

	/* Note: in case this is not an OFFER, we don't know whether any medium are supported on the other side or not yet 
	如果这不是OFFER，我们不知道对方是否支持任何媒体
	*/
	if(audio) {
		janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_AUDIO);
	} else {
		janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_AUDIO);
	}
	if(video) {
		janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_VIDEO);
	} else {
		janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_VIDEO);
	}
	if(data) {
		janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_DATA_CHANNELS);
	} else {
		janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_DATA_CHANNELS);
	}
	/* Note: in case this is not an OFFER, we don't know whether ICE trickling is supported on the other side or not yet 
	如果这不是一个OFFER，我们不知道另一边是否支持 ICE trickling */
	if(offer && trickle) {
		janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_TRICKLE);
	} else {
		janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_TRICKLE);
	}
	/*清除标志（ALL_TRICKLES，TRICKLE_SYNCED）*/
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALL_TRICKLES);
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_TRICKLE_SYNCED);

	/* Note: NICE_COMPATIBILITY_RFC5245 is only available in more recent versions of libnice
	NICE_COMPATIBILITY_RFC5245 仅在较新版本的 libnice 中可用  */
	/* 如果开启了ICE LITE, handle的角色标志成controlled(受控制), 
	 * 如果没有开启ICE LITE ，在收到offer 的时候，！offer = 1 handle的角色标志成controlling (控制) 
	 * 如果没有开启ICE LITE ，在收到answer的时候，！offer = 0 handle的角色标志成controlled (受控制)
	 */
	handle->controlling = janus_ice_lite_enabled ? FALSE : !offer;
	JANUS_LOG(LOG_INFO, "[%"SCNu64"] Creating ICE agent (ICE %s mode, %s)\n", handle->handle_id,
		janus_ice_lite_enabled ? "Lite" : "Full", handle->controlling ? "controlling" : "controlled");
	/*libnice创建一个ICE代理*/
	handle->agent = g_object_new(NICE_TYPE_AGENT,
		"compatibility", NICE_COMPATIBILITY_DRAFT19,
		"main-context", handle->mainctx,
		"reliable", FALSE,
		"full-mode", janus_ice_lite_enabled ? FALSE : TRUE,
#ifdef HAVE_ICE_NOMINATION
		"nomination-mode", janus_ice_nomination,
#endif
		"keepalive-conncheck", janus_ice_keepalive_connchecks ? TRUE : FALSE,
#ifdef HAVE_LIBNICE_TCP
		"ice-udp", TRUE,
		"ice-tcp", janus_ice_tcp_enabled ? TRUE : FALSE,
#endif
		NULL);
	handle->agent_created = janus_get_monotonic_time();
	handle->srtp_errors_count = 0;
	handle->last_srtp_error = 0;
	/* Any STUN server to use? 我们是否需要使用STUN服务器？ */
	if(janus_stun_server != NULL && janus_stun_port > 0) {
		g_object_set(G_OBJECT(handle->agent),
			"stun-server", janus_stun_server,
			"stun-server-port", janus_stun_port,
			NULL);
	}
	/* Any dynamic TURN credentials to retrieve via REST API? 
	任何动态 TURN 凭据可通过 REST API 检索？*/
	gboolean have_turnrest_credentials = FALSE;
#ifdef HAVE_TURNRESTAPI
	/* When using the TURN REST API, we use the handle's opaque_id as a username
	 * by default, and fall back to the session_id when it's missing. Refer to this
	 * issue for more context: https://github.com/meetecho/janus-gateway/issues/2199 
	 * 在使用 TURN REST API 时，我们默认使用handle 的 opaque_id 作为用户名，当它丢失时回退到 session_id
	 * */
	char turnrest_username[20];
	if(handle->opaque_id == NULL) {
		janus_session *session = (janus_session *)handle->session;
		g_snprintf(turnrest_username, sizeof(turnrest_username), "%"SCNu64, session->session_id);
	}
	janus_turnrest_response *turnrest_credentials = janus_turnrest_request((const char *)(handle->opaque_id ?
		handle->opaque_id : turnrest_username));
	if(turnrest_credentials != NULL) {
		have_turnrest_credentials = TRUE;
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] Got credentials from the TURN REST API backend!\n", handle->handle_id);
		JANUS_LOG(LOG_HUGE, "  -- Username: %s\n", turnrest_credentials->username);
		JANUS_LOG(LOG_HUGE, "  -- Password: %s\n", turnrest_credentials->password);
		JANUS_LOG(LOG_HUGE, "  -- TTL:      %"SCNu32"\n", turnrest_credentials->ttl);
		JANUS_LOG(LOG_HUGE, "  -- Servers:  %d\n", g_list_length(turnrest_credentials->servers));
		GList *server = turnrest_credentials->servers;
		while(server != NULL) {
			janus_turnrest_instance *instance = (janus_turnrest_instance *)server->data;
			JANUS_LOG(LOG_HUGE, "  -- -- URI: %s:%"SCNu16" (%d)\n", instance->server, instance->port, instance->transport);
			server = server->next;
		}
	}
#endif
    /*设置代理的配置，例如角色控制状态，candidate收集完成的回调函数，组件状态改变的回调函数*/
	g_object_set(G_OBJECT(handle->agent), "upnp", FALSE, NULL);
	g_object_set(G_OBJECT(handle->agent), "controlling-mode", handle->controlling, NULL);
	g_signal_connect (G_OBJECT (handle->agent), "candidate-gathering-done",
		G_CALLBACK (janus_ice_cb_candidate_gathering_done), handle);
	g_signal_connect (G_OBJECT (handle->agent), "component-state-changed",
		G_CALLBACK (janus_ice_cb_component_state_changed), handle);
	/*是否定义了使用TCP进行ICE连接*/
#ifndef HAVE_LIBNICE_TCP
	g_signal_connect (G_OBJECT (handle->agent), "new-selected-pair",
#else
	g_signal_connect (G_OBJECT (handle->agent), "new-selected-pair-full",
#endif
		G_CALLBACK (janus_ice_cb_new_selected_pair), handle);
	if(janus_full_trickle_enabled) {
#ifndef HAVE_LIBNICE_TCP
		g_signal_connect (G_OBJECT (handle->agent), "new-candidate",
#else
		g_signal_connect (G_OBJECT (handle->agent), "new-candidate-full",
#endif
			G_CALLBACK (janus_ice_cb_new_local_candidate), handle);
	}
#ifndef HAVE_LIBNICE_TCP
	g_signal_connect (G_OBJECT (handle->agent), "new-remote-candidate",
#else
	g_signal_connect (G_OBJECT (handle->agent), "new-remote-candidate-full",
#endif
		G_CALLBACK (janus_ice_cb_new_remote_candidate), handle);

	/* Add all local addresses, except those in the ignore list 
	添加所有本地地址，除了我们需要忽略的那些
	*/
	struct ifaddrs *ifaddr, *ifa;
	int family, s, n;
	char host[NI_MAXHOST];
	if(getifaddrs(&ifaddr) == -1) {
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] Error getting list of interfaces... %d (%s)\n",
			handle->handle_id, errno, g_strerror(errno));
	} else {
		for(ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
			if(ifa->ifa_addr == NULL)
				continue;
			/* Skip interfaces which are not up and running 跳过那些没有在运行的地址*/
			if(!((ifa->ifa_flags & IFF_UP) && (ifa->ifa_flags & IFF_RUNNING)))
				continue;
			/* Skip loopback interfaces 跳过环回地址*/
			if(ifa->ifa_flags & IFF_LOOPBACK)
				continue;
			family = ifa->ifa_addr->sa_family;
			if(family != AF_INET && family != AF_INET6)
				continue;
			/* We only add IPv6 addresses if support for them has been explicitly enabled 
			如果已明确启用对 IPv6 地址的支持，我们只会添加 IPv6 地址*/
			if(family == AF_INET6 && !janus_ipv6_enabled)
				continue;
			/* Check the interface name first, we can ignore that as well: enforce list would be checked later 
			跳过忽略地址*/
			if(janus_ice_enforce_list == NULL && ifa->ifa_name != NULL && janus_ice_is_ignored(ifa->ifa_name))
				continue;
			/*获取地址名称信息*/
			s = getnameinfo(ifa->ifa_addr,
					(family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
					host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
			if(s != 0) {
				JANUS_LOG(LOG_ERR, "[%"SCNu64"] getnameinfo() failed: %s\n", handle->handle_id, gai_strerror(s));
				continue;
			}
			/* Skip 0.0.0.0, :: and, unless otherwise configured, local scoped addresses 
			跳过 0.0.0.0、:: 以及除非另有配置，否则跳过本地范围地址 */
			if(!strcmp(host, "0.0.0.0") || !strcmp(host, "::") || (!janus_ipv6_linklocal_enabled && !strncmp(host, "fe80:", 5)))
				continue;
			/* Check if this IP address is in the ignore/enforce list: the enforce list has the precedence but the ignore list can then discard candidates 
			检查IP地址是否在强制使用列表中，如果强制使用，会有更高优先级，如果忽略，则丢弃*/
			if(janus_ice_enforce_list != NULL) {
				if(ifa->ifa_name != NULL && !janus_ice_is_enforced(ifa->ifa_name) && !janus_ice_is_enforced(host))
					continue;
			}
			if(janus_ice_is_ignored(host))
				continue;
			/* Ok, add interface to the ICE agent 添加地址到ICE代理 */
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] Adding %s to the addresses to gather candidates for\n", handle->handle_id, host);
			NiceAddress addr_local;
			nice_address_init (&addr_local);
			if(!nice_address_set_from_string (&addr_local, host)) {
				/*添加地址失败，可能是无效地址*/
				JANUS_LOG(LOG_WARN, "[%"SCNu64"] Skipping invalid address %s\n", handle->handle_id, host);
				continue;
			}
			/*添加地址到ICE代理*/
			nice_agent_add_local_address (handle->agent, &addr_local);
		}
		/*释放已使用的资源*/
		freeifaddrs(ifaddr);
	}

	handle->cdone = 0;
	handle->stream_id = 0;
	/* If this is our first offer, let's generate some mids 如果这是我们的第一个offer，生成一些mids */
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
#ifdef HAVE_SCTP
		if(data) {
			if(handle->data_mid == NULL)
				handle->data_mid = g_strdup("data");
			if(handle->stream_mid == NULL)
				handle->stream_mid = handle->data_mid;
		}
#endif
	}
	/* Now create an ICE stream for all the media we'll handle
	现在为了所有我们处理的媒体生成一个ICE stream
	 */
	handle->stream_id = nice_agent_add_stream(handle->agent, 1);
	if(dscp_ef > 0) {
		/* A DSCP value was configured, shift it and pass it to libnice as a TOS
		如果配置了 DSCP 值，将其转换并作为 TOS 传递给 libnice */
		nice_agent_set_stream_tos(handle->agent, handle->stream_id, dscp_ef << 2);
	}
	/*初始化一个ICE stream*/
	janus_ice_stream *stream = g_malloc0(sizeof(janus_ice_stream));
	/*增加一些引用计数*/
	janus_refcount_init(&stream->ref, janus_ice_stream_free);
	janus_refcount_increase(&handle->ref);
	/*ICE stream 赋值*/
	stream->stream_id = handle->stream_id;
	stream->handle = handle;
	stream->audio_payload_type = -1;
	stream->video_payload_type = -1;
	stream->video_rtx_payload_type = -1;
	stream->nack_queue_ms = min_nack_queue;
	/* FIXME By default, if we're being called we're DTLS clients, but this may be changed by ICE...
	如果我们接受offer，那么我们是接收端，反之我们是客户端 */
	stream->dtls_role = offer ? JANUS_DTLS_ROLE_CLIENT : JANUS_DTLS_ROLE_ACTPASS;
	if(audio) {
		stream->audio_ssrc = janus_random_uint32();	/* FIXME Should we look for conflicts? 我们是否应该寻找冲突？ 这里可能会有ssrc冲突 概率很低*/
		stream->audio_rtcp_ctx = g_malloc0(sizeof(janus_rtcp_context));
		stream->audio_rtcp_ctx->tb = 48000;	/* May change later 可能会被后续请求修改 */
	}
	if(video) {
		stream->video_ssrc = janus_random_uint32();	/* FIXME Should we look for conflicts? 我们是否应该寻找冲突？ 这里可能会有ssrc冲突 概率很低*/
		if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RFC4588_RTX)) {
			/* Create an SSRC for RFC4588 as well */
			stream->video_ssrc_rtx = janus_random_uint32();	/* FIXME Should we look for conflicts? 我们是否应该寻找冲突？ 这里可能会有ssrc_rtx冲突 概率很低*/
		}
		stream->video_rtcp_ctx[0] = g_malloc0(sizeof(janus_rtcp_context));
		stream->video_rtcp_ctx[0]->tb = 90000;
	}
	janus_mutex_init(&stream->mutex);
	if(!have_turnrest_credentials) {
		/* No TURN REST API server and credentials, any static ones? 
		没有配置动态turn服务API来获取turn服务，我们是否有一个静态的turn服务？*/
		if(janus_turn_server != NULL) {
			/* We need relay candidates as well 我们有一个静态的turn服务，需要转发candidate */
			gboolean ok = nice_agent_set_relay_info(handle->agent, handle->stream_id, 1,
				janus_turn_server, janus_turn_port, janus_turn_user, janus_turn_pwd, janus_turn_type);
			if(!ok) {
				JANUS_LOG(LOG_WARN, "Could not set TURN server, is the address correct? (%s:%"SCNu16")\n",
					janus_turn_server, janus_turn_port);
			}
		}
#ifdef HAVE_TURNRESTAPI
	} else {
		/* We need relay candidates as well: add all those we got 
		我们配置了动态turn服务API来获取turn服务*/
		GList *server = turnrest_credentials->servers;
		while(server != NULL) {
			/*转发candidate*/
			janus_turnrest_instance *instance = (janus_turnrest_instance *)server->data;
			gboolean ok = nice_agent_set_relay_info(handle->agent, handle->stream_id, 1,
				instance->server, instance->port,
				turnrest_credentials->username, turnrest_credentials->password,
				instance->transport);
			if(!ok) {
				JANUS_LOG(LOG_WARN, "Could not set TURN server, is the address correct? (%s:%"SCNu16")\n",
					instance->server, instance->port);
			}
			server = server->next;
		}
#endif
	}
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
#ifdef HAVE_PORTRANGE
    /*是否有端口范围*/
	/* FIXME: libnice supports this since 0.1.0, but the 0.1.3 on Fedora fails with an undefined reference! 
	libnice 从 0.1.0 开始就支持这一点，但是 Fedora 上的 0.1.3 会失败并带有未定义的引用*/
	nice_agent_set_port_range(handle->agent, handle->stream_id, 1, rtp_range_min, rtp_range_max);
#endif
	/* Gather now only if we're doing hanf-trickle
	仅当我们正在做 hanf-trickle 时才收集 */
	if(!janus_full_trickle_enabled && !nice_agent_gather_candidates(handle->agent, handle->stream_id)) {
#ifdef HAVE_TURNRESTAPI
		if(turnrest_credentials != NULL) {
			janus_turnrest_response_destroy(turnrest_credentials);
			turnrest_credentials = NULL;
		}
#endif
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] Error gathering candidates...\n", handle->handle_id);
		janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_AGENT);
		janus_ice_webrtc_hangup(handle, "Gathering error");
		return -1;
	}
	nice_agent_attach_recv(handle->agent, handle->stream_id, 1, g_main_loop_get_context(handle->mainloop), janus_ice_cb_nice_recv, component);
#ifdef HAVE_TURNRESTAPI
	if(turnrest_credentials != NULL) {
		janus_turnrest_response_destroy(turnrest_credentials);
		turnrest_credentials = NULL;
	}
#endif
	/* Create DTLS-SRTP context, at last 最后创建DTLS-SRTP内容 */
	component->dtls = janus_dtls_srtp_create(component, stream->dtls_role);
	if(!component->dtls) {
		/* FIXME We should clear some resources...如果创建失败，我们需要清理一些资源 */
		JANUS_LOG(LOG_ERR, "[%"SCNu64"] Error creating DTLS-SRTP stack...\n", handle->handle_id);
		janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_AGENT);
		janus_ice_webrtc_hangup(handle, "DTLS-SRTP stack error");
		return -1;
	}
	janus_refcount_increase(&component->dtls->ref);
	/* If we're doing full-tricke, start gathering asynchronously 
	如果我们在做full-trickle，开始异步收集
	*/
	if(janus_full_trickle_enabled) {
#if GLIB_CHECK_VERSION(2, 46, 0)
		g_async_queue_push_front(handle->queued_packets, &janus_ice_start_gathering);
#else
		g_async_queue_push(handle->queued_packets, &janus_ice_start_gathering);
#endif
		g_main_context_wakeup(handle->mainctx);
	}
	return 0;
}

/**
 * @brief ICE重新协商
 * 
 * @param handle 
 */
void janus_ice_restart(janus_ice_handle *handle) {
	if(!handle || !handle->agent || !handle->stream)
		return;
	/* Restart ICE */
	if(nice_agent_restart(handle->agent) == FALSE) {
		JANUS_LOG(LOG_WARN, "[%"SCNu64"] ICE restart failed...\n", handle->handle_id);
	}
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ICE_RESTART);
}

/*重新发送trickle给客户端*/
void janus_ice_resend_trickles(janus_ice_handle *handle) {
	if(!handle || !handle->agent)
		return;
	janus_flags_clear(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RESEND_TRICKLES);
	janus_ice_stream *stream = handle->stream;
	if(!stream)
		return;
	janus_ice_component *component = stream->component;
	if(!component)
		return;
	NiceAgent *agent = handle->agent;
	/* Iterate on all existing local candidates 迭代所有已经存在的本地candidate */
	gchar buffer[200];
	GSList *candidates, *i;
	candidates = nice_agent_get_local_candidates (agent, stream->stream_id, component->component_id);
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] We have %d candidates for Stream #%d, Component #%d\n",
		handle->handle_id, g_slist_length(candidates), stream->stream_id, component->component_id);
	for(i = candidates; i; i = i->next) {
		NiceCandidate *c = (NiceCandidate *) i->data;
		if(c->type == NICE_CANDIDATE_TYPE_PEER_REFLEXIVE) {
			nice_candidate_free(c);
			continue;
		}

		guint public_ip_index = 0;
		do {
			if(janus_ice_candidate_to_string(handle, c, buffer, sizeof(buffer), FALSE, FALSE, public_ip_index) == 0) {
				/* Candidate encoded, send a "trickle" event to the browser
				candidate编码，向客户端发送trickle回复（带有candidate），客户端通过webRTC进行重新协商ICE
				 */
				janus_ice_notify_trickle(handle, buffer);
				/* If nat-1-1 is enabled but we want to keep the private host, add another candidate
				如果开启了1对1 nat地址映射但是我们想要保持私有地址，添加其他的candidate
				 */
				if(nat_1_1_enabled && keep_private_host && public_ip_index == 0 &&
						janus_ice_candidate_to_string(handle, c, buffer, sizeof(buffer), FALSE, TRUE, public_ip_index) == 0) {
					/* Candidate encoded, send a "trickle" event to the browser 
					candidate编码，向客户端发送trickle回复（带有candidate），客户端通过webRTC进行重新协商ICE */
					janus_ice_notify_trickle(handle, buffer);
				}
			}
			public_ip_index++;
		} while (public_ip_index < janus_get_public_ip_count());
		nice_candidate_free(c);
	}
	/* Send a "completed" trickle at the end 最后发送completed */
	janus_ice_notify_trickle(handle, NULL);
}


/**
 * @brief 比较两个RTCP拥塞传输的序列号，使用该比较器供list进行排序 （升序）
 * 
 * @param item1 
 * @param item2 
 * @return gint 
 */
static gint rtcp_transport_wide_cc_stats_comparator(gconstpointer item1, gconstpointer item2) {
	return ((rtcp_transport_wide_cc_stats*)item1)->transport_seq_num - ((rtcp_transport_wide_cc_stats*)item2)->transport_seq_num;
}

/**
 * @brief 发送传输拥塞控制反馈信息
 * 
 * @param user_data 
 * @return gboolean 
 */
static gboolean janus_ice_outgoing_transport_wide_cc_feedback(gpointer user_data) {
	janus_ice_handle *handle = (janus_ice_handle *)user_data;
	janus_ice_stream *stream = handle->stream;
	if(stream && stream->video_recv && stream->do_transport_wide_cc) {
		/* Create a transport wide feedback message  创建拥塞控制反馈信息 */
		size_t size = 1300;
		char rtcpbuf[1300];
		/* Order packet list 对拥塞控制接收到的序列号进行从小到大排序 */
		stream->transport_wide_received_seq_nums = g_slist_sort(stream->transport_wide_received_seq_nums,
			rtcp_transport_wide_cc_stats_comparator);
		/* Create full stats queue 创建包队列 */
		GQueue *packets = g_queue_new();
		/* For all packets 对所有排序好的序列号进行迭代 */
		GSList *it = NULL;
		/* 补齐每一个缺失的序列号 */
		for(it = stream->transport_wide_received_seq_nums; it; it = it->next) {
			/* Get stat 获取统计信息 */
			janus_rtcp_transport_wide_cc_stats *stats = (janus_rtcp_transport_wide_cc_stats *)it->data;
			/* Get transport seq 获取传输序列号 */
			guint32 transport_seq_num = stats->transport_seq_num;
			/* Check if it is an out of order 检查它是否小于最后一次反馈的序列号，我们只发送大于最后一次反馈的序列号 */
			if(transport_seq_num < stream->transport_wide_cc_last_feedback_seq_num) {
				/* Skip, it was already reported as lost 跳过，它已经被报告成丢失了  */
				g_free(stats);
				continue;
			}
			/* If not first 检查之前有没有反馈过 */
			if(stream->transport_wide_cc_last_feedback_seq_num) {
				/* 如果当前 stream 有反馈过拥塞控制的序列号 */
				/* For each lost */
				guint32 i = 0;
				/* 从上一次反馈的序列号+1 -> 该循环当前序列号-1 标记成missing 说明之前的反馈都没有收到 */
				for(i = stream->transport_wide_cc_last_feedback_seq_num+1; i<transport_seq_num; ++i) {
					/* Create new stat */
					janus_rtcp_transport_wide_cc_stats *missing = g_malloc(sizeof(janus_rtcp_transport_wide_cc_stats));
					/* Add missing packet */
					missing->transport_seq_num = i;
					missing->timestamp = 0;
					/* Add it */
					g_queue_push_tail(packets, missing);
				}
			}
			/* Store last 把最后一次反馈的序列号设置成该循环当前的反馈序列号 */
			stream->transport_wide_cc_last_feedback_seq_num = transport_seq_num;
			/* Add this one 把该循环当前序列号也丢进队列等待处理 */
			g_queue_push_tail(packets, stats);
		}
		/* Free and reset stats list 释放一些资源 */
		g_slist_free(stream->transport_wide_received_seq_nums);
		stream->transport_wide_received_seq_nums = NULL;
		/* Create and enqueue RTCP packets 创建 RTCP 数据包并将其排入队列 */
		guint packets_len = 0;
		while((packets_len = g_queue_get_length(packets)) > 0) {
			GQueue *packets_to_process;
			/* If we have more than 400 packets to acknowledge, let's send more than one message 
			如果我们要确认的数据包超过 400 个，让我们一次发送多个消息
			*/
			if(packets_len > 400) {
				/* Split the queue into two 将队列分成两部分 */
				GList *new_head = g_queue_peek_nth_link(packets, 400);
				GList *new_tail = new_head->prev;
				new_head->prev = NULL;
				new_tail->next = NULL;
				packets_to_process = g_queue_new();
				packets_to_process->head = packets->head;
				packets_to_process->tail = new_tail;
				packets_to_process->length = 400;
				packets->head = new_head;
				/* packets->tail is unchanged packets->tail没有改变 */
				packets->length = packets_len - 400;
			} else {
				packets_to_process = packets;
			}
			/* Get feedback packet count and increase it for next one
			获取反馈数据包计数并递增  */
			guint8 feedback_packet_count = stream->transport_wide_cc_feedback_count++;
			/* Create RTCP packet 创建RTCP包 */
			int len = janus_rtcp_transport_wide_cc_feedback(rtcpbuf, size,
				stream->video_ssrc, stream->video_ssrc_peer[0], feedback_packet_count, packets_to_process);
			/* Enqueue it, we'll send it later 入队，我们会稍后发送 */
			if(len > 0) {
				janus_plugin_rtcp rtcp = { .video = TRUE, .buffer = rtcpbuf, .length = len };
				janus_ice_relay_rtcp_internal(handle, &rtcp, FALSE);
			}
			if(packets_to_process != packets) {
				g_queue_free(packets_to_process);
			}
		}
		/* Free mem 释放一些资源 */
		g_queue_free(packets);
	}
	return G_SOURCE_CONTINUE;
}

/**
 * @brief 用于处理传出的RTCP数据
 * 
 * @param user_data 
 * @return gboolean 
 */
static gboolean janus_ice_outgoing_rtcp_handle(gpointer user_data) {
	janus_ice_handle *handle = (janus_ice_handle *)user_data;
	janus_ice_stream *stream = handle->stream;
	/* Audio */
	if(stream && stream->audio_send && stream->component && stream->component->out_stats.audio.packets > 0) {
		/* Create a SR/SDES compound */
		int srlen = 28;
		int sdeslen = 16;
		char rtcpbuf[sizeof(janus_rtcp_sr)+sdeslen];
		memset(rtcpbuf, 0, sizeof(rtcpbuf));
		rtcp_sr *sr = (rtcp_sr *)&rtcpbuf;
		sr->header.version = 2;
		sr->header.type = RTCP_SR;
		sr->header.rc = 0;
		sr->header.length = htons((srlen/4)-1);
		sr->ssrc = htonl(stream->audio_ssrc);
		struct timeval tv;
		gettimeofday(&tv, NULL);
		uint32_t s = tv.tv_sec + 2208988800u;
		uint32_t u = tv.tv_usec;
		uint32_t f = (u << 12) + (u << 8) - ((u * 3650) >> 6);
		sr->si.ntp_ts_msw = htonl(s);
		sr->si.ntp_ts_lsw = htonl(f);
		/* Compute an RTP timestamp coherent with the NTP one */
		rtcp_context *rtcp_ctx = stream->audio_rtcp_ctx;
		if(rtcp_ctx == NULL) {
			sr->si.rtp_ts = htonl(stream->audio_last_rtp_ts);	/* FIXME */
		} else {
			int64_t ntp = tv.tv_sec*G_USEC_PER_SEC + tv.tv_usec;
			uint32_t rtp_ts = ((ntp-stream->audio_last_ntp_ts)*(rtcp_ctx->tb))/1000000 + stream->audio_last_rtp_ts;
			sr->si.rtp_ts = htonl(rtp_ts);
		}
		sr->si.s_packets = htonl(stream->component->out_stats.audio.packets);
		sr->si.s_octets = htonl(stream->component->out_stats.audio.bytes);
		rtcp_sdes *sdes = (rtcp_sdes *)&rtcpbuf[srlen];
		janus_rtcp_sdes_cname((char *)sdes, sdeslen, "janus", 5);
		sdes->chunk.ssrc = htonl(stream->audio_ssrc);
		/* Enqueue it, we'll send it later */
		janus_plugin_rtcp rtcp = { .video = FALSE, .buffer = rtcpbuf, .length = srlen+sdeslen };
		janus_ice_relay_rtcp_internal(handle, &rtcp, FALSE);
		/* Check if we detected too many losses, and send a slowlink event in case */
		guint lost = janus_rtcp_context_get_lost_all(rtcp_ctx, TRUE);
		janus_slow_link_update(stream->component, handle, FALSE, TRUE, lost);
	}
	if(stream && stream->audio_recv) {
		/* Create a RR too */
		int rrlen = 32;
		char rtcpbuf[32];
		memset(rtcpbuf, 0, sizeof(rtcpbuf));
		rtcp_rr *rr = (rtcp_rr *)&rtcpbuf;
		rr->header.version = 2;
		rr->header.type = RTCP_RR;
		rr->header.rc = 1;
		rr->header.length = htons((rrlen/4)-1);
		rr->ssrc = htonl(stream->audio_ssrc);
		janus_rtcp_report_block(stream->audio_rtcp_ctx, &rr->rb[0]);
		rr->rb[0].ssrc = htonl(stream->audio_ssrc_peer);
		/* Enqueue it, we'll send it later */
		janus_plugin_rtcp rtcp = { .video = FALSE, .buffer = rtcpbuf, .length = 32 };
		janus_ice_relay_rtcp_internal(handle, &rtcp, FALSE);
		/* Check if we detected too many losses, and send a slowlink event in case */
		guint lost = janus_rtcp_context_get_lost_all(stream->audio_rtcp_ctx, FALSE);
		janus_slow_link_update(stream->component, handle, FALSE, FALSE, lost);
	}
	/* Now do the same for video */
	if(stream && stream->video_send && stream->component && stream->component->out_stats.video[0].packets > 0) {
		/* Create a SR/SDES compound */
		int srlen = 28;
		int sdeslen = 16;
		char rtcpbuf[sizeof(janus_rtcp_sr)+sdeslen];
		memset(rtcpbuf, 0, sizeof(rtcpbuf));
		rtcp_sr *sr = (rtcp_sr *)&rtcpbuf;
		sr->header.version = 2;
		sr->header.type = RTCP_SR;
		sr->header.rc = 0;
		sr->header.length = htons((srlen/4)-1);
		sr->ssrc = htonl(stream->video_ssrc);
		struct timeval tv;
		gettimeofday(&tv, NULL);
		uint32_t s = tv.tv_sec + 2208988800u;
		uint32_t u = tv.tv_usec;
		uint32_t f = (u << 12) + (u << 8) - ((u * 3650) >> 6);
		sr->si.ntp_ts_msw = htonl(s);
		sr->si.ntp_ts_lsw = htonl(f);
		/* Compute an RTP timestamp coherent with the NTP one */
		rtcp_context *rtcp_ctx = stream->video_rtcp_ctx[0];
		if(rtcp_ctx == NULL) {
			sr->si.rtp_ts = htonl(stream->video_last_rtp_ts);	/* FIXME */
		} else {
			int64_t ntp = tv.tv_sec*G_USEC_PER_SEC + tv.tv_usec;
			uint32_t rtp_ts = ((ntp-stream->video_last_ntp_ts)*(rtcp_ctx->tb))/1000000 + stream->video_last_rtp_ts;
			sr->si.rtp_ts = htonl(rtp_ts);
		}
		sr->si.s_packets = htonl(stream->component->out_stats.video[0].packets);
		sr->si.s_octets = htonl(stream->component->out_stats.video[0].bytes);
		rtcp_sdes *sdes = (rtcp_sdes *)&rtcpbuf[srlen];
		janus_rtcp_sdes_cname((char *)sdes, sdeslen, "janus", 5);
		sdes->chunk.ssrc = htonl(stream->video_ssrc);
		/* Enqueue it, we'll send it later */
		janus_plugin_rtcp rtcp = { .video = TRUE, .buffer = rtcpbuf, .length = srlen+sdeslen };
		janus_ice_relay_rtcp_internal(handle, &rtcp, FALSE);
		/* Check if we detected too many losses, and send a slowlink event in case */
		guint lost = janus_rtcp_context_get_lost_all(rtcp_ctx, TRUE);
		janus_slow_link_update(stream->component, handle, TRUE, TRUE, lost);
	}
	if(stream && stream->video_recv) {
		/* Create a RR too (for each SSRC, if we're simulcasting) */
		int vindex=0;
		for(vindex=0; vindex<3; vindex++) {
			if(stream->video_rtcp_ctx[vindex] && stream->video_rtcp_ctx[vindex]->rtp_recvd) {
				/* Create a RR */
				int rrlen = 32;
				char rtcpbuf[32];
				memset(rtcpbuf, 0, sizeof(rtcpbuf));
				rtcp_rr *rr = (rtcp_rr *)&rtcpbuf;
				rr->header.version = 2;
				rr->header.type = RTCP_RR;
				rr->header.rc = 1;
				rr->header.length = htons((rrlen/4)-1);
				rr->ssrc = htonl(stream->video_ssrc);
				janus_rtcp_report_block(stream->video_rtcp_ctx[vindex], &rr->rb[0]);
				rr->rb[0].ssrc = htonl(stream->video_ssrc_peer[vindex]);
				/* Enqueue it, we'll send it later */
				janus_plugin_rtcp rtcp = { .video = TRUE, .buffer = rtcpbuf, .length = 32 };
				janus_ice_relay_rtcp_internal(handle, &rtcp, FALSE);
			}
		}
		/* Check if we detected too many losses, and send a slowlink event in case */
		guint lost = janus_rtcp_context_get_lost_all(stream->video_rtcp_ctx[0], FALSE);
		janus_slow_link_update(stream->component, handle, TRUE, FALSE, lost);
	}
	if(twcc_period == 1000) {
		/* The Transport Wide CC feedback period is 1s as well, send it here
		Transport Wide CC 反馈周期也是1s，通过这里发送 */
		janus_ice_outgoing_transport_wide_cc_feedback(handle);
	}
	return G_SOURCE_CONTINUE;
}

/**
 * @brief 用于统计传出的数据
 * 
 * @param user_data 
 * @return gboolean 
 */
static gboolean janus_ice_outgoing_stats_handle(gpointer user_data) {
	janus_ice_handle *handle = (janus_ice_handle *)user_data;
	/* This callback is for stats and other things we need to do on a regular basis (typically called once per second) */
	janus_session *session = (janus_session *)handle->session;
	gint64 now = janus_get_monotonic_time();
	/* Reset the last second counters if too much time passed with no data in or out */
	janus_ice_stream *stream = handle->stream;
	if(stream == NULL || stream->component == NULL)
		return G_SOURCE_CONTINUE;
	janus_ice_component *component = stream->component;
	/* Audio */
	gint64 last = component->in_stats.audio.updated;
	if(last && now > last && now-last >= 2*G_USEC_PER_SEC && component->in_stats.audio.bytes_lastsec_temp > 0) {
		component->in_stats.audio.bytes_lastsec = 0;
		component->in_stats.audio.bytes_lastsec_temp = 0;
	}
	last = component->out_stats.audio.updated;
	if(last && now > last && now-last >= 2*G_USEC_PER_SEC && component->out_stats.audio.bytes_lastsec_temp > 0) {
		component->out_stats.audio.bytes_lastsec = 0;
		component->out_stats.audio.bytes_lastsec_temp = 0;
	}
	/* Video */
	int vindex = 0;
	for(vindex=0; vindex < 3; vindex++) {
		gint64 last = component->in_stats.video[vindex].updated;
		if(last && now > last && now-last >= 2*G_USEC_PER_SEC && component->in_stats.video[vindex].bytes_lastsec_temp > 0) {
			component->in_stats.video[vindex].bytes_lastsec = 0;
			component->in_stats.video[vindex].bytes_lastsec_temp = 0;
		}
		last = component->out_stats.video[vindex].updated;
		if(last && now > last && now-last >= 2*G_USEC_PER_SEC && component->out_stats.video[vindex].bytes_lastsec_temp > 0) {
			component->out_stats.video[vindex].bytes_lastsec = 0;
			component->out_stats.video[vindex].bytes_lastsec_temp = 0;
		}
	}
	/* Now let's see if we need to notify the user about no incoming audio or video */
	if(no_media_timer > 0 && component->dtls && component->dtls->dtls_connected > 0 && (now - component->dtls->dtls_connected >= G_USEC_PER_SEC)) {
		/* Audio */
		gint64 last = component->in_stats.audio.updated;
		if(!component->in_stats.audio.notified_lastsec && last &&
				!component->in_stats.audio.bytes_lastsec && !component->in_stats.audio.bytes_lastsec_temp &&
					now-last >= (gint64)no_media_timer*G_USEC_PER_SEC) {
			/* We missed more than no_second_timer seconds of audio! */
			component->in_stats.audio.notified_lastsec = TRUE;
			JANUS_LOG(LOG_WARN, "[%"SCNu64"] Didn't receive audio for more than %d seconds...\n", handle->handle_id, no_media_timer);
			janus_ice_notify_media(handle, FALSE, 0, FALSE);
		}
		/* Video */
		int vindex=0;
		for(vindex=0; vindex<3; vindex++) {
			last = component->in_stats.video[vindex].updated;
			if(!component->in_stats.video[vindex].notified_lastsec && last &&
					!component->in_stats.video[vindex].bytes_lastsec && !component->in_stats.video[vindex].bytes_lastsec_temp &&
						now-last >= (gint64)no_media_timer*G_USEC_PER_SEC) {
				/* We missed more than no_second_timer seconds of this video stream! */
				component->in_stats.video[vindex].notified_lastsec = TRUE;
				JANUS_LOG(LOG_WARN, "[%"SCNu64"] Didn't receive video #%d for more than a second...\n", handle->handle_id, vindex);
				janus_ice_notify_media(handle, TRUE, vindex, FALSE);
			}
		}
	}
	/* We also send live stats to event handlers every tot-seconds (configurable) */
	handle->last_event_stats++;
	if(janus_ice_event_stats_period > 0 && handle->last_event_stats >= janus_ice_event_stats_period) {
		handle->last_event_stats = 0;
		json_t *combined_event = NULL;
		/* Shall janus send dedicated events per media or one per peerConnection */
		if(janus_events_is_enabled() && janus_ice_event_get_combine_media_stats())
			combined_event = json_array();
		/* Audio */
		if(janus_events_is_enabled() && janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_AUDIO)) {
			if(stream && stream->audio_rtcp_ctx) {
				json_t *info = json_object();
				json_object_set_new(info, "media", json_string("audio"));
				json_object_set_new(info, "base", json_integer(stream->audio_rtcp_ctx->tb));
				json_object_set_new(info, "rtt", json_integer(janus_rtcp_context_get_rtt(stream->audio_rtcp_ctx)));
				json_object_set_new(info, "lost", json_integer(janus_rtcp_context_get_lost_all(stream->audio_rtcp_ctx, FALSE)));
				json_object_set_new(info, "lost-by-remote", json_integer(janus_rtcp_context_get_lost_all(stream->audio_rtcp_ctx, TRUE)));
				json_object_set_new(info, "jitter-local", json_integer(janus_rtcp_context_get_jitter(stream->audio_rtcp_ctx, FALSE)));
				json_object_set_new(info, "jitter-remote", json_integer(janus_rtcp_context_get_jitter(stream->audio_rtcp_ctx, TRUE)));
				json_object_set_new(info, "in-link-quality", json_integer(janus_rtcp_context_get_in_link_quality(stream->audio_rtcp_ctx)));
				json_object_set_new(info, "in-media-link-quality", json_integer(janus_rtcp_context_get_in_media_link_quality(stream->audio_rtcp_ctx)));
				json_object_set_new(info, "out-link-quality", json_integer(janus_rtcp_context_get_out_link_quality(stream->audio_rtcp_ctx)));
				json_object_set_new(info, "out-media-link-quality", json_integer(janus_rtcp_context_get_out_media_link_quality(stream->audio_rtcp_ctx)));
				if(stream->component) {
					json_object_set_new(info, "packets-received", json_integer(stream->component->in_stats.audio.packets));
					json_object_set_new(info, "packets-sent", json_integer(stream->component->out_stats.audio.packets));
					json_object_set_new(info, "bytes-received", json_integer(stream->component->in_stats.audio.bytes));
					json_object_set_new(info, "bytes-sent", json_integer(stream->component->out_stats.audio.bytes));
					json_object_set_new(info, "bytes-received-lastsec", json_integer(stream->component->in_stats.audio.bytes_lastsec));
					json_object_set_new(info, "bytes-sent-lastsec", json_integer(stream->component->out_stats.audio.bytes_lastsec));
					json_object_set_new(info, "nacks-received", json_integer(stream->component->in_stats.audio.nacks));
					json_object_set_new(info, "nacks-sent", json_integer(stream->component->out_stats.audio.nacks));
					json_object_set_new(info, "retransmissions-received", json_integer(stream->audio_rtcp_ctx->retransmitted));
				}
				if(combined_event != NULL) {
					json_array_append_new(combined_event, info);
				} else {
					janus_events_notify_handlers(JANUS_EVENT_TYPE_MEDIA, JANUS_EVENT_SUBTYPE_MEDIA_STATS,
						session->session_id, handle->handle_id, handle->opaque_id, info);
				}
			}
		}
		/* Do the same for video */
		if(janus_events_is_enabled() && janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_VIDEO)) {
			int vindex=0;
			for(vindex=0; vindex<3; vindex++) {
				if(stream && stream->video_rtcp_ctx[vindex]) {
					json_t *info = json_object();
					if(vindex == 0)
						json_object_set_new(info, "media", json_string("video"));
					else if(vindex == 1)
						json_object_set_new(info, "media", json_string("video-sim1"));
					else
						json_object_set_new(info, "media", json_string("video-sim2"));
					json_object_set_new(info, "base", json_integer(stream->video_rtcp_ctx[vindex]->tb));
					if(vindex == 0)
						json_object_set_new(info, "rtt", json_integer(janus_rtcp_context_get_rtt(stream->video_rtcp_ctx[vindex])));
					json_object_set_new(info, "lost", json_integer(janus_rtcp_context_get_lost_all(stream->video_rtcp_ctx[vindex], FALSE)));
					json_object_set_new(info, "lost-by-remote", json_integer(janus_rtcp_context_get_lost_all(stream->video_rtcp_ctx[vindex], TRUE)));
					json_object_set_new(info, "jitter-local", json_integer(janus_rtcp_context_get_jitter(stream->video_rtcp_ctx[vindex], FALSE)));
					json_object_set_new(info, "jitter-remote", json_integer(janus_rtcp_context_get_jitter(stream->video_rtcp_ctx[vindex], TRUE)));
					json_object_set_new(info, "in-link-quality", json_integer(janus_rtcp_context_get_in_link_quality(stream->video_rtcp_ctx[vindex])));
					json_object_set_new(info, "in-media-link-quality", json_integer(janus_rtcp_context_get_in_media_link_quality(stream->video_rtcp_ctx[vindex])));
					json_object_set_new(info, "out-link-quality", json_integer(janus_rtcp_context_get_out_link_quality(stream->video_rtcp_ctx[vindex])));
					json_object_set_new(info, "out-media-link-quality", json_integer(janus_rtcp_context_get_out_media_link_quality(stream->video_rtcp_ctx[vindex])));
					if(vindex == 0 && stream->remb_bitrate > 0)
						json_object_set_new(info, "remb-bitrate", json_integer(stream->remb_bitrate));
					if(stream->component) {
						json_object_set_new(info, "packets-received", json_integer(stream->component->in_stats.video[vindex].packets));
						json_object_set_new(info, "packets-sent", json_integer(stream->component->out_stats.video[vindex].packets));
						json_object_set_new(info, "bytes-received", json_integer(stream->component->in_stats.video[vindex].bytes));
						json_object_set_new(info, "bytes-sent", json_integer(stream->component->out_stats.video[vindex].bytes));
						json_object_set_new(info, "bytes-received-lastsec", json_integer(stream->component->in_stats.video[vindex].bytes_lastsec));
						json_object_set_new(info, "bytes-sent-lastsec", json_integer(stream->component->out_stats.video[vindex].bytes_lastsec));
						json_object_set_new(info, "nacks-received", json_integer(stream->component->in_stats.video[vindex].nacks));
						json_object_set_new(info, "nacks-sent", json_integer(stream->component->out_stats.video[vindex].nacks));
						json_object_set_new(info, "retransmissions-received", json_integer(stream->video_rtcp_ctx[vindex]->retransmitted));
					}
					if(combined_event) {
						json_array_append_new(combined_event, info);
					} else {
						janus_events_notify_handlers(JANUS_EVENT_TYPE_MEDIA, JANUS_EVENT_SUBTYPE_MEDIA_STATS,
							session->session_id, handle->handle_id, handle->opaque_id, info);
					}
				}
			}
			if(combined_event) {
				janus_events_notify_handlers(JANUS_EVENT_TYPE_MEDIA, JANUS_EVENT_SUBTYPE_MEDIA_STATS,
					session->session_id, handle->handle_id, handle->opaque_id, combined_event);
			}
		}
	}
	/* Should we clean up old NACK buffers for any of the streams? */
	janus_cleanup_nack_buffer(now, handle->stream, TRUE, TRUE);
	/* Check if we should also print a summary of SRTP-related errors */
	handle->last_srtp_summary++;
	if(handle->last_srtp_summary == 0 || handle->last_srtp_summary == 2) {
		if(handle->srtp_errors_count > 0) {
			JANUS_LOG(LOG_ERR, "[%"SCNu64"] Got %d SRTP/SRTCP errors in the last few seconds (last error: %s)\n",
				handle->handle_id, handle->srtp_errors_count, janus_srtp_error_str(handle->last_srtp_error));
			handle->srtp_errors_count = 0;
			handle->last_srtp_error = 0;
		}
		handle->last_srtp_summary = 0;
	}
	return G_SOURCE_CONTINUE;
}

/**
 * @brief 用于传出的流量处理
 * 
 * @param handle 
 * @param pkt 
 * @return gboolean 
 */
static gboolean janus_ice_outgoing_traffic_handle(janus_ice_handle *handle, janus_ice_queued_packet *pkt) {
	janus_session *session = (janus_session *)handle->session;
	janus_ice_stream *stream = handle->stream;
	janus_ice_component *component = stream ? stream->component : NULL;
	if(pkt == &janus_ice_start_gathering) {
		/* Start gathering candidates 开始收集candidtae*/
		if(handle->agent == NULL) {
			JANUS_LOG(LOG_WARN, "[%"SCNu64"] No ICE agent, not going to gather candidates...\n", handle->handle_id);
		} else if(!nice_agent_gather_candidates(handle->agent, handle->stream_id)) {
			JANUS_LOG(LOG_ERR, "[%"SCNu64"] Error gathering candidates...\n", handle->handle_id);
			janus_ice_webrtc_hangup(handle, "ICE gathering error");
		}
		return G_SOURCE_CONTINUE;
	} else if(pkt == &janus_ice_add_candidates) {
		/* There are remote candidates pending, add them now 有一些远端的candidate等待被添加，现在可以进行添加*/
		GSList *candidates = NULL;
		NiceCandidate *c = NULL;
		while((c = g_async_queue_try_pop(handle->queued_candidates)) != NULL) {
			JANUS_LOG(LOG_VERB, "[%"SCNu64"] Processing candidate %p\n", handle->handle_id, c);
			candidates = g_slist_append(candidates, c);
		}
		guint count = g_slist_length(candidates);
		if(stream != NULL && component != NULL && count > 0) {
			int added = nice_agent_set_remote_candidates(handle->agent, stream->stream_id, component->component_id, candidates);
			if(added < 0 || (guint)added != count) {
				JANUS_LOG(LOG_WARN, "[%"SCNu64"] Failed to add some remote candidates (added %u, expected %u)\n",
					handle->handle_id, added, count);
			} else {
				JANUS_LOG(LOG_VERB, "[%"SCNu64"] %d remote %s added\n", handle->handle_id,
					count, (count > 1 ? "candidates" : "candidate"));
			}
		}
		g_slist_free(candidates);
		return G_SOURCE_CONTINUE;
	} else if(pkt == &janus_ice_dtls_handshake) {
		if(!janus_is_webrtc_encryption_enabled()) {
			JANUS_LOG(LOG_WARN, "[%"SCNu64"] WebRTC encryption disabled, skipping DTLS handshake\n", handle->handle_id);
			janus_ice_dtls_handshake_done(handle, component);
			return G_SOURCE_CONTINUE;
		} else if(!component) {
			JANUS_LOG(LOG_WARN, "[%"SCNu64"] ICE component not initialized, aborting DTLS handshake\n", handle->handle_id);
			return G_SOURCE_CONTINUE;
		}
		/* Start the DTLS handshake 开始DTLS握手*/
		janus_dtls_srtp_handshake(component->dtls);
		/* Create retransmission timer 创建重传定时器*/
		component->dtlsrt_source = g_timeout_source_new(50);
		g_source_set_callback(component->dtlsrt_source, janus_dtls_retry, component->dtls, NULL);
		guint id = g_source_attach(component->dtlsrt_source, handle->mainctx);
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] Creating retransmission timer with ID %u\n", handle->handle_id, id);
		return G_SOURCE_CONTINUE;
	} else if(pkt == &janus_ice_media_stopped) {
		/* Either audio or video has been disabled on the way in, so use the callback to notify the peer 
		音频或视频在进入的过程中已禁用，因此使用回调通知对端 */
		if(component && stream && !component->in_stats.audio.notified_lastsec && component->in_stats.audio.bytes && !stream->audio_send) {
			/* Audio won't be received for a while, notify */
			component->in_stats.audio.notified_lastsec = TRUE;
			janus_ice_notify_media(handle, FALSE, 0, FALSE);
		}
		int vindex=0;
		for(vindex=0; vindex<3; vindex++) {
			if(component && stream && !component->in_stats.video[vindex].notified_lastsec && component->in_stats.video[vindex].bytes && !stream->video_recv) {
				/* Video won't be received for a while, notify */
				component->in_stats.video[vindex].notified_lastsec = TRUE;
				janus_ice_notify_media(handle, TRUE, vindex, FALSE);
			}
		}
		return G_SOURCE_CONTINUE;
	} else if(pkt == &janus_ice_hangup_peerconnection) {
		/* The media session is over, send an alert on all streams and components */
		if(handle->stream && handle->stream->component && janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_READY)) {
			janus_dtls_srtp_send_alert(handle->stream->component->dtls);
		}
		/* Notify the plugin about the fact this PeerConnection has just gone */
		janus_plugin *plugin = (janus_plugin *)handle->app;
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] Telling the plugin about the hangup (%s)\n",
			handle->handle_id, plugin ? plugin->get_name() : "??");
		if(plugin != NULL && handle->app_handle != NULL) {
			plugin->hangup_media(handle->app_handle);
		}
		/* Get rid of the attached sources */
		if(handle->rtcp_source) {
			g_source_destroy(handle->rtcp_source);
			g_source_unref(handle->rtcp_source);
			handle->rtcp_source = NULL;
		}
		if(handle->twcc_source) {
			g_source_destroy(handle->twcc_source);
			g_source_unref(handle->twcc_source);
			handle->twcc_source = NULL;
		}
		if(handle->stats_source) {
			g_source_destroy(handle->stats_source);
			g_source_unref(handle->stats_source);
			handle->stats_source = NULL;
		}
		/* If event handlers are active, send stats one last time */
		if(janus_events_is_enabled()) {
			handle->last_event_stats = janus_ice_event_stats_period;
			(void)janus_ice_outgoing_stats_handle(handle);
		}
		janus_ice_webrtc_free(handle);
		return G_SOURCE_CONTINUE;
	} else if(pkt == &janus_ice_detach_handle) {
		/* This handle has just been detached, notify the plugin 
		此 handle 刚刚分离，通知插件
		*/
		janus_plugin *plugin = (janus_plugin *)handle->app;
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] Telling the plugin about the handle detach (%s)\n",
			handle->handle_id, plugin ? plugin->get_name() : "??");
		if(plugin != NULL && handle->app_handle != NULL) {
			int error = 0;
			plugin->destroy_session(handle->app_handle, &error);
		}
		handle->app_handle = NULL;
		/* TODO Get rid of the loop by removing the source */
		if(handle->rtp_source) {
			g_source_destroy(handle->rtp_source);
			g_source_unref(handle->rtp_source);
			handle->rtp_source = NULL;
		}
		/* Prepare JSON event to notify user/application */
		json_t *event = json_object();
		json_object_set_new(event, "janus", json_string("detached"));
		json_object_set_new(event, "session_id", json_integer(session->session_id));
		json_object_set_new(event, "sender", json_integer(handle->handle_id));
		if(opaqueid_in_api && handle->opaque_id != NULL)
			json_object_set_new(event, "opaque_id", json_string(handle->opaque_id));
		/* Send the event */
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] Sending event to transport...; %p\n", handle->handle_id, handle);
		janus_session_notify_event(session, event);
		/* Notify event handlers as well */
		if(janus_events_is_enabled())
			janus_events_notify_handlers(JANUS_EVENT_TYPE_HANDLE, JANUS_EVENT_SUBTYPE_NONE,
				session->session_id, handle->handle_id, "detached",
				plugin ? plugin->get_package() : NULL, handle->opaque_id, handle->token);
		return G_SOURCE_REMOVE;
	} else if(pkt == &janus_ice_data_ready) {
		/* Data is writable on this PeerConnection, notify the plugin */
		janus_plugin *plugin = (janus_plugin *)handle->app;
		if(plugin != NULL && plugin->data_ready != NULL && handle->app_handle != NULL) {
			JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Telling the plugin about the data channel being ready (%s)\n",
				handle->handle_id, plugin ? plugin->get_name() : "??");
			plugin->data_ready(handle->app_handle);
		}
	}
	if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_READY)) {
		janus_ice_free_queued_packet(pkt);
		return G_SOURCE_CONTINUE;
	}
	/* Now let's get on with the packet */
	if(pkt == NULL)
		return G_SOURCE_CONTINUE;
	if(pkt->data == NULL || stream == NULL) {
		janus_ice_free_queued_packet(pkt);
		return G_SOURCE_CONTINUE;
	}
	gint64 age = (janus_get_monotonic_time() - pkt->added);
	if(age > G_USEC_PER_SEC) {
		JANUS_LOG(LOG_WARN, "[%"SCNu64"] Discarding too old outgoing packet (age=%"SCNi64"us)\n", handle->handle_id, age);
		janus_ice_free_queued_packet(pkt);
		return G_SOURCE_CONTINUE;
	}
	if(!stream->cdone) {
		if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT) && !stream->noerrorlog) {
			JANUS_LOG(LOG_ERR, "[%"SCNu64"] No candidates not gathered yet for stream??\n", handle->handle_id);
			stream->noerrorlog = TRUE;	/* Don't flood with the same error all over again */
		}
		janus_ice_free_queued_packet(pkt);
		return G_SOURCE_CONTINUE;
	}
	if(pkt->control) {
		/* RTCP */
		int video = (pkt->type == JANUS_ICE_PACKET_VIDEO);
		stream->noerrorlog = FALSE;
		if(janus_is_webrtc_encryption_enabled() && (!component->dtls || !component->dtls->srtp_valid || !component->dtls->srtp_out)) {
			if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT) && !component->noerrorlog) {
				JANUS_LOG(LOG_WARN, "[%"SCNu64"] %s stream (#%u) component has no valid SRTP session (yet?)\n",
					handle->handle_id, video ? "video" : "audio", stream->stream_id);
				component->noerrorlog = TRUE;	/* Don't flood with the same error all over again */
			}
			janus_ice_free_queued_packet(pkt);
			return G_SOURCE_CONTINUE;
		}
		component->noerrorlog = FALSE;
		if(pkt->encrypted) {
			/* Already SRTCP */
			int sent = nice_agent_send(handle->agent, stream->stream_id, component->component_id, pkt->length, (const gchar *)pkt->data);
			if(sent < pkt->length) {
				JANUS_LOG(LOG_ERR, "[%"SCNu64"] ... only sent %d bytes? (was %d)\n", handle->handle_id, sent, pkt->length);
			}
		} else {
			/* Check if there's anything we need to do before sending */
			uint32_t bitrate = janus_rtcp_get_remb(pkt->data, pkt->length);
			if(bitrate > 0) {
				/* There's a REMB, prepend a RR as it won't work otherwise */
				int rrlen = 8;
				char *rtcpbuf = g_malloc0(rrlen+pkt->length+SRTP_MAX_TAG_LEN+4);
				rtcp_rr *rr = (rtcp_rr *)rtcpbuf;
				rr->header.version = 2;
				rr->header.type = RTCP_RR;
				rr->header.rc = 0;
				rr->header.length = htons((rrlen/4)-1);
				janus_ice_stream *stream = handle->stream;
				/* Append REMB */
				memcpy(rtcpbuf+rrlen, pkt->data, pkt->length);
				/* If we're simulcasting, set the extra SSRCs (the first one will be set by janus_rtcp_fix_ssrc) */
				if(stream->video_ssrc_peer[1] && pkt->length >= 28) {
					rtcp_fb *rtcpfb = (rtcp_fb *)(rtcpbuf+rrlen);
					rtcp_remb *remb = (rtcp_remb *)rtcpfb->fci;
					remb->ssrc[1] = htonl(stream->video_ssrc_peer[1]);
					if(stream->video_ssrc_peer[2] && pkt->length >= 32) {
						remb->ssrc[2] = htonl(stream->video_ssrc_peer[2]);
					}
				}
				/* Free old packet and update */
				char *prev_data = pkt->data;
				pkt->data = rtcpbuf;
				pkt->length = rrlen+pkt->length;
				g_clear_pointer(&prev_data, g_free);
			}
			/* Do we need to dump this packet for debugging? */
			if(g_atomic_int_get(&handle->dump_packets))
				janus_text2pcap_dump(handle->text2pcap, JANUS_TEXT2PCAP_RTCP, FALSE, pkt->data, pkt->length,
					"[session=%"SCNu64"][handle=%"SCNu64"]", session->session_id, handle->handle_id);
			/* Encrypt SRTCP */
			int protected = pkt->length;
			int res = janus_is_webrtc_encryption_enabled() ?
				srtp_protect_rtcp(component->dtls->srtp_out, pkt->data, &protected) : srtp_err_status_ok;
			if(res != srtp_err_status_ok) {
				/* We don't spam the logs for every SRTP error: just take note of this, and print a summary later */
				handle->srtp_errors_count++;
				handle->last_srtp_error = res;
				/* If we're debugging, though, print every occurrence */
				JANUS_LOG(LOG_DBG, "[%"SCNu64"] ... SRTCP protect error... %s (len=%d-->%d)...\n", handle->handle_id, janus_srtp_error_str(res), pkt->length, protected);
			} else {
				/* Shoot! */
				int sent = nice_agent_send(handle->agent, stream->stream_id, component->component_id, protected, pkt->data);
				if(sent < protected) {
					JANUS_LOG(LOG_ERR, "[%"SCNu64"] ... only sent %d bytes? (was %d)\n", handle->handle_id, sent, protected);
				}
			}
		}
		janus_ice_free_queued_packet(pkt);
	} else {
		/* RTP or data */
		if(pkt->type == JANUS_ICE_PACKET_AUDIO || pkt->type == JANUS_ICE_PACKET_VIDEO) {
			/* RTP */
			int video = (pkt->type == JANUS_ICE_PACKET_VIDEO);
			if((!video && !stream->audio_send) || (video && !stream->video_send)) {
				janus_ice_free_queued_packet(pkt);
				return G_SOURCE_CONTINUE;
			}
			if(janus_is_webrtc_encryption_enabled() && (!component->dtls || !component->dtls->srtp_valid || !component->dtls->srtp_out)) {
				if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT) && !component->noerrorlog) {
					JANUS_LOG(LOG_WARN, "[%"SCNu64"] %s stream component has no valid SRTP session (yet?)\n",
						handle->handle_id, video ? "video" : "audio");
					component->noerrorlog = TRUE;	/* Don't flood with the same error all over again */
				}
				janus_ice_free_queued_packet(pkt);
				return G_SOURCE_CONTINUE;
			}
			component->noerrorlog = FALSE;
			if(pkt->encrypted) {
				/* Already RTP (probably a retransmission?) */
				janus_rtp_header *header = (janus_rtp_header *)pkt->data;
				JANUS_LOG(LOG_HUGE, "[%"SCNu64"] ... Retransmitting seq.nr %"SCNu16"\n\n", handle->handle_id, ntohs(header->seq_number));
				int sent = nice_agent_send(handle->agent, stream->stream_id, component->component_id, pkt->length, (const gchar *)pkt->data);
				if(sent < pkt->length) {
					JANUS_LOG(LOG_ERR, "[%"SCNu64"] ... only sent %d bytes? (was %d)\n", handle->handle_id, sent, pkt->length);
				}
			} else {
				/* Overwrite SSRC */
				janus_rtp_header *header = (janus_rtp_header *)pkt->data;
				if(!pkt->retransmission) {
					/* ... but only if this isn't a retransmission (for those we already set it before) */
					header->ssrc = htonl(video ? stream->video_ssrc : stream->audio_ssrc);
				}
				/* Set the abs-send-time value, if needed */
				if(video && stream->abs_send_time_ext_id > 0) {
					int64_t now = (((janus_get_monotonic_time()/1000) << 18) + 500) / 1000;
					uint32_t abs_ts = (uint32_t)now & 0x00FFFFFF;
					if(janus_rtp_header_extension_set_abs_send_time(pkt->data, pkt->length,
							stream->abs_send_time_ext_id, abs_ts) < 0) {
						JANUS_LOG(LOG_ERR, "[%"SCNu64"] Error setting abs-send-time value...\n", handle->handle_id);
					}
				}
				/* Set the transport-wide sequence number, if needed */
				if(video && stream->transport_wide_cc_ext_id > 0) {
					stream->transport_wide_cc_out_seq_num++;
					if(janus_rtp_header_extension_set_transport_wide_cc(pkt->data, pkt->length,
							stream->transport_wide_cc_ext_id, stream->transport_wide_cc_out_seq_num) < 0) {
						JANUS_LOG(LOG_ERR, "[%"SCNu64"] Error setting transport wide CC sequence number...\n", handle->handle_id);
					}
				}
				/* Keep track of payload types too */
				if(!video && stream->audio_payload_type < 0) {
					stream->audio_payload_type = header->type;
					if(stream->audio_codec == NULL) {
						const char *codec = janus_get_codec_from_pt(handle->local_sdp, stream->audio_payload_type);
						if(codec != NULL)
							stream->audio_codec = g_strdup(codec);
					}
				} else if(video && stream->video_payload_type < 0) {
					stream->video_payload_type = header->type;
					if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RFC4588_RTX) &&
							stream->rtx_payload_types && g_hash_table_size(stream->rtx_payload_types) > 0) {
						stream->video_rtx_payload_type = GPOINTER_TO_INT(g_hash_table_lookup(stream->rtx_payload_types, GINT_TO_POINTER(stream->video_payload_type)));
						JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Retransmissions will have payload type %d\n",
							handle->handle_id, stream->video_rtx_payload_type);
					}
					if(stream->video_codec == NULL) {
						const char *codec = janus_get_codec_from_pt(handle->local_sdp, stream->video_payload_type);
						if(codec != NULL)
							stream->video_codec = g_strdup(codec);
					}
					if(stream->video_is_keyframe == NULL && stream->video_codec != NULL) {
						if(!strcasecmp(stream->video_codec, "vp8"))
							stream->video_is_keyframe = &janus_vp8_is_keyframe;
						else if(!strcasecmp(stream->video_codec, "vp9"))
							stream->video_is_keyframe = &janus_vp9_is_keyframe;
						else if(!strcasecmp(stream->video_codec, "h264"))
							stream->video_is_keyframe = &janus_h264_is_keyframe;
						else if(!strcasecmp(stream->video_codec, "av1"))
							stream->video_is_keyframe = &janus_av1_is_keyframe;
						else if(!strcasecmp(stream->video_codec, "h265"))
							stream->video_is_keyframe = &janus_h265_is_keyframe;
					}
				}
				/* Do we need to dump this packet for debugging? */
				if(g_atomic_int_get(&handle->dump_packets))
					janus_text2pcap_dump(handle->text2pcap, JANUS_TEXT2PCAP_RTP, FALSE, pkt->data, pkt->length,
						"[session=%"SCNu64"][handle=%"SCNu64"]", session->session_id, handle->handle_id);
				/* If this is video and NACK optimizations are enabled, check if this is
				 * a keyframe: if so, we empty our retransmit buffer for incoming NACKs */
				if(video && nack_optimizations && stream->video_is_keyframe) {
					int plen = 0;
					char *payload = janus_rtp_payload(pkt->data, pkt->length, &plen);
					if(stream->video_is_keyframe(payload, plen)) {
						JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Keyframe sent, cleaning retransmit buffer\n", handle->handle_id);
						janus_cleanup_nack_buffer(0, stream, FALSE, TRUE);
					}
				}
				/* Before encrypting, check if we need to copy the unencrypted payload (e.g., for rtx/90000) */
				janus_rtp_packet *p = NULL;
				if(stream->nack_queue_ms > 0 && !pkt->retransmission && pkt->type == JANUS_ICE_PACKET_VIDEO && component->do_video_nacks &&
						janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_RFC4588_RTX)) {
					/* Save the packet for retransmissions that may be needed later: start by
					 * making room for two more bytes to store the original sequence number */
					p = g_malloc(sizeof(janus_rtp_packet));
					janus_rtp_header *header = (janus_rtp_header *)pkt->data;
					guint16 original_seq = header->seq_number;
					p->data = g_malloc(pkt->length+2);
					p->length = pkt->length+2;
					/* Check where the payload starts */
					int plen = 0;
					char *payload = janus_rtp_payload(pkt->data, pkt->length, &plen);
					if(plen == 0) {
						JANUS_LOG(LOG_WARN, "[%"SCNu64"] Discarding outgoing empty RTP packet\n", handle->handle_id);
						janus_ice_free_rtp_packet(p);
						janus_ice_free_queued_packet(pkt);
						return G_SOURCE_CONTINUE;
					}
					size_t hsize = payload - pkt->data;
					/* Copy the header first */
					memcpy(p->data, pkt->data, hsize);
					/* Copy the original sequence number */
					memcpy(p->data+hsize, &original_seq, 2);
					/* Copy the payload */
					memcpy(p->data+hsize+2, payload, pkt->length - hsize);
				}
				/* Encrypt SRTP */
				int protected = pkt->length;
				int res = janus_is_webrtc_encryption_enabled() ?
					srtp_protect(component->dtls->srtp_out, pkt->data, &protected) : srtp_err_status_ok;
				if(res != srtp_err_status_ok) {
					/* We don't spam the logs for every SRTP error: just take note of this, and print a summary later */
					handle->srtp_errors_count++;
					handle->last_srtp_error = res;
					/* If we're debugging, though, print every occurrence */
					janus_rtp_header *header = (janus_rtp_header *)pkt->data;
					guint32 timestamp = ntohl(header->timestamp);
					guint16 seq = ntohs(header->seq_number);
					JANUS_LOG(LOG_DBG, "[%"SCNu64"] ... SRTP protect error... %s (len=%d-->%d, ts=%"SCNu32", seq=%"SCNu16")...\n",
						handle->handle_id, janus_srtp_error_str(res), pkt->length, protected, timestamp, seq);
					janus_ice_free_rtp_packet(p);
				} else {
					/* Shoot! */
					int sent = nice_agent_send(handle->agent, stream->stream_id, component->component_id, protected, pkt->data);
					if(sent < protected) {
						JANUS_LOG(LOG_ERR, "[%"SCNu64"] ... only sent %d bytes? (was %d)\n", handle->handle_id, sent, protected);
					}
					/* Update stats */
					if(sent > 0) {
						/* Update the RTCP context as well */
						janus_rtp_header *header = (janus_rtp_header *)pkt->data;
						guint32 timestamp = ntohl(header->timestamp);
						if(pkt->type == JANUS_ICE_PACKET_AUDIO) {
							component->out_stats.audio.packets++;
							component->out_stats.audio.bytes += pkt->length;
							/* Last second outgoing audio */
							gint64 now = janus_get_monotonic_time();
							if(component->out_stats.audio.updated == 0)
								component->out_stats.audio.updated = now;
							if(now > component->out_stats.audio.updated &&
									now - component->out_stats.audio.updated >= G_USEC_PER_SEC) {
								component->out_stats.audio.bytes_lastsec = component->out_stats.audio.bytes_lastsec_temp;
								component->out_stats.audio.bytes_lastsec_temp = 0;
								component->out_stats.audio.updated = now;
							}
							component->out_stats.audio.bytes_lastsec_temp += pkt->length;
							struct timeval tv;
							gettimeofday(&tv, NULL);
							if(stream->audio_last_ntp_ts == 0 || (gint32)(timestamp - stream->audio_last_rtp_ts) > 0) {
								stream->audio_last_ntp_ts = (gint64)tv.tv_sec*G_USEC_PER_SEC + tv.tv_usec;
								stream->audio_last_rtp_ts = timestamp;
							}
							if(stream->audio_first_ntp_ts == 0) {
								stream->audio_first_ntp_ts = (gint64)tv.tv_sec*G_USEC_PER_SEC + tv.tv_usec;
								stream->audio_first_rtp_ts = timestamp;
							}
							/* Let's check if this is not Opus: in case we may need to change the timestamp base */
							rtcp_context *rtcp_ctx = stream->audio_rtcp_ctx;
							int pt = header->type;
							uint32_t clock_rate = stream->clock_rates ?
								GPOINTER_TO_UINT(g_hash_table_lookup(stream->clock_rates, GINT_TO_POINTER(pt))) : 48000;
							if(rtcp_ctx->tb != clock_rate)
								rtcp_ctx->tb = clock_rate;
						} else if(pkt->type == JANUS_ICE_PACKET_VIDEO) {
							component->out_stats.video[0].packets++;
							component->out_stats.video[0].bytes += pkt->length;
							/* Last second outgoing video */
							gint64 now = janus_get_monotonic_time();
							if(component->out_stats.video[0].updated == 0)
								component->out_stats.video[0].updated = now;
							if(now > component->out_stats.video[0].updated &&
									now - component->out_stats.video[0].updated >= G_USEC_PER_SEC) {
								component->out_stats.video[0].bytes_lastsec = component->out_stats.video[0].bytes_lastsec_temp;
								component->out_stats.video[0].bytes_lastsec_temp = 0;
								component->out_stats.video[0].updated = now;
							}
							component->out_stats.video[0].bytes_lastsec_temp += pkt->length;
							struct timeval tv;
							gettimeofday(&tv, NULL);
							if(stream->video_last_ntp_ts == 0 || (gint32)(timestamp - stream->video_last_rtp_ts) > 0) {
								stream->video_last_ntp_ts = (gint64)tv.tv_sec*G_USEC_PER_SEC + tv.tv_usec;
								stream->video_last_rtp_ts = timestamp;
							}
							if(stream->video_first_ntp_ts[0] == 0) {
								stream->video_first_ntp_ts[0] = (gint64)tv.tv_sec*G_USEC_PER_SEC + tv.tv_usec;
								stream->video_first_rtp_ts[0] = timestamp;
							}
						}
						/* Update sent packets counter */
						rtcp_context *rtcp_ctx = video ? stream->video_rtcp_ctx[0] : stream->audio_rtcp_ctx;
						if(rtcp_ctx)
							g_atomic_int_inc(&rtcp_ctx->sent_packets_since_last_rr);
					}
					if(stream->nack_queue_ms > 0 && !pkt->retransmission) {
						/* Save the packet for retransmissions that may be needed later */
						if((pkt->type == JANUS_ICE_PACKET_AUDIO && !component->do_audio_nacks) ||
								(pkt->type == JANUS_ICE_PACKET_VIDEO && !component->do_video_nacks)) {
							/* ... unless NACKs are disabled for this medium */
							janus_ice_free_queued_packet(pkt);
							return G_SOURCE_CONTINUE;
						}
						if(p == NULL) {
							/* If we're not doing RFC4588, we're saving the SRTP packet as it is */
							p = g_malloc(sizeof(janus_rtp_packet));
							p->data = g_malloc(protected);
							memcpy(p->data, pkt->data, protected);
							p->length = protected;
						}
						p->created = janus_get_monotonic_time();
						p->last_retransmit = 0;
						janus_rtp_header *header = (janus_rtp_header *)pkt->data;
						guint16 seq = ntohs(header->seq_number);
						if(!video) {
							if(component->audio_retransmit_buffer == NULL) {
								component->audio_retransmit_buffer = g_queue_new();
								component->audio_retransmit_seqs = g_hash_table_new(NULL, NULL);
							}
							g_queue_push_tail(component->audio_retransmit_buffer, p);
							/* Insert in the table too, for quick lookup */
							g_hash_table_insert(component->audio_retransmit_seqs, GUINT_TO_POINTER(seq), p);
						} else {
							if(component->video_retransmit_buffer == NULL) {
								component->video_retransmit_buffer = g_queue_new();
								component->video_retransmit_seqs = g_hash_table_new(NULL, NULL);
							}
							g_queue_push_tail(component->video_retransmit_buffer, p);
							/* Insert in the table too, for quick lookup */
							g_hash_table_insert(component->video_retransmit_seqs, GUINT_TO_POINTER(seq), p);
						}
					} else {
						janus_ice_free_rtp_packet(p);
					}
				}
			}
		} else if(pkt->type == JANUS_ICE_PACKET_TEXT || pkt->type == JANUS_ICE_PACKET_BINARY) {
			/* Data */
			if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_DATA_CHANNELS)) {
				janus_ice_free_queued_packet(pkt);
				return G_SOURCE_CONTINUE;
			}
#ifdef HAVE_SCTP
			if(!component->dtls) {
				if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT) && !component->noerrorlog) {
					JANUS_LOG(LOG_WARN, "[%"SCNu64"] SCTP stream component has no valid DTLS session (yet?)\n", handle->handle_id);
					component->noerrorlog = TRUE;	/* Don't flood with the same error all over again */
				}
				janus_ice_free_queued_packet(pkt);
				return G_SOURCE_CONTINUE;
			}
			component->noerrorlog = FALSE;
			/* TODO Support binary data */
			janus_dtls_wrap_sctp_data(component->dtls, pkt->label, pkt->protocol,
				pkt->type == JANUS_ICE_PACKET_TEXT, pkt->data, pkt->length);
#endif
		} else if(pkt->type == JANUS_ICE_PACKET_SCTP) {
			/* SCTP data to push */
			if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_DATA_CHANNELS)) {
				janus_ice_free_queued_packet(pkt);
				return G_SOURCE_CONTINUE;
			}
#ifdef HAVE_SCTP
			/* Encapsulate this data in DTLS and send it */
			if(!component->dtls) {
				if(!janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_ALERT) && !component->noerrorlog) {
					JANUS_LOG(LOG_WARN, "[%"SCNu64"] SCTP stream component has no valid DTLS session (yet?)\n", handle->handle_id);
					component->noerrorlog = TRUE;	/* Don't flood with the same error all over again */
				}
				janus_ice_free_queued_packet(pkt);
				return G_SOURCE_CONTINUE;
			}
			component->noerrorlog = FALSE;
			janus_dtls_send_sctp_data(component->dtls, pkt->data, pkt->length);
#endif
		} else {
			JANUS_LOG(LOG_WARN, "[%"SCNu64"] Unsupported packet type %d\n", handle->handle_id, pkt->type);
		}
		janus_ice_free_queued_packet(pkt);
	}
	return G_SOURCE_CONTINUE;
}

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

/**
 * @brief ICE转发RTP数据
 * 
 * @param handle 
 * @param packet 
 */
void janus_ice_relay_rtp(janus_ice_handle *handle, janus_plugin_rtp *packet) {
	/* 判断参数是否有效 */
	if(!handle || !handle->stream || handle->queued_packets == NULL || packet == NULL || packet->buffer == NULL ||
			!janus_is_rtp(packet->buffer, packet->length))
		return;
	/* 判断该插件是否不传输音频和视频 */	
	if((!packet->video && !janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_AUDIO))
			|| (packet->video && !janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_HAS_VIDEO)))
		return;
	/*RTP头部大小*/
	uint16_t totlen = RTP_HEADER_SIZE;
	/* Check how large the payload is 检查payload的大小 */
	int plen = 0;
	char *payload = janus_rtp_payload(packet->buffer, packet->length, &plen);
	if(payload != NULL)
	    /*总长度等于RTP头部长度+payload长度*/
		totlen += plen;
	/* We need to strip extensions, here, and add those that need to be there manually
	我们需要在这里去除扩展名，然后手动添加那些需要的扩展名 */
	uint16_t extlen = 0;
	char extensions[50];
	janus_rtp_header *header = (janus_rtp_header *)packet->buffer;
	int origext = header->extension;
	header->extension = 0;
	/* Add core and plugin extensions, if any 如果需要添加插件拓展 */
	if(handle->stream->mid_ext_id > 0 || 
	        (packet->video && handle->stream->abs_send_time_ext_id > 0) ||
			(packet->video && handle->stream->transport_wide_cc_ext_id > 0) ||
			(!packet->video && packet->extensions.audio_level != -1 && handle->stream->audiolevel_ext_id > 0) ||
			(packet->video && packet->extensions.video_rotation != -1 && handle->stream->videoorientation_ext_id > 0)) {
		header->extension = 1;
		/*初始化extensions内存空间为0*/
		memset(extensions, 0, sizeof(extensions));
		/*在extensions内存空间上创建janus_rtp_header_extension，初始化type = 0xBEDE , length = 0 RTP头后的第一个16为固定为0XBEDE标志，意味着这是一个one-byte扩展*/
		janus_rtp_header_extension *extheader = (janus_rtp_header_extension *)extensions;
		extheader->type = htons(0xBEDE);
		extheader->length = 0;
		/* Iterate on all extensions we need 迭代我们需要的拓展 index指向拓展内容*/
		char *index = extensions + 4;
		/* Check if we need to add the abs-send-time extension 检查我们是否需要添加abs-send-time拓展*/
		if(packet->video && handle->stream->abs_send_time_ext_id > 0) {
			*index = (handle->stream->abs_send_time_ext_id << 4) + 2;
			/* We'll actually set the value later, when sending the packet
			我们稍后会在发送数据包时设置该值  */
			memset(index+1, 0, 3);
			index += 4;
			extlen += 4;
		}
		/* Check if we need to add the transport-wide CC extension 检查我们是否需要添加transport-wide CC拓展 */
		if(packet->video && handle->stream->transport_wide_cc_ext_id > 0) {
			*index = (handle->stream->transport_wide_cc_ext_id << 4) + 1;
			/* We'll actually set the sequence number later, when sending the packet
			我们稍后会在发送数据包时设置序列号 */
			memset(index+1, 0, 2);
			index += 3;
			extlen += 3;
		}
		/* Check if we need to add the mid extension 检查我们是否需要添加mid拓展 */
		if(handle->stream->mid_ext_id > 0) {
			char *mid = packet->video ? handle->video_mid : handle->audio_mid;
			if(mid != NULL) {
				size_t midlen = strlen(mid) & 0x0F;
				*index = (handle->stream->mid_ext_id << 4) + (midlen ? midlen-1 : 0);
				memcpy(index+1, mid, midlen);
				index += (midlen + 1);
				extlen += (midlen + 1);
			}
		}
		/* Check if the plugin (or source) included other extensions 检查是否插件包含其他拓展 */
		if(!packet->video && packet->extensions.audio_level != -1 && handle->stream->audiolevel_ext_id > 0) {
			/* Add audio-level extension 添加音频级别拓展 */
			*index = (handle->stream->audiolevel_ext_id << 4) + 0;
			*(index+1) = (packet->extensions.audio_level_vad << 7) + (packet->extensions.audio_level & 0x7F);
			index += 2;
			extlen += 2;
		}
		if(packet->video && packet->extensions.video_rotation != -1 && handle->stream->videoorientation_ext_id > 0) {
			/* Add video-orientation extension 添加视频角度拓展 */
			*index = (handle->stream->videoorientation_ext_id << 4);
			gboolean c = packet->extensions.video_back_camera,
				f = packet->extensions.video_flipped, r1 = FALSE, r0 = FALSE;
			switch(packet->extensions.video_rotation) {
				case 270:
					r1 = TRUE;
					r0 = TRUE;
					break;
				case 180:
					r1 = TRUE;
					r0 = FALSE;
					break;
				case 90:
					r1 = FALSE;
					r0 = TRUE;
					break;
				case 0:
				default:
					r1 = FALSE;
					r0 = FALSE;
					break;
			}
			*(index+1) = (c<<3) + (f<<2) + (r1<<1) + r0;
			index += 2;
			extlen += 2;
		}
		/* Calculate the whole length 计算总长度 */
		uint16_t words = extlen/4;
		if(extlen%4 != 0)
			words++;
		extheader->length = htons(words);
		/* Update lengths (taking into account the RFC5285 header) 更新总长度 */
		extlen = 4 + (words*4);
		totlen += extlen;
	}
	/* Queue this packet 入队RTP包 */
	janus_ice_queued_packet *pkt = g_malloc(sizeof(janus_ice_queued_packet));
	pkt->data = g_malloc(totlen + SRTP_MAX_TAG_LEN);
	/* RTP header first 复制包头 */
	memcpy(pkt->data, packet->buffer, RTP_HEADER_SIZE);
	/* Then RTP extensions, if any 复制包拓展头 如果有*/
	if(extlen > 0)
		memcpy(pkt->data + RTP_HEADER_SIZE, extensions, extlen);
	/* Finally the RTP payload, if available 最后复制RTP payload*/
	if(payload != NULL && plen > 0)
		memcpy(pkt->data + RTP_HEADER_SIZE + extlen, payload, plen);
	pkt->length = totlen;
	pkt->type = packet->video ? JANUS_ICE_PACKET_VIDEO : JANUS_ICE_PACKET_AUDIO;
	pkt->control = FALSE;
	pkt->encrypted = FALSE;
	pkt->retransmission = FALSE;
	pkt->label = NULL;
	pkt->protocol = NULL;
	pkt->added = janus_get_monotonic_time();
	janus_ice_queue_packet(handle, pkt);
	/* Restore the extension flag to what the plugin set it to 将扩展标志恢复为插件设置的值 */
	header->extension = origext;
}

/**
 * @brief 转发 RTCP 消息的内部方法，可选择过滤它们 如果它们来自插件
 * 
 * @param handle 
 * @param packet 
 * @param filter_rtcp 
 */
void janus_ice_relay_rtcp_internal(janus_ice_handle *handle, janus_plugin_rtcp *packet, gboolean filter_rtcp) {
	if(!handle || handle->queued_packets == NULL || packet == NULL || packet->buffer == NULL ||
			!janus_is_rtcp(packet->buffer, packet->length))
		return;
	/* We use this internal method to check whether we need to filter RTCP (e.g., to make
	 * sure we don't just forward any SR/RR from peers/plugins, but use our own) or it has
	 * already been done, and so this is actually a packet added by the ICE send thread 
	 * 我们使用这个内部方法来检查我们是否需要过滤 RTCP 或者它已经完成了
	 * （例如，确保我们不只是转发来自对等/插件的任何 SR/RR，而是使用我们自己的）
	 * 所以这是 实际上是ICE发送线程添加的一个数据包 */
	char *rtcp_buf = packet->buffer;
	int rtcp_len = packet->length;
	if(filter_rtcp) {
		/* FIXME Strip RR/SR/SDES/NACKs/etc. 剥离 RR/SR/SDES/NACKs/等。 */
		janus_ice_stream *stream = handle->stream;
		if(stream == NULL)
		    /*没有stream数据，不需要通过RTCP进行控制*/
			return;
		/*过滤RTCP信息*/
		rtcp_buf = janus_rtcp_filter(packet->buffer, packet->length, &rtcp_len);
		if(rtcp_buf == NULL || rtcp_len < 1) {
			g_free(rtcp_buf);
			return;
		}
		/* Fix all SSRCs before enqueueing, as we need to use the ones for this media
		 * leg. Note that this is only needed for RTCP packets coming from plugins: the
		 * ones created by the core already have the right SSRCs in the right place 
		 * 在入队之前修复所有 SSRC，因为我们需要将这些 SSRC 用于此媒体分发。 
		 * 请注意，这只需要处理来自插件的 RTCP 数据包
		 * 由core创建的数据包已经在正确的地方拥有正确的SSRC，不需要处理*/
		JANUS_LOG(LOG_HUGE, "[%"SCNu64"] Fixing SSRCs (local %u, peer %u)\n", handle->handle_id,
			packet->video ? stream->video_ssrc : stream->audio_ssrc,
			packet->video ? stream->video_ssrc_peer[0] : stream->audio_ssrc_peer);
		janus_rtcp_fix_ssrc(NULL, rtcp_buf, rtcp_len, 1,
			packet->video ? stream->video_ssrc : stream->audio_ssrc,
			packet->video ? stream->video_ssrc_peer[0] : stream->audio_ssrc_peer);
	}
	/* Queue this packet  入队数据包 */
	janus_ice_queued_packet *pkt = g_malloc(sizeof(janus_ice_queued_packet));
	pkt->data = g_malloc(rtcp_len+SRTP_MAX_TAG_LEN+4);
	memcpy(pkt->data, rtcp_buf, rtcp_len);
	pkt->length = rtcp_len;
	pkt->type = packet->video ? JANUS_ICE_PACKET_VIDEO : JANUS_ICE_PACKET_AUDIO;
	pkt->control = TRUE;
	pkt->encrypted = FALSE;
	pkt->retransmission = FALSE;
	pkt->label = NULL;
	pkt->protocol = NULL;
	pkt->added = janus_get_monotonic_time();
	janus_ice_queue_packet(handle, pkt);
	if(rtcp_buf != packet->buffer) {
		/* We filtered the original packet, deallocate it
		我们已经过滤了原始包，释放它
		 */
		g_free(rtcp_buf);
	}
}

/**
 * @brief 核心的RTCP回调函数，在插件有需要发送到对端的RTCP包时被调用
 * 
 * @param handle 
 * @param packet 
 */
void janus_ice_relay_rtcp(janus_ice_handle *handle, janus_plugin_rtcp *packet) {
	janus_ice_relay_rtcp_internal(handle, packet, TRUE);
	/* If this is a PLI and we're simulcasting, send a PLI on other layers as well 
	如果这是一个 PLI 并且我们正在simulcasting，那么也在其他层上发送一个 PLI */
	if(janus_rtcp_has_pli(packet->buffer, packet->length)) {
		janus_ice_stream *stream = handle->stream;
		if(stream == NULL)
			return;
		if(stream->video_ssrc_peer[1]) {
			char plibuf[12];
			memset(plibuf, 0, 12);
			janus_rtcp_pli((char *)&plibuf, 12);
			janus_rtcp_fix_ssrc(NULL, plibuf, sizeof(plibuf), 1,
				stream->video_ssrc, stream->video_ssrc_peer[1]);
			janus_plugin_rtcp rtcp = { .video = TRUE, .buffer = plibuf, .length = sizeof(plibuf) };
			janus_ice_relay_rtcp_internal(handle, &rtcp, FALSE);
		}
		if(stream->video_ssrc_peer[2]) {
			char plibuf[12];
			memset(plibuf, 0, 12);
			janus_rtcp_pli((char *)&plibuf, 12);
			janus_rtcp_fix_ssrc(NULL, plibuf, sizeof(plibuf), 1,
				stream->video_ssrc, stream->video_ssrc_peer[2]);
			janus_plugin_rtcp rtcp = { .video = TRUE, .buffer = plibuf, .length = sizeof(plibuf) };
			janus_ice_relay_rtcp_internal(handle, &rtcp, FALSE);
		}
	}
}

/**
 * @brief 在插件想要去发送RTCP PLI到对端时调用
 * 
 * @param handle 
 */
void janus_ice_send_pli(janus_ice_handle *handle) {
	char rtcpbuf[12];
	memset(rtcpbuf, 0, 12);
	janus_rtcp_pli((char *)&rtcpbuf, 12);
	janus_plugin_rtcp rtcp = { .video = TRUE, .buffer = rtcpbuf, .length = 12 };
	janus_ice_relay_rtcp(handle, &rtcp);
}

/**
 * @brief 在插件想要去发送RTCP PLI到对端时调用
 * 
 * @param handle 
 * @param bitrate 
 */
void janus_ice_send_remb(janus_ice_handle *handle, uint32_t bitrate) {
	char rtcpbuf[24];
	janus_rtcp_remb((char *)&rtcpbuf, 24, bitrate);
	janus_plugin_rtcp rtcp = { .video = TRUE, .buffer = rtcpbuf, .length = 24 };
	janus_ice_relay_rtcp(handle, &rtcp);
}

#ifdef HAVE_SCTP
void janus_ice_relay_data(janus_ice_handle *handle, janus_plugin_data *packet) {
	if(!handle || handle->queued_packets == NULL || packet == NULL || packet->buffer == NULL || packet->length < 1)
		return;
	/* Queue this packet */
	janus_ice_queued_packet *pkt = g_malloc(sizeof(janus_ice_queued_packet));
	pkt->data = g_malloc(packet->length);
	memcpy(pkt->data, packet->buffer, packet->length);
	pkt->length = packet->length;
	pkt->type = packet->binary ? JANUS_ICE_PACKET_BINARY : JANUS_ICE_PACKET_TEXT;
	pkt->control = FALSE;
	pkt->encrypted = FALSE;
	pkt->retransmission = FALSE;
	pkt->label = packet->label ? g_strdup(packet->label) : NULL;
	pkt->protocol = packet->protocol ? g_strdup(packet->protocol) : NULL;
	pkt->added = janus_get_monotonic_time();
	janus_ice_queue_packet(handle, pkt);
}
#endif

/**
 * @brief 核心 SCTP/DataChannel 回调，当有数据要发送 时 由 SCTP 堆栈调用
 * 
 * @param handle 
 * @param buffer 
 * @param length 
 */
void janus_ice_relay_sctp(janus_ice_handle *handle, char *buffer, int length) {
#ifdef HAVE_SCTP
	if(!handle || handle->queued_packets == NULL || buffer == NULL || length < 1)
		return;
	/* Queue this packet */
	janus_ice_queued_packet *pkt = g_malloc(sizeof(janus_ice_queued_packet));
	pkt->data = g_malloc(length);
	memcpy(pkt->data, buffer, length);
	pkt->length = length;
	pkt->type = JANUS_ICE_PACKET_SCTP;
	pkt->control = FALSE;
	pkt->encrypted = FALSE;
	pkt->retransmission = FALSE;
	pkt->label = NULL;
	pkt->protocol = NULL;
	pkt->added = janus_get_monotonic_time();
	janus_ice_queue_packet(handle, pkt);
#endif
}

/**
 * @brief 插件 SCTP/DataChannel 回调，在可以写入数据 时 由 SCTP 堆栈调用
 * 
 * @param handle 
 */
void janus_ice_notify_data_ready(janus_ice_handle *handle) {
#ifdef HAVE_SCTP
	if(!handle || handle->queued_packets == NULL)
		return;
	/* Queue this event */
#if GLIB_CHECK_VERSION(2, 46, 0)
	g_async_queue_push_front(handle->queued_packets, &janus_ice_data_ready);
#else
	g_async_queue_push(handle->queued_packets, &janus_ice_data_ready);
#endif
	g_main_context_wakeup(handle->mainctx);
#endif
}

/**
 * @brief 核心 SDP 回调，当stream 被协商暂停 时 由 SDP 堆栈调用
 * 
 * @param handle 
 */
void janus_ice_notify_media_stopped(janus_ice_handle *handle) {
	if(!handle || handle->queued_packets == NULL)
		return;
	/* Queue this event */
#if GLIB_CHECK_VERSION(2, 46, 0)
	g_async_queue_push_front(handle->queued_packets, &janus_ice_media_stopped);
#else
	g_async_queue_push(handle->queued_packets, &janus_ice_media_stopped);
#endif
	g_main_context_wakeup(handle->mainctx);
}

/**
 * @brief 当特定组件的 DTLS 握手完成时通知回调函数
 * 
 * @param handle 
 * @param component 
 */
void janus_ice_dtls_handshake_done(janus_ice_handle *handle, janus_ice_component *component) {
	if(!handle || !component)
		return;
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] The DTLS handshake for the component %d in stream %d has been completed\n",
		handle->handle_id, component->component_id, component->stream_id);
	/* Check if all components are ready 检查是否所有组件都已经准备好 */
	janus_mutex_lock(&handle->mutex);
	if(handle->stream && janus_is_webrtc_encryption_enabled()) {
		if(handle->stream->component && (!handle->stream->component->dtls ||!handle->stream->component->dtls->srtp_valid)) {
			/* Still waiting for this component to become ready 还在等待组件准备完毕 */
			janus_mutex_unlock(&handle->mutex);
			return;
		}
	}
	if(janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_READY)) {
		/* Already notified 已经通知过了 */
		janus_mutex_unlock(&handle->mutex);
		return;
	}
	janus_flags_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_READY);
	/* Create a source for RTCP and one for stats
	为 RTCP 和 stats 各创建一个源 */
	handle->rtcp_source = g_timeout_source_new_seconds(1);
	g_source_set_priority(handle->rtcp_source, G_PRIORITY_DEFAULT);
	g_source_set_callback(handle->rtcp_source, janus_ice_outgoing_rtcp_handle, handle, NULL);
	g_source_attach(handle->rtcp_source, handle->mainctx);
	if(twcc_period != 1000) {
		/* The Transport Wide CC feedback period is different, create another source
		Transport Wide CC 反馈周期不同，创建另一个源 */
		handle->twcc_source = g_timeout_source_new(twcc_period);
		g_source_set_priority(handle->twcc_source, G_PRIORITY_DEFAULT);
		g_source_set_callback(handle->twcc_source, janus_ice_outgoing_transport_wide_cc_feedback, handle, NULL);
		g_source_attach(handle->twcc_source, handle->mainctx);
	}
	handle->last_event_stats = 0;
	handle->last_srtp_summary = -1;
	handle->stats_source = g_timeout_source_new_seconds(1);
	g_source_set_callback(handle->stats_source, janus_ice_outgoing_stats_handle, handle, NULL);
	g_source_set_priority(handle->stats_source, G_PRIORITY_DEFAULT);
	g_source_attach(handle->stats_source, handle->mainctx);
	janus_mutex_unlock(&handle->mutex);
	JANUS_LOG(LOG_INFO, "[%"SCNu64"] The DTLS handshake has been completed\n", handle->handle_id);
	/* Notify the plugin that the WebRTC PeerConnection is ready to be used 通知插件，WebRTC PeerConnection 可以准备被使用了 */
	janus_plugin *plugin = (janus_plugin *)handle->app;
	if(plugin != NULL) {
		JANUS_LOG(LOG_VERB, "[%"SCNu64"] Telling the plugin about it (%s)\n", handle->handle_id, plugin->get_name());
		/*dtls握手完成说明媒体可以开始发布了*/
		if(plugin && plugin->setup_media && janus_plugin_session_is_alive(handle->app_handle))
			plugin->setup_media(handle->app_handle);
	}
	/* Also prepare JSON event to notify user/application 也准备JSON 事件去同时用户/应用程序 */
	janus_session *session = (janus_session *)handle->session;
	if(session == NULL)
		return;
	json_t *event = json_object();
	json_object_set_new(event, "janus", json_string("webrtcup"));
	json_object_set_new(event, "session_id", json_integer(session->session_id));
	json_object_set_new(event, "sender", json_integer(handle->handle_id));
	if(opaqueid_in_api && handle->opaque_id != NULL)
		json_object_set_new(event, "opaque_id", json_string(handle->opaque_id));
	/* Send the event 发送事件 */
	JANUS_LOG(LOG_VERB, "[%"SCNu64"] Sending event to transport...; %p\n", handle->handle_id, handle);
	janus_session_notify_event(session, event);
	/* Notify event handlers as well 如果广播事件允许，我们也同步发送 */
	if(janus_events_is_enabled()) {
		json_t *info = json_object();
		json_object_set_new(info, "connection", json_string("webrtcup"));
		janus_events_notify_handlers(JANUS_EVENT_TYPE_WEBRTC, JANUS_EVENT_SUBTYPE_WEBRTC_STATE,
			session->session_id, handle->handle_id, handle->opaque_id, info);
	}
}
