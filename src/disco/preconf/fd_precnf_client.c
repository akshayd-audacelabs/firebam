#define _GNU_SOURCE
#include "fd_precnf_client.h"
#include "fd_precnf_encode.h"

#include "../../waltz/resolv/fd_netdb.h"
#include "../../waltz/http/fd_url.h"
#include "../../waltz/grpc/fd_grpc_client.h"
#include "../../waltz/grpc/fd_grpc_client_private.h"
#include "../../waltz/tlsrec/fd_tlsrec.h"
#include "../../ballet/ed25519/fd_x25519.h"
#include "../../util/net/fd_ip4.h"

#include <netinet/tcp.h>
#include <unistd.h>
#include <errno.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* Adapted from src/disco/events/fd_event_client.c.  See
   fd_precnf_client.h for the differences. */

static char const * const disconnect_reason_str[ FD_PRECNF_DISCONNECT_CNT ] = {
  "identity changed",
  "DNS resolution failed",
  "connect failed",
  "timeout",
  "transport failed",
  "peer closed the stream",
  "authentication failed",
  "no heartbeat from relayer",
  "relayer stopped granting flow-control credit",
};

struct fd_precnf_client {
  fd_grpc_client_t *       grpc_client;
  fd_grpc_client_metrics_t grpc_metrics[1];
  fd_grpc_h2_stream_t *    relay_stream;

  fd_precnf_auther_t auther[1];
  ulong              auth_fail_seen; /* auther->fail_cnt when last checked */

  int   connect_fail_logged;
  int   defer_disconnect;           /* INT_MAX if none */
  ulong consecutive_failure_count;

  long now; /* of the current poll */

  long  last_response_ns;
  long  last_heartbeat_ns;
  ulong heartbeat_count;
  long  stall_since;
  ulong stall_rem;
  ulong stall_msgs_sent;

  ulong state;
  long  reconnect_deadline;   /* DISCONNECTED */
  long  connect_deadline;     /* CONNECTING */
  long  auth_deadline;        /* AUTHENTICATING */
  long  connected_timestamp;  /* STREAMING */

  int sockfd;
  int epoll_fd;
  int epoll_out_armed;

  int              use_tls;
  fd_tls_t         tls[1];
  fd_chacha_rng_t  tls_rng[1];
  fd_tlsrec_conn_t tls_conn[1];

  char   server_fqdn[ FD_FQDN_BUF_MAX ]; /* cstr */
  ulong  server_fqdn_len;
  uint   server_ip4_addr;
  ushort server_tcp_port;

  fd_rng_t *             rng;
  fd_circq_t *           circq;
  fd_keyguard_client_t * keyguard_client;

  fd_precnf_client_metrics_t metrics;
};

static void
tls_init( fd_precnf_client_t *       client,
          fd_x509_ca_store_t const * ca_store ) {
  fd_tls_t * tls = fd_tls_join( fd_tls_new( client->tls ) );
  FD_TEST( tls );

  uchar rng_key[ FD_CHACHA_KEY_SZ ];
  if( FD_UNLIKELY( !fd_rng_secure( rng_key, sizeof(rng_key) ) ) ) FD_LOG_CRIT(( "fd_rng_secure failed" ));
  fd_chacha_rng_init( client->tls_rng, rng_key, FD_CHACHA_RNG_ALGO_CHACHA8 );
  fd_memzero_explicit( rng_key, sizeof(rng_key) );
  tls->rng = client->tls_rng;

  static uchar const alpn[] = { 2, 'h', '2' };
  fd_memcpy( tls->alpn, alpn, sizeof(alpn) );
  tls->alpn_sz = sizeof(alpn);

  if( FD_UNLIKELY( client->server_fqdn_len>=sizeof(tls->server_name) ) ) {
    FD_LOG_ERR(( "Server name is %lu bytes, longer than the %lu byte maximum: check [tiles.preconf.url]",
                 client->server_fqdn_len, sizeof(tls->server_name)-1UL ));
  }
  fd_memcpy( tls->server_name, client->server_fqdn, client->server_fqdn_len+1UL );
  tls->server_name_len = (ushort)client->server_fqdn_len;

  tls->ca_store = ca_store;
}

FD_FN_CONST ulong
fd_precnf_client_align( void ) {
  return alignof( fd_precnf_client_t );
}

FD_FN_CONST ulong
fd_precnf_client_footprint( ulong buf_max ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_precnf_client_t), sizeof(fd_precnf_client_t)          );
  l = FD_LAYOUT_APPEND( l, fd_grpc_client_align(),      fd_grpc_client_footprint( buf_max ) );
  return FD_LAYOUT_FINI( l, alignof(fd_precnf_client_t) );
}

void *
fd_precnf_client_new( void *                     shmem,
                      fd_keyguard_client_t *     keyguard_client,
                      fd_rng_t *                 rng,
                      fd_circq_t *               circq,
                      int                        epoll_fd,
                      char const *               _url,
                      uchar const                identity_pubkey[ 32 ],
                      ulong                      buf_max,
                      int                        use_tls,
                      fd_x509_ca_store_t const * ca_store ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_precnf_client_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_precnf_client_t * client = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_precnf_client_t), sizeof(fd_precnf_client_t)          );
  void * grpc_client_mem      = FD_SCRATCH_ALLOC_APPEND( l, fd_grpc_client_align(),      fd_grpc_client_footprint( buf_max ) );
  memset( client, 0, sizeof(fd_precnf_client_t) );

  fd_url_t url[1];
  _Bool _is_ssl = 0;
  if( FD_UNLIKELY( fd_url_parse_endpoint( url, _url, strlen( _url ), &client->server_tcp_port, &_is_ssl, "[tiles.preconf.url]" ) ) ) {
    FD_LOG_ERR(( "Could not parse [tiles.preconf.url]" ));
  }
  if( FD_UNLIKELY( url->host_len>=FD_FQDN_BUF_MAX ) ) FD_LOG_CRIT(( "Invalid url->host_len" )); /* unreachable */
  fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( client->server_fqdn ), url->host, url->host_len ) );
  client->server_fqdn_len = url->host_len;

  fd_precnf_auther_init( client->auther, identity_pubkey );

  client->sockfd   = -1;
  FD_TEST( -1!=epoll_fd );
  client->epoll_fd = epoll_fd;
  client->use_tls  = use_tls;
  if( use_tls ) {
    if( FD_UNLIKELY( !ca_store ) ) FD_LOG_ERR(( "NULL ca_store, but [tiles.preconf.url] requires TLS" ));
    tls_init( client, ca_store );
  }

  client->state                     = FD_PRECNF_CLIENT_STATE_DISCONNECTED;
  client->reconnect_deadline        = 0L;
  client->defer_disconnect          = INT_MAX;
  client->consecutive_failure_count = 0UL;
  client->auth_deadline             = LONG_MAX;

  client->circq           = circq;
  client->rng             = rng;
  client->keyguard_client = keyguard_client;

  extern fd_grpc_client_callbacks_t fd_precnf_client_grpc_callbacks;
  client->grpc_client = fd_grpc_client_new( grpc_client_mem, &fd_precnf_client_grpc_callbacks, client->grpc_metrics, client, buf_max, fd_rng_ulong( rng ) );
  FD_TEST( client->grpc_client );
  fd_grpc_client_set_authority( client->grpc_client, client->server_fqdn, client->server_fqdn_len, client->server_tcp_port );

  return (void *)client;
}

fd_precnf_client_t *
fd_precnf_client_join( void * shclient ) {
  if( FD_UNLIKELY( !shclient ) ) {
    FD_LOG_WARNING(( "NULL shclient" ));
    return NULL;
  }
  return (fd_precnf_client_t *)shclient;
}

fd_precnf_client_metrics_t const *
fd_precnf_client_metrics( fd_precnf_client_t const * client ) {
  fd_precnf_client_t * c = (fd_precnf_client_t *)client;
  c->metrics.bytes_written = client->grpc_metrics->stream_chunks_tx_bytes;
  c->metrics.bytes_read    = client->grpc_metrics->stream_chunks_rx_bytes;
  return &client->metrics;
}

ulong
fd_precnf_client_state( fd_precnf_client_t const * client ) {
  return client->state;
}

fd_precnf_auther_t const *
fd_precnf_client_auther( fd_precnf_client_t const * client ) {
  return client->auther;
}

/* clear_queue drops every queued message.  Called on (re)connect so
   transactions that waited out a disconnect are never sent late. */

static void
clear_queue( fd_precnf_client_t * client ) {
  fd_circq_t * circq = client->circq;
  client->metrics.stale_msg_cleared_cnt += circq->cnt;
  circq->cnt    = 0UL;
  circq->head   = 0UL;
  circq->tail   = 0UL;
  circq->cursor = ULONG_MAX;
}

static void
backoff( fd_precnf_client_t * client,
         long                 now ) {
  /* 1, 2, 4, ..., 32 s plus up to 100% jitter */
  ulong backoff_base   = 1UL << fd_ulong_min( client->consecutive_failure_count, 5UL );
  ulong backoff_jitter = fd_rng_ulong_roll( client->rng, backoff_base );
  client->reconnect_deadline = now + (long)( backoff_base + backoff_jitter )*(long)1e9;
  if( FD_UNLIKELY( client->consecutive_failure_count<8UL ) ) client->consecutive_failure_count++;
}

static void
disconnect( fd_precnf_client_t * client,
            long                 now,
            int                  reason,
            int                  err,
            int                  _backoff ) {
  if( FD_LIKELY( -1!=client->sockfd ) ) {
    if( FD_UNLIKELY( -1==close( client->sockfd ) ) ) FD_LOG_ERR(( "close() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
    client->sockfd = -1;
  }
  client->epoll_out_armed  = 0;
  client->state            = FD_PRECNF_CLIENT_STATE_DISCONNECTED;
  client->relay_stream     = NULL;
  client->auth_deadline    = LONG_MAX;
  client->stall_since      = 0L;
  client->defer_disconnect = INT_MAX;
  fd_precnf_auther_reset( client->auther );
  client->auth_fail_seen   = client->auther->fail_cnt;
  clear_queue( client );

  client->metrics.disconnect_cnt[ reason ]++;
  int quiet = ( reason==FD_PRECNF_DISCONNECT_CONNECT_FAILED || reason==FD_PRECNF_DISCONNECT_DNS_FAILED ) && client->connect_fail_logged;
  if( FD_UNLIKELY( quiet ) ) {
    FD_LOG_INFO(( "precnf: relayer %.*s: %s (%d)", (int)client->server_fqdn_len, client->server_fqdn, disconnect_reason_str[ reason ], err ));
  } else {
    FD_LOG_WARNING(( "precnf: disconnected from relayer %.*s: %s (%d)", (int)client->server_fqdn_len, client->server_fqdn, disconnect_reason_str[ reason ], err ));
  }
  if( reason==FD_PRECNF_DISCONNECT_CONNECT_FAILED || reason==FD_PRECNF_DISCONNECT_DNS_FAILED ) client->connect_fail_logged = 1;

  if( FD_LIKELY( _backoff ) ) backoff( client, now );
  else                        client->reconnect_deadline = now;
}

void
fd_precnf_client_set_identity( fd_precnf_client_t * client,
                               uchar const          identity_pubkey[ 32 ] ) {
  fd_precnf_auther_set_pubkey( client->auther, identity_pubkey );
  disconnect( client, client->now, FD_PRECNF_DISCONNECT_IDENTITY_CHANGED, 0, 0 );
}

static void
reconnect( fd_precnf_client_t * client,
           long                 now,
           int *                charge_busy ) {
  if( FD_UNLIKELY( now<client->reconnect_deadline ) ) return;

  *charge_busy = 1;
  client->metrics.connect_attempt_cnt++;
  FD_LOG_INFO(( "precnf: connecting to relayer %s://%.*s:%u", client->use_tls ? "https" : "http",
                (int)client->server_fqdn_len, client->server_fqdn, client->server_tcp_port ));

  /* FIXME IPv6 support */
  fd_addrinfo_t hints = {0};
  hints.ai_family = AF_INET;
  fd_addrinfo_t * res = NULL;
  uchar scratch[ 4096 ];
  void * pscratch = scratch;
  int err = fd_getaddrinfo( client->server_fqdn, &hints, &res, &pscratch, sizeof(scratch) );
  if( FD_UNLIKELY( err || !res || !res->ai_addr ) ) {
    disconnect( client, now, FD_PRECNF_DISCONNECT_DNS_FAILED, err, 1 );
    return;
  }
  uint const ip4_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;
  client->server_ip4_addr = ip4_addr;

  client->sockfd = socket( AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0 );
  if( FD_UNLIKELY( -1==client->sockfd ) ) FD_LOG_ERR(( "socket() failed (%d-%s)", errno, fd_io_strerror( errno ) ));

  struct epoll_event ev = { .events = EPOLLIN|EPOLLOUT, .data.fd = client->sockfd };
  if( FD_UNLIKELY( -1==epoll_ctl( client->epoll_fd, EPOLL_CTL_ADD, client->sockfd, &ev ) ) ) FD_LOG_ERR(( "epoll_ctl(ADD,sockfd) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  client->epoll_out_armed = 1;

  int tcp_nodelay = 1;
  if( FD_UNLIKELY( -1==setsockopt( client->sockfd, SOL_TCP, TCP_NODELAY, &tcp_nodelay, sizeof(int) ) ) ) FD_LOG_ERR(( "setsockopt failed (%d-%s)", errno, fd_io_strerror( errno ) ));

  struct sockaddr_in addr = {0};
  addr.sin_family      = AF_INET;
  addr.sin_port        = fd_ushort_bswap( client->server_tcp_port );
  addr.sin_addr.s_addr = ip4_addr;
  if( FD_UNLIKELY( -1==connect( client->sockfd, fd_type_pun_const( &addr ), sizeof(struct sockaddr_in) ) && errno!=EINPROGRESS ) ) {
    disconnect( client, now, FD_PRECNF_DISCONNECT_CONNECT_FAILED, errno, 1 );
    return;
  }

  if( client->use_tls ) {
    fd_tls_t * tls = client->tls;
    if( FD_UNLIKELY( !fd_rng_secure( tls->kex_private_key, 32UL ) ) ) FD_LOG_CRIT(( "fd_rng_secure failed" ));
    fd_x25519_public( tls->kex_public_key, tls->kex_private_key );
    fd_tlsrec_conn_init( client->tls_conn, tls, 0 );
  }

  fd_grpc_client_reset( client->grpc_client );

  client->state            = FD_PRECNF_CLIENT_STATE_CONNECTING;
  client->connect_deadline = now + FD_PRECNF_CONNECT_TIMEOUT_NS;
}

/* open_stream starts the long-lived StartRelayStream request once an
   access token is available. */

static void
open_stream( fd_precnf_client_t * client,
             long                 now,
             int *                charge_busy ) {
  if( FD_UNLIKELY( fd_grpc_client_request_is_blocked( client->grpc_client ) ) ) return;
  fd_precnf_auther_t const * auther = client->auther;

  static char const path[] = "/astralane_relayer.AstralaneRelayer/StartRelayStream";
  fd_grpc_h2_stream_t * stream = fd_grpc_client_request_start1(
      client->grpc_client, path, sizeof(path)-1, FD_PRECNF_REQ_RELAY_STREAM,
      NULL, 0UL, /* headers only; messages are sent later */
      auther->access_token, auther->access_token_sz,
      1 /* streaming */ );
  if( FD_UNLIKELY( !stream ) ) return; /* transient; retry next poll */
  fd_grpc_client_deadline_set( stream, FD_GRPC_DEADLINE_HEADER, now+FD_PRECNF_STREAM_OPEN_TIMEOUT_NS );

  client->relay_stream        = stream;
  client->state               = FD_PRECNF_CLIENT_STATE_STREAMING;
  client->auth_deadline       = LONG_MAX;
  client->connected_timestamp = now;
  client->last_response_ns    = now; /* opening the stream counts as the first sign of life */
  client->last_heartbeat_ns   = 0L;  /* send a heartbeat right away */
  client->heartbeat_count     = 0UL;
  client->connect_fail_logged = 0;
  client->metrics.stream_open_cnt++;
  clear_queue( client );
  *charge_busy = 1;
  FD_LOG_NOTICE(( "precnf: streaming to relayer %s://%.*s:%u", client->use_tls ? "https" : "http",
                  (int)client->server_fqdn_len, client->server_fqdn, client->server_tcp_port ));
}

/* tx sends at most one message per poll: a heartbeat if one is due,
   otherwise the oldest queued RelayUpdate. */

static void
tx( fd_precnf_client_t * client,
    long                 now,
    int *                charge_busy ) {
  fd_grpc_client_t * grpc = client->grpc_client;

  /* An auth request (e.g. a token refresh) is being written. */
  if( FD_UNLIKELY( grpc->request_stream && grpc->request_stream!=client->relay_stream ) ) return;
  if( FD_UNLIKELY( fd_grpc_client_stream_send_is_blocked( grpc ) ) ) return;

  if( FD_UNLIKELY( now-client->last_heartbeat_ns>=FD_PRECNF_HEARTBEAT_NS ) ) {
    uchar hb[ FD_PRECNF_HEARTBEAT_ENC_MAX ];
    ulong hb_sz = fd_precnf_encode_heartbeat( hb, client->heartbeat_count );
    if( FD_LIKELY( fd_grpc_client_stream_send_msg1( grpc, client->relay_stream, hb, hb_sz ) ) ) {
      client->heartbeat_count++;
      client->last_heartbeat_ns = now;
      client->metrics.heartbeat_sent_cnt++;
      *charge_busy = 1;
    }
    return;
  }

  ulong         msg_sz;
  uchar const * msg = fd_circq_cursor_advance( client->circq, &msg_sz );
  if( FD_LIKELY( !msg ) ) return;

  int sent = fd_grpc_client_stream_send_msg1( grpc, client->relay_stream, msg, msg_sz );

  /* Pop the message whether or not it was sent: the only failure here is
     a message larger than the gRPC buffer, which would never fit.  Reset
     the cursor so the next advance starts at the new head. */
  FD_TEST( !fd_circq_pop_until( client->circq, client->circq->cursor_seq-1UL ) );
  fd_circq_reset_cursor( client->circq );

  if( FD_LIKELY( sent ) ) client->metrics.msg_sent_cnt++;
  else                    client->metrics.msg_too_large_cnt++;
  *charge_busy = 1;
}

static void
epoll_out( fd_precnf_client_t * client,
           int                  want ) {
  if( FD_UNLIKELY( client->sockfd<0 ) ) return;
  if( FD_LIKELY( want==client->epoll_out_armed ) ) return;
  struct epoll_event ev = { .events = EPOLLIN | (want ? EPOLLOUT : 0U), .data.fd = client->sockfd };
  if( FD_UNLIKELY( -1==epoll_ctl( client->epoll_fd, EPOLL_CTL_MOD, client->sockfd, &ev ) ) ) FD_LOG_ERR(( "epoll_ctl(MOD,sockfd) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  client->epoll_out_armed = want;
}

long
fd_precnf_client_next_deadline( fd_precnf_client_t const * client,
                                long                       now ) {
  switch( client->state ) {
  case FD_PRECNF_CLIENT_STATE_DISCONNECTED:
    return fd_long_max( client->reconnect_deadline, now );
  case FD_PRECNF_CLIENT_STATE_CONNECTING:
    return client->connect_deadline; /* completion arrives as an epoll event */
  default: break;
  }

  /* Decrypted TLS bytes buffered in the gRPC client do not make the fd
     readable: drain now (see fd_event_client). */
  if( FD_UNLIKELY( client->use_tls &&
                   fd_grpc_client_tls_rx_pending( client->grpc_client ) &&
                   !fd_grpc_client_tls_tx_pending( client->grpc_client ) ) ) return now;

  long deadline = fd_grpc_client_next_deadline( client->grpc_client );
  if( client->state==FD_PRECNF_CLIENT_STATE_AUTHENTICATING ) {
    deadline = fd_long_min( deadline, client->auth_deadline );
    if( client->auther->needs_poll || fd_precnf_auther_has_token( client->auther ) ) deadline = now;
  }
  if( client->state==FD_PRECNF_CLIENT_STATE_STREAMING ) {
    deadline = fd_long_min( deadline, client->last_heartbeat_ns+FD_PRECNF_HEARTBEAT_NS );
    deadline = fd_long_min( deadline, client->last_response_ns +FD_PRECNF_RESPONSE_TIMEOUT_NS );
    if( client->auther->needs_poll ) deadline = now;
    if( fd_circq_unsent_cnt( client->circq ) && !fd_grpc_client_stream_send_is_blocked( client->grpc_client ) ) deadline = now;
    if( client->stall_since ) deadline = fd_long_min( deadline, client->stall_since+FD_PRECNF_CREDIT_STALL_NS );
    /* Re-check token expiry about once a minute. */
    deadline = fd_long_min( deadline, now+(long)60e9 );
  }
  return deadline;
}

static int
credit_stall_check( fd_precnf_client_t * client,
                    long                 now ) {
  ulong rem = fd_grpc_client_tx_starved( client->grpc_client );
  if( FD_LIKELY( !rem ) ) {
    client->stall_since = 0L;
    return 0;
  }
  if( !client->stall_since || rem!=client->stall_rem || client->metrics.msg_sent_cnt!=client->stall_msgs_sent ) {
    client->stall_since     = now;
    client->stall_rem       = rem;
    client->stall_msgs_sent = client->metrics.msg_sent_cnt;
    return 0;
  }
  if( FD_LIKELY( now-client->stall_since<=FD_PRECNF_CREDIT_STALL_NS ) ) return 0;
  disconnect( client, now, FD_PRECNF_DISCONNECT_CREDIT_STALL, 0, 1 );
  return 1;
}

static void
poll1( fd_precnf_client_t * client,
       long                 now,
       int *                charge_busy ) {
  if( FD_UNLIKELY( client->state==FD_PRECNF_CLIENT_STATE_DISCONNECTED ) ) reconnect( client, now, charge_busy );
  if( FD_UNLIKELY( client->state==FD_PRECNF_CLIENT_STATE_CONNECTING && now>client->connect_deadline ) ) {
    disconnect( client, now, FD_PRECNF_DISCONNECT_TIMEOUT, 0, 1 );
    return;
  }
  if( FD_UNLIKELY( client->state==FD_PRECNF_CLIENT_STATE_AUTHENTICATING && now>client->auth_deadline ) ) {
    disconnect( client, now, FD_PRECNF_DISCONNECT_TIMEOUT, 0, 1 );
    return;
  }

  if( FD_LIKELY( client->state!=FD_PRECNF_CLIENT_STATE_DISCONNECTED ) ) {
    int rxtx_err;
    if( client->use_tls ) rxtx_err = fd_grpc_client_rxtx_tls   ( client->grpc_client, client->tls_conn, client->sockfd, now, charge_busy );
    else                  rxtx_err = fd_grpc_client_rxtx_socket( client->grpc_client, client->sockfd, now, charge_busy );
    if( FD_UNLIKELY( -1==rxtx_err ) ) {
      disconnect( client, now, FD_PRECNF_DISCONNECT_TRANSPORT, errno, 1 );
      return;
    }
  }

  /* Callbacks never tear down the connection directly; they leave the
     reason here. */
  if( FD_UNLIKELY( client->defer_disconnect!=INT_MAX ) ) {
    disconnect( client, now, client->defer_disconnect, 0, 1 );
    return;
  }

  if( client->state==FD_PRECNF_CLIENT_STATE_AUTHENTICATING ) {
    if( FD_UNLIKELY( client->auther->fail_cnt!=client->auth_fail_seen ) ) {
      disconnect( client, now, FD_PRECNF_DISCONNECT_AUTH_FAILED, 0, 1 );
      return;
    }
    if( client->auther->needs_poll ) {
      fd_precnf_auther_poll( client->auther, client->grpc_client, client->keyguard_client, now );
      *charge_busy = 1;
    }
    if( fd_precnf_auther_has_token( client->auther ) ) open_stream( client, now, charge_busy );
  }

  if( client->state==FD_PRECNF_CLIENT_STATE_STREAMING ) {
    if( FD_UNLIKELY( now-client->last_response_ns>FD_PRECNF_RESPONSE_TIMEOUT_NS ) ) {
      disconnect( client, now, FD_PRECNF_DISCONNECT_NO_HEARTBEAT, 0, 1 );
      return;
    }
    if( FD_UNLIKELY( client->consecutive_failure_count && now-client->connected_timestamp>10L*(long)1e9 ) ) client->consecutive_failure_count = 0UL;
    if( FD_UNLIKELY( credit_stall_check( client, now ) ) ) return;

    /* Keep the token fresh for the next stream.  A failed refresh falls
       back to a full challenge in the background; the open stream is
       not affected. */
    client->auth_fail_seen = client->auther->fail_cnt;
    fd_precnf_auther_check_expiry( client->auther, now );
    if( client->auther->needs_poll ) fd_precnf_auther_poll( client->auther, client->grpc_client, client->keyguard_client, now );

    tx( client, now, charge_busy );
  }
}

void
fd_precnf_client_poll( fd_precnf_client_t * client,
                       long                 now,
                       int *                charge_busy ) {
  client->now = now;
  poll1( client, now, charge_busy );

  /* Flush bytes queued during this poll right away (see fd_event_client). */
  if( FD_UNLIKELY( client->state!=FD_PRECNF_CLIENT_STATE_DISCONNECTED && fd_grpc_client_tx_pending( client->grpc_client ) ) ) {
    int flush_err = client->use_tls ? fd_grpc_client_tls_flush      ( client->grpc_client, client->sockfd )
                                    : fd_grpc_client_tx_flush_socket( client->grpc_client, client->sockfd );
    if( FD_UNLIKELY( -1==flush_err ) ) {
      disconnect( client, now, FD_PRECNF_DISCONNECT_TRANSPORT, errno, 1 );
      return;
    }
  }

  int want = fd_grpc_client_tx_pending( client->grpc_client );
  want |= client->use_tls && fd_grpc_client_tls_tx_pending( client->grpc_client );
  epoll_out( client, want );
}

/* gRPC callbacks *****************************************************/

static void
grpc_conn_established( void * app_ctx ) {
  fd_precnf_client_t * client = app_ctx;
  client->state          = FD_PRECNF_CLIENT_STATE_AUTHENTICATING;
  client->auth_deadline  = client->now + FD_PRECNF_AUTH_TIMEOUT_NS;
  fd_precnf_auther_reset( client->auther );
  client->auth_fail_seen = client->auther->fail_cnt;
}

static void
grpc_conn_dead( void * app_ctx,
                uint   h2_err,
                int    closed_by ) {
  fd_precnf_client_t * client = app_ctx;
  FD_LOG_INFO(( "precnf: relayer connection closed %s (%u-%s)", closed_by ? "by peer" : "due to error", h2_err, fd_h2_strerror( h2_err ) ));
  client->defer_disconnect = FD_PRECNF_DISCONNECT_PEER_CLOSED;
}

static void
grpc_tx_complete( void * app_ctx,
                  ulong  request_ctx ) {
  (void)app_ctx; (void)request_ctx;
}

static void
grpc_rx_start( void * app_ctx,
               ulong  request_ctx ) {
  (void)app_ctx; (void)request_ctx;
}

static void
grpc_rx_msg( void *       app_ctx,
             void const * protobuf,
             ulong        protobuf_sz,
             ulong        request_ctx ) {
  fd_precnf_client_t * client = app_ctx;
  if( FD_LIKELY( request_ctx==FD_PRECNF_REQ_RELAY_STREAM ) ) {
    /* Contents are not used: any message from the relayer is a sign of
       life (it sends StartExpiringPacketStreamResponse heartbeats). */
    client->last_response_ns = client->now;
    client->metrics.response_rx_cnt++;
    return;
  }
  fd_precnf_auther_handle_resp( client->auther, request_ctx, protobuf, protobuf_sz, client->now );
}

static void
grpc_rx_end( void *                app_ctx,
             ulong                 request_ctx,
             fd_grpc_resp_hdrs_t * resp ) {
  fd_precnf_client_t * client = app_ctx;
  int ok = resp->h2_status==200 && resp->grpc_status==FD_GRPC_STATUS_OK;
  if( FD_UNLIKELY( !ok ) ) {
    FD_LOG_WARNING(( "precnf: relayer request %lu failed (HTTP %u, gRPC %u-%s): %.*s", request_ctx,
                     resp->h2_status, resp->grpc_status, fd_grpc_status_cstr( resp->grpc_status ),
                     (int)resp->grpc_msg_len, resp->grpc_msg ));
  }

  if( request_ctx==FD_PRECNF_REQ_RELAY_STREAM ) {
    /* The relay stream never ends normally. */
    int auth = resp->grpc_status==FD_GRPC_STATUS_UNAUTHENTICATED || resp->grpc_status==FD_GRPC_STATUS_PERMISSION_DENIED;
    client->defer_disconnect = auth ? FD_PRECNF_DISCONNECT_AUTH_FAILED : FD_PRECNF_DISCONNECT_PEER_CLOSED;
    return;
  }
  if( FD_UNLIKELY( !ok ) ) fd_precnf_auther_handle_request_fail( client->auther, request_ctx );
}

static void
grpc_rx_timeout( void * app_ctx,
                 ulong  request_ctx,
                 int    deadline_kind ) {
  (void)deadline_kind;
  fd_precnf_client_t * client = app_ctx;
  if( request_ctx==FD_PRECNF_REQ_RELAY_STREAM ) {
    client->defer_disconnect = FD_PRECNF_DISCONNECT_TIMEOUT;
    return;
  }
  fd_precnf_auther_handle_request_fail( client->auther, request_ctx );
}

static void
grpc_ping_ack( void * app_ctx ) {
  (void)app_ctx;
}

fd_grpc_client_callbacks_t fd_precnf_client_grpc_callbacks = {
  .conn_established = grpc_conn_established,
  .conn_dead        = grpc_conn_dead,
  .tx_complete      = grpc_tx_complete,
  .rx_start         = grpc_rx_start,
  .rx_msg           = grpc_rx_msg,
  .rx_end           = grpc_rx_end,
  .rx_timeout       = grpc_rx_timeout,
  .ping_ack         = grpc_ping_ack,
};
