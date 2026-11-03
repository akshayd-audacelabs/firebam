#ifndef HEADER_fd_src_disco_preconf_fd_precnf_client_h
#define HEADER_fd_src_disco_preconf_fd_precnf_client_h

/* fd_precnf_client.h maintains the connection to the pre-confirmation
   relayer and sends the queued RelayUpdate messages.

   It is adapted from fd_event_client (connection, TLS, deferred
   disconnects, backoff) with these differences:

   - Auth is Jito's auth.AuthService with role RELAYER (fd_precnf_auth),
     served from the same URL as the relay stream.
   - Messages are popped from the queue as soon as they are written.
     The relayer does not acknowledge messages, so there is no resend.
   - The queue is cleared on every (re)connect: stale transactions are
     never sent after a reconnect, as in the reference implementation.
   - A heartbeat RelayUpdate is sent every FD_PRECNF_HEARTBEAT_NS, ahead
     of queued data.
   - Any message from the relayer counts as liveness.  If none arrives
     for FD_PRECNF_RESPONSE_TIMEOUT_NS, the connection is torn down.

   The client is a non-blocking state machine driven by
   fd_precnf_client_poll.  All times are UNIX wallclock nanoseconds. */

#include "fd_precnf_auth.h"
#include "../events/fd_circq.h"
#include "../../ballet/x509/fd_x509_ca_store.h"

#define FD_PRECNF_CLIENT_STATE_DISCONNECTED   (0)
#define FD_PRECNF_CLIENT_STATE_CONNECTING     (1) /* TCP/TLS/HTTP2 handshake */
#define FD_PRECNF_CLIENT_STATE_AUTHENTICATING (2)
#define FD_PRECNF_CLIENT_STATE_STREAMING      (3) /* relay stream open */

/* Reasons a connection ended (indices into disconnect_cnt). */

#define FD_PRECNF_DISCONNECT_IDENTITY_CHANGED (0)
#define FD_PRECNF_DISCONNECT_DNS_FAILED       (1)
#define FD_PRECNF_DISCONNECT_CONNECT_FAILED   (2)
#define FD_PRECNF_DISCONNECT_TIMEOUT          (3) /* connect, auth or stream open took too long */
#define FD_PRECNF_DISCONNECT_TRANSPORT        (4) /* socket/TLS/HTTP2 error */
#define FD_PRECNF_DISCONNECT_PEER_CLOSED      (5)
#define FD_PRECNF_DISCONNECT_AUTH_FAILED      (6)
#define FD_PRECNF_DISCONNECT_NO_HEARTBEAT     (7) /* relayer silent for FD_PRECNF_RESPONSE_TIMEOUT_NS */
#define FD_PRECNF_DISCONNECT_CREDIT_STALL     (8) /* relayer stopped reading */
#define FD_PRECNF_DISCONNECT_CNT              (9)

#define FD_PRECNF_HEARTBEAT_NS          (500L*(long)1e6)  /* 500 ms */
#define FD_PRECNF_RESPONSE_TIMEOUT_NS   (15L*(long)1e9)   /* 15 s   */
#define FD_PRECNF_CONNECT_TIMEOUT_NS    (5L*(long)1e9)    /* 5 s    */
#define FD_PRECNF_AUTH_TIMEOUT_NS       (15L*(long)1e9)   /* whole auth handshake */
#define FD_PRECNF_STREAM_OPEN_TIMEOUT_NS (5L*(long)1e9)   /* response headers */
#define FD_PRECNF_CREDIT_STALL_NS       (20L*(long)1e9)

struct fd_precnf_client_metrics {
  ulong connect_attempt_cnt;
  ulong stream_open_cnt;
  ulong disconnect_cnt[ FD_PRECNF_DISCONNECT_CNT ];
  ulong heartbeat_sent_cnt;
  ulong msg_sent_cnt;
  ulong msg_too_large_cnt;
  ulong stale_msg_cleared_cnt;
  ulong response_rx_cnt;
  ulong bytes_written;
  ulong bytes_read;
};

typedef struct fd_precnf_client_metrics fd_precnf_client_metrics_t;

struct fd_precnf_client;
typedef struct fd_precnf_client fd_precnf_client_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_precnf_client_align( void );

FD_FN_CONST ulong
fd_precnf_client_footprint( ulong buf_max );

/* fd_precnf_client_new formats a client.  url is the relayer URL
   (http:// or https://; https uses ca_store to verify the server).
   epoll_fd is the waker's inner epoll fd the socket is registered with.
   buf_max is the gRPC buffer size, which bounds the largest message. */

void *
fd_precnf_client_new( void *                     shmem,
                      fd_keyguard_client_t *     keyguard_client,
                      fd_rng_t *                 rng,
                      fd_circq_t *               circq,
                      int                        epoll_fd,
                      char const *               url,
                      uchar const                identity_pubkey[ 32 ],
                      ulong                      buf_max,
                      int                        use_tls,
                      fd_x509_ca_store_t const * ca_store );

fd_precnf_client_t *
fd_precnf_client_join( void * shclient );

/* fd_precnf_client_poll drives the connection: connects, authenticates,
   opens the stream, sends heartbeats and queued messages, and handles
   timeouts.  Sets *charge_busy if it did work. */

void
fd_precnf_client_poll( fd_precnf_client_t * client,
                       long                 now,
                       int *                charge_busy );

/* fd_precnf_client_next_deadline returns when the client next needs to
   be polled (wallclock ns), assuming no socket activity. */

long
fd_precnf_client_next_deadline( fd_precnf_client_t const * client,
                                long                       now );

/* fd_precnf_client_set_identity switches the authentication key: the
   connection is dropped and re-established with the new identity. */

void
fd_precnf_client_set_identity( fd_precnf_client_t * client,
                               uchar const          identity_pubkey[ 32 ] );

ulong
fd_precnf_client_state( fd_precnf_client_t const * client );

/* fd_precnf_client_streaming returns 1 if the relay stream is open, so
   newly queued messages will be sent. */

static inline int
fd_precnf_client_streaming( fd_precnf_client_t const * client ) {
  return fd_precnf_client_state( client )==FD_PRECNF_CLIENT_STATE_STREAMING;
}

fd_precnf_client_metrics_t const *
fd_precnf_client_metrics( fd_precnf_client_t const * client );

fd_precnf_auther_t const *
fd_precnf_client_auther( fd_precnf_client_t const * client );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_preconf_fd_precnf_client_h */
