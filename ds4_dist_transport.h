#ifndef DS4_DIST_TRANSPORT_H
#define DS4_DIST_TRANSPORT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Transport abstraction for distributed inference data-plane connections.
 *
 * Control-plane connections (HELLO, monitoring, KV snapshots) always use TCP
 * and are not touched by this abstraction.  Data-plane connections (WORK and
 * RESULT frames) use ds4_dist_conn, which can be backed by either TCP or RDMA
 * (Apple's RDMA over Thunderbolt 5, macOS 26.2+, infiniband/verbs.h +
 * librdma.tbd).
 *
 * When RDMA is enabled the coordinator opens dedicated data connections to
 * worker data listeners (use_control_for_work = false) so that every WORK and
 * RESULT frame can flow over a dedicated RDMA queue pair instead of being
 * multiplexed on the TCP control socket.
 *
 * RDMA constraints on macOS (TN3205):
 *   - Send/Recv only (IBV_WR_SEND), no RDMA Write/Read
 *   - UC queue pairs only (IBV_QPT_UC)
 *   - Max 10 QPs per device, max 4095 work requests
 *   - Max message 16,773,120 bytes (4095 * 4096)
 *   - No librdmacm — manual QP state transitions, GID/QPN/PSN exchange over
 *     the TCP side-channel (the same fd used for the handshake)
 *   - Completion via ibv_poll_cq busy-poll
 */

/* Wire frame header — identical layout to ds4_dist_frame_header in
 * ds4_distributed.c, kept here so the transport can encode/decode frames. */
#define DS4_DIST_TRANSPORT_MAGIC 0x44533444u

typedef struct {
    uint32_t magic;
    uint32_t type;
    uint32_t bytes;
} ds4_dist_transport_header;

#define DS4_DIST_TRANSPORT_HEADER_BYTES 12u

typedef enum {
    DS4_DIST_TRANSPORT_TCP = 0,
    DS4_DIST_TRANSPORT_RDMA = 1,
} ds4_dist_transport_kind;

typedef struct ds4_dist_conn ds4_dist_conn;

struct ds4_dist_conn {
    /* TCP socket — always present.  For RDMA connections this is the
     * side-channel used for the GID/QPN/PSN handshake and remains open for
     * error signalling / shutdown. */
    int fd;
    /* RDMA context (opaque, defined in ds4_dist_rdma.c).  NULL for TCP. */
    void *rdma;
};

/* ----------------------------------------------------------------------- *
 * Connection lifecycle
 * ----------------------------------------------------------------------- */

/* Wrap an existing TCP fd into a conn (no RDMA).  Takes ownership of the fd. */
ds4_dist_conn *ds4_dist_conn_new_tcp(int fd);

/* Connect to host:port.  When kind == RDMA, performs the TCP connect, then
 * exchanges QP metadata over the TCP socket and transitions the QP to RTS.
 * Returns NULL on error. */
ds4_dist_conn *ds4_dist_conn_connect(
        const char *host,
        int port,
        ds4_dist_transport_kind kind,
        const char *rdma_device,
        char *err,
        size_t errlen);

/* Accept a connection from a TCP listener fd.  When kind == RDMA, performs
 * the RDMA handshake after accepting.  Returns NULL on error. */
ds4_dist_conn *ds4_dist_conn_accept(
        int listen_fd,
        ds4_dist_transport_kind kind,
        const char *rdma_device,
        char *err,
        size_t errlen);

/* Shutdown the underlying socket (SHUT_RDWR).  Safe to call on NULL. */
void ds4_dist_conn_shutdown(ds4_dist_conn *c);

/* Close and free.  Tears down RDMA state if present, then closes the fd.
 * Safe to call on NULL. */
void ds4_dist_conn_close(ds4_dist_conn *c);

/* ----------------------------------------------------------------------- *
 * I/O — frame-level send/recv
 *
 * For TCP, these delegate to blocking send/recv loops.
 * For RDMA, the entire frame (header + body) is transferred in a single
 * ibv_post_send / ibv_post_recv.  recv_header buffers the full frame
 * internally; recv_body copies from that buffer.
 * ----------------------------------------------------------------------- */

/* Send a complete frame: header(type, body_bytes) + body.
 * Returns 0 on success, -1 on error. */
int ds4_dist_conn_send(
        ds4_dist_conn *c,
        uint32_t type,
        const void *body,
        uint32_t body_bytes);

/* Send a frame from two non-contiguous buffers (header + part1 + part2).
 * Useful for assembling WORK frames without copying into a single buffer.
 * For TCP, writes header then part1 then part2.  For RDMA, copies all three
 * into the registered send buffer and posts one send.
 * Returns 0 on success, -1 on error. */
int ds4_dist_conn_send2(
        ds4_dist_conn *c,
        uint32_t type,
        const void *body1,
        uint32_t body1_bytes,
        const void *body2,
        uint32_t body2_bytes);

/* Receive a frame header.  For RDMA, receives the entire frame into an
 * internal buffer and returns the parsed header.  The body must be consumed
 * via recv_body or discard before the next recv_header call.
 * Returns 1 on success, 0 on clean EOF, -1 on error. */
int ds4_dist_conn_recv_header(
        ds4_dist_conn *c,
        uint32_t *type,
        uint32_t *body_bytes,
        char *err,
        size_t errlen);

/* Receive frame body into buf (buf must hold at least body_bytes).
 * Must be called after recv_header.  Returns 1 on success, 0 on EOF, -1
 * on error. */
int ds4_dist_conn_recv_body(
        ds4_dist_conn *c,
        void *buf,
        uint32_t bytes);

/* Discard body_bytes of frame body.  Returns 1 on success, 0 on EOF, -1
 * on error. */
int ds4_dist_conn_discard(
        ds4_dist_conn *c,
        uint32_t bytes);

/* ----------------------------------------------------------------------- *
 * Accessors
 * ----------------------------------------------------------------------- */

/* Get the underlying TCP fd (for poll, getpeername, etc.). */
static inline int ds4_dist_conn_fd(const ds4_dist_conn *c) {
    return c ? c->fd : -1;
}

/* Check if the connection is RDMA. */
static inline bool ds4_dist_conn_is_rdma(const ds4_dist_conn *c) {
    return c && c->rdma != NULL;
}

/* ----------------------------------------------------------------------- *
 * RDMA availability and configuration
 * ----------------------------------------------------------------------- */

/* Returns true if the RDMA verbs library is available and at least one
 * device is present. */
bool ds4_dist_rdma_available(void);

/* Auto-detect the first RDMA device with a PORT_ACTIVE port.  Returns a
 * device name string (static buffer) or NULL if none found. */
const char *ds4_dist_rdma_auto_device(void);

/* Maximum message size for RDMA (16,773,120 bytes per TN3205). */
#define DS4_DIST_RDMA_MAX_MESSAGE 1048576u

/* Compute the max tokens that fit in one RDMA message given hc_values and
 * bits-per-activation-element. */
uint32_t ds4_dist_rdma_max_tokens(uint64_t hc_values, uint32_t activation_bits);

#endif /* DS4_DIST_TRANSPORT_H */
