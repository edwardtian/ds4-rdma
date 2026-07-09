/* ds4_dist_rdma.c — Transport implementations (TCP + RDMA) for ds4 distributed.
 *
 * TCP path: blocking send/recv loops, identical semantics to the existing
 *           static helpers in ds4_distributed.c.
 *
 * RDMA path: Apple RDMA over Thunderbolt 5 (macOS 26.2+, infiniband/verbs.h,
 *            librdma.tbd).  Uses UC queue pairs with IBV_WR_SEND/RECV only.
 *            QP metadata (GID, QPN, PSN) is exchanged over the TCP fd that
 *            remains open as a side-channel.
 *
 * The verbs header is included when available via __has_include so the file
 * compiles on older SDKs without RDMA support.
 */

#include "ds4_dist_transport.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* ----------------------------------------------------------------------- *
 * Verbs header detection
 * ----------------------------------------------------------------------- */

#if defined(__APPLE__) && defined(__has_include)
#  if __has_include(<infiniband/verbs.h>)
#    define DS4_HAS_VERBS_H 1
#  endif
#elif defined(__linux__)
#  define DS4_HAS_VERBS_H 1
#endif

#ifdef DS4_HAS_VERBS_H
#include <infiniband/verbs.h>
#endif

/* ----------------------------------------------------------------------- *
 * RDMA context
 * ----------------------------------------------------------------------- */

#ifdef DS4_HAS_VERBS_H

/* QP metadata exchanged over the TCP side-channel. */
typedef struct {
    uint32_t qpn;
    uint32_t psn;
    uint16_t lid;
    uint16_t pad;
    uint8_t  gid[16];
} ds4_dist_rdma_dest;

/* Per-connection RDMA state. */
typedef struct {
    struct ibv_context *ctx;
    struct ibv_pd      *pd;
    struct ibv_cq      *cq;
    struct ibv_qp      *qp;
    struct ibv_mr      *mr;
    void               *buf;
    size_t              buf_size;
    void               *send_ptr;
    void               *recv_ptr;
    size_t              send_cap;
    size_t              recv_cap;
    bool                recv_posted;
    bool                recv_ready;
    uint32_t            recv_len;
    uint32_t            recv_consumed;
    ds4_dist_rdma_dest  local;
} ds4_dist_rdma_ctx;

/* Per TN3205, queue depth is in units of 4 KB frames.  A single message of
 * N bytes consumes ceil(N/4096) WR slots.  To allow messages up to the
 * 16,773,120-byte limit (4095 * 4096), we must request max_send_wr and
 * max_recv_wr of at least 4095.  The CQ must be at least as deep.
 * The buffer size must not exceed 4095 * 4096 = 16,773,120 bytes. */
#define DS4_DIST_RDMA_QP_DEPTH 4095
#define DS4_DIST_RDMA_CQ_DEPTH 4096
#define DS4_DIST_RDMA_MAX_MSG  167773120  /* 4095 * 4096 */
#define DS4_DIST_RDMA_BUF_SIZE DS4_DIST_RDMA_MAX_MSG

#endif /* DS4_HAS_VERBS_H */

/* ----------------------------------------------------------------------- *
 * TCP I/O helpers
 * ----------------------------------------------------------------------- */

static int tcp_write_full(int fd, const void *buf, size_t len) {
    const unsigned char *p = buf;
    while (len > 0) {
        ssize_t n = send(fd, p, len, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        p += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

static int tcp_read_full(int fd, void *buf, size_t len) {
    unsigned char *p = buf;
    while (len > 0) {
        ssize_t n = recv(fd, p, len, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return 0;
        p += (size_t)n;
        len -= (size_t)n;
    }
    return 1;
}

static void encode_header(ds4_dist_transport_header *h, uint32_t type, uint32_t bytes) {
    h->magic = htonl(DS4_DIST_TRANSPORT_MAGIC);
    h->type = htonl(type);
    h->bytes = htonl(bytes);
}

static int decode_header(const ds4_dist_transport_header *h, uint32_t *type, uint32_t *bytes) {
    uint32_t magic = ntohl(h->magic);
    if (magic != DS4_DIST_TRANSPORT_MAGIC) return -1;
    *type = ntohl(h->type);
    *bytes = ntohl(h->bytes);
    return 0;
}

/* ----------------------------------------------------------------------- *
 * Connection lifecycle — TCP
 * ----------------------------------------------------------------------- */

ds4_dist_conn *ds4_dist_conn_new_tcp(int fd) {
    ds4_dist_conn *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->fd = fd;
    c->rdma = NULL;
    return c;
}

/* ----------------------------------------------------------------------- *
 * RDMA helpers
 * ----------------------------------------------------------------------- */

#ifdef DS4_HAS_VERBS_H

static ds4_dist_rdma_ctx *rdma_ctx_create(const char *device_name, char *err, size_t errlen) {
    int num_devices = 0;
    struct ibv_device **dev_list = ibv_get_device_list(&num_devices);
    if (!dev_list || num_devices == 0) {
        if (errlen) snprintf(err, errlen, "no RDMA devices found");
        if (dev_list) ibv_free_device_list(dev_list);
        return NULL;
    }

    struct ibv_device *dev = NULL;
    if (device_name && device_name[0]) {
        for (int i = 0; i < num_devices; i++) {
            if (strcmp(ibv_get_device_name(dev_list[i]), device_name) == 0) {
                dev = dev_list[i];
                break;
            }
        }
        if (!dev) {
            if (errlen) snprintf(err, errlen, "RDMA device '%s' not found", device_name);
            ibv_free_device_list(dev_list);
            return NULL;
        }
    } else {
        /* Find first device with PORT_ACTIVE */
        for (int i = 0; i < num_devices && !dev; i++) {
            struct ibv_context *ctx = ibv_open_device(dev_list[i]);
            if (!ctx) continue;
            struct ibv_port_attr attr;
            if (ibv_query_port(ctx, 1, &attr) == 0 && attr.state == IBV_PORT_ACTIVE) {
                dev = dev_list[i];
            }
            ibv_close_device(ctx);
        }
        if (!dev) dev = dev_list[0];
    }

    struct ibv_context *ctx = ibv_open_device(dev);
    ibv_free_device_list(dev_list);
    if (!ctx) {
        if (errlen) snprintf(err, errlen, "failed to open RDMA device");
        return NULL;
    }

    ds4_dist_rdma_ctx *r = calloc(1, sizeof(*r));
    if (!r) {
        ibv_close_device(ctx);
        if (errlen) snprintf(err, errlen, "out of memory");
        return NULL;
    }
    r->ctx = ctx;

    r->pd = ibv_alloc_pd(ctx);
    if (!r->pd) {
        if (errlen) snprintf(err, errlen, "ibv_alloc_pd failed");
        goto fail;
    }

    r->buf_size = DS4_DIST_RDMA_BUF_SIZE * 2;
    if (posix_memalign(&r->buf, 4096, r->buf_size) != 0) {
        if (errlen) snprintf(err, errlen, "posix_memalign failed for RDMA buffer");
        goto fail;
    }
    memset(r->buf, 0, r->buf_size);
    r->send_ptr = r->buf;
    r->recv_ptr = (char *)r->buf + DS4_DIST_RDMA_BUF_SIZE;
    r->send_cap = DS4_DIST_RDMA_BUF_SIZE;
    r->recv_cap = DS4_DIST_RDMA_BUF_SIZE;

    r->mr = ibv_reg_mr(r->pd, r->buf, r->buf_size, IBV_ACCESS_LOCAL_WRITE);
    if (!r->mr) {
        if (errlen) snprintf(err, errlen, "ibv_reg_mr failed");
        goto fail;
    }

    r->cq = ibv_create_cq(ctx, DS4_DIST_RDMA_CQ_DEPTH, NULL, NULL, 0);
    if (!r->cq) {
        if (errlen) snprintf(err, errlen, "ibv_create_cq failed");
        goto fail;
    }

    struct ibv_qp_init_attr qp_init;
    memset(&qp_init, 0, sizeof(qp_init));
    qp_init.send_cq = r->cq;
    qp_init.recv_cq = r->cq;
    qp_init.cap.max_send_wr = DS4_DIST_RDMA_QP_DEPTH;
    qp_init.cap.max_recv_wr = DS4_DIST_RDMA_QP_DEPTH;
    qp_init.cap.max_send_sge = 1;
    qp_init.cap.max_recv_sge = 1;
    qp_init.qp_type = IBV_QPT_UC;
    r->qp = ibv_create_qp(r->pd, &qp_init);
    if (!r->qp) {
        if (errlen) snprintf(err, errlen, "ibv_create_qp failed: %s", strerror(errno));
        goto fail;
    }

    /* Check actual QP capabilities — the hardware may adjust queue depths. */
    struct ibv_qp_attr qp_attr;
    struct ibv_qp_init_attr qp_init_attr_check;
    if (ibv_query_qp(r->qp, &qp_attr, IBV_QP_CAP, &qp_init_attr_check) == 0) {
        if (qp_attr.cap.max_send_wr < DS4_DIST_RDMA_QP_DEPTH ||
            qp_attr.cap.max_recv_wr < DS4_DIST_RDMA_QP_DEPTH) {
            fprintf(stderr,
                    "ds4: distributed rdma: warning: QP capabilities adjusted by hardware: "
                    "max_send_wr=%u max_recv_wr=%u (requested %d)\n",
                    qp_attr.cap.max_send_wr, qp_attr.cap.max_recv_wr,
                    DS4_DIST_RDMA_QP_DEPTH);
        }
    }

    /* Transition to INIT */
    struct ibv_qp_attr init_attr;
    memset(&init_attr, 0, sizeof(init_attr));
    init_attr.qp_state = IBV_QPS_INIT;
    init_attr.pkey_index = 0;
    init_attr.port_num = 1;
    init_attr.qp_access_flags = 0;
    if (ibv_modify_qp(r->qp, &init_attr,
                      IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS)) {
        if (errlen) snprintf(err, errlen, "ibv_modify_qp INIT failed");
        goto fail;
    }

    /* Query our GID and lid */
    struct ibv_port_attr port_attr;
    if (ibv_query_port(ctx, 1, &port_attr) != 0) {
        if (errlen) snprintf(err, errlen, "ibv_query_port failed");
        goto fail;
    }
    r->local.lid = port_attr.lid;
    union ibv_gid gid;
    if (ibv_query_gid(ctx, 1, 1, &gid) != 0) {
        if (errlen) snprintf(err, errlen, "ibv_query_gid failed");
        goto fail;
    }
    memcpy(r->local.gid, gid.raw, 16);
    r->local.qpn = r->qp->qp_num;
    r->local.psn = 7;
    r->local.pad = 0;

    return r;

fail:
    if (r->qp) ibv_destroy_qp(r->qp);
    if (r->cq) ibv_destroy_cq(r->cq);
    if (r->mr) ibv_dereg_mr(r->mr);
    if (r->buf) free(r->buf);
    if (r->pd) ibv_dealloc_pd(r->pd);
    ibv_close_device(r->ctx);
    free(r);
    return NULL;
}

static int rdma_qp_connect(ds4_dist_rdma_ctx *r, const ds4_dist_rdma_dest *peer,
                           char *err, size_t errlen) {
    /* Transition to RTR */
    struct ibv_qp_attr rtr_attr;
    memset(&rtr_attr, 0, sizeof(rtr_attr));
    rtr_attr.qp_state = IBV_QPS_RTR;
    rtr_attr.path_mtu = IBV_MTU_4096;
    rtr_attr.rq_psn = peer->psn;
    rtr_attr.dest_qp_num = peer->qpn;
    rtr_attr.ah_attr.dlid = peer->lid;
    rtr_attr.ah_attr.sl = 0;
    rtr_attr.ah_attr.src_path_bits = 0;
    rtr_attr.ah_attr.port_num = 1;
    rtr_attr.ah_attr.is_global = 1;
    rtr_attr.ah_attr.grh.hop_limit = 1;
    rtr_attr.ah_attr.grh.sgid_index = 1;
    memcpy(&rtr_attr.ah_attr.grh.dgid, peer->gid, 16);

    if (ibv_modify_qp(r->qp, &rtr_attr,
                      IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU |
                      IBV_QP_DEST_QPN | IBV_QP_RQ_PSN)) {
        if (errlen) snprintf(err, errlen, "ibv_modify_qp RTR failed");
        return -1;
    }

    /* Transition to RTS */
    struct ibv_qp_attr rts_attr;
    memset(&rts_attr, 0, sizeof(rts_attr));
    rts_attr.qp_state = IBV_QPS_RTS;
    rts_attr.sq_psn = r->local.psn;
    if (ibv_modify_qp(r->qp, &rts_attr, IBV_QP_STATE | IBV_QP_SQ_PSN)) {
        if (errlen) snprintf(err, errlen, "ibv_modify_qp RTS failed");
        return -1;
    }

    return 0;
}

static void rdma_ctx_destroy(ds4_dist_rdma_ctx *r) {
    if (!r) return;
    if (r->qp) ibv_destroy_qp(r->qp);
    if (r->cq) ibv_destroy_cq(r->cq);
    if (r->mr) ibv_dereg_mr(r->mr);
    if (r->buf) free(r->buf);
    if (r->pd) ibv_dealloc_pd(r->pd);
    if (r->ctx) ibv_close_device(r->ctx);
    free(r);
}

/* Exchange QP metadata over the TCP side-channel. */
static int rdma_handshake(ds4_dist_conn *c, ds4_dist_rdma_ctx *r,
                          char *err, size_t errlen) {
    /* Send our dest (network byte order) */
    ds4_dist_rdma_dest local = r->local;
    local.qpn = htonl(local.qpn);
    local.psn = htonl(local.psn);
    local.lid = htons(local.lid);
    local.pad = 0;
    if (tcp_write_full(c->fd, &local, sizeof(local)) != 0) {
        if (errlen) snprintf(err, errlen, "RDMA handshake: failed to send local dest");
        return -1;
    }

    /* Receive peer dest */
    ds4_dist_rdma_dest peer_net;
    int rc = tcp_read_full(c->fd, &peer_net, sizeof(peer_net));
    if (rc <= 0) {
        if (errlen) snprintf(err, errlen, "RDMA handshake: failed to recv peer dest");
        return -1;
    }
    ds4_dist_rdma_dest peer = peer_net;
    peer.qpn = ntohl(peer.qpn);
    peer.psn = ntohl(peer.psn);
    peer.lid = ntohs(peer.lid);

    /* Connect QP */
    if (rdma_qp_connect(r, &peer, err, errlen) != 0) return -1;

    /* Post initial receive */
    struct ibv_sge sge;
    memset(&sge, 0, sizeof(sge));
    sge.addr = (uintptr_t)r->recv_ptr;
    sge.length = (uint32_t)r->recv_cap;
    sge.lkey = r->mr->lkey;

    struct ibv_recv_wr wr;
    memset(&wr, 0, sizeof(wr));
    wr.wr_id = 2;
    wr.sg_list = &sge;
    wr.num_sge = 1;

    struct ibv_recv_wr *bad_wr;
    if (ibv_post_recv(r->qp, &wr, &bad_wr) != 0) {
        if (errlen) snprintf(err, errlen, "ibv_post_recv failed: %s", strerror(errno));
        return -1;
    }
    r->recv_posted = true;
    r->recv_ready = false;

    return 0;
}

/* Post a new recv and poll until completion. */
static int rdma_recv_wait(ds4_dist_rdma_ctx *r, char *err, size_t errlen) {
    if (r->recv_ready) return 0;

    if (!r->recv_posted) {
        struct ibv_sge sge;
        memset(&sge, 0, sizeof(sge));
        sge.addr = (uintptr_t)r->recv_ptr;
        sge.length = (uint32_t)r->recv_cap;
        sge.lkey = r->mr->lkey;

        struct ibv_recv_wr wr;
        memset(&wr, 0, sizeof(wr));
        wr.wr_id = 2;
        wr.sg_list = &sge;
        wr.num_sge = 1;

        struct ibv_recv_wr *bad_wr;
        if (ibv_post_recv(r->qp, &wr, &bad_wr) != 0) {
            if (errlen) snprintf(err, errlen, "ibv_post_recv failed: %s", strerror(errno));
            return -1;
        }
        r->recv_posted = true;
    }

    struct ibv_wc wc;
    int n;
    do {
        n = ibv_poll_cq(r->cq, 1, &wc);
    } while (n == 0);

    if (n < 0 || wc.status != IBV_WC_SUCCESS) {
        if (errlen) snprintf(err, errlen, "RDMA recv failed (wc.status=%d)", wc.status);
        r->recv_posted = false;
        return -1;
    }

    r->recv_posted = false;
    r->recv_ready = true;
    r->recv_len = wc.byte_len;
    r->recv_consumed = 0;
    return 0;
}

/* Poll until send completion. */
static int rdma_send_wait(ds4_dist_rdma_ctx *r, char *err, size_t errlen) {
    struct ibv_wc wc;
    int n;
    do {
        n = ibv_poll_cq(r->cq, 1, &wc);
    } while (n == 0);

    if (n < 0 || wc.status != IBV_WC_SUCCESS) {
        if (errlen) snprintf(err, errlen, "RDMA send failed (wc.status=%d)", wc.status);
        return -1;
    }
    return 0;
}

static int rdma_send_frame(ds4_dist_rdma_ctx *r, uint32_t type,
                           const void *body, uint32_t body_bytes,
                           char *err, size_t errlen) {
    uint32_t total = DS4_DIST_TRANSPORT_HEADER_BYTES + body_bytes;
    if (total > r->send_cap) {
        if (errlen) snprintf(err, errlen, "RDMA frame %u exceeds send buffer %zu", total, r->send_cap);
        return -1;
    }

    ds4_dist_transport_header *hdr = (ds4_dist_transport_header *)r->send_ptr;
    encode_header(hdr, type, body_bytes);
    if (body_bytes > 0)
        memcpy((char *)r->send_ptr + DS4_DIST_TRANSPORT_HEADER_BYTES, body, body_bytes);

    struct ibv_sge sge;
    memset(&sge, 0, sizeof(sge));
    sge.addr = (uintptr_t)r->send_ptr;
    sge.length = total;
    sge.lkey = r->mr->lkey;

    struct ibv_send_wr wr;
    memset(&wr, 0, sizeof(wr));
    wr.wr_id = 1;
    wr.sg_list = &sge;
    wr.num_sge = 1;
    wr.opcode = IBV_WR_SEND;
    wr.send_flags = IBV_SEND_SIGNALED;

    struct ibv_send_wr *bad_wr;
    if (ibv_post_send(r->qp, &wr, &bad_wr) != 0) {
        if (errlen) snprintf(err, errlen, "ibv_post_send failed: %s", strerror(errno));
        return -1;
    }

    return rdma_send_wait(r, err, errlen);
}

static int rdma_send_frame2(ds4_dist_rdma_ctx *r, uint32_t type,
                            const void *body1, uint32_t body1_bytes,
                            const void *body2, uint32_t body2_bytes,
                            char *err, size_t errlen) {
    uint32_t total = DS4_DIST_TRANSPORT_HEADER_BYTES + body1_bytes + body2_bytes;
    if (total > r->send_cap) {
        if (errlen) snprintf(err, errlen, "RDMA frame %u exceeds send buffer %zu", total, r->send_cap);
        return -1;
    }

    unsigned char *p = (unsigned char *)r->send_ptr;
    ds4_dist_transport_header *hdr = (ds4_dist_transport_header *)p;
    encode_header(hdr, type, body1_bytes + body2_bytes);
    p += DS4_DIST_TRANSPORT_HEADER_BYTES;
    if (body1_bytes > 0) { memcpy(p, body1, body1_bytes); p += body1_bytes; }
    if (body2_bytes > 0) { memcpy(p, body2, body2_bytes); }

    struct ibv_sge sge;
    memset(&sge, 0, sizeof(sge));
    sge.addr = (uintptr_t)r->send_ptr;
    sge.length = total;
    sge.lkey = r->mr->lkey;

    struct ibv_send_wr wr;
    memset(&wr, 0, sizeof(wr));
    wr.wr_id = 1;
    wr.sg_list = &sge;
    wr.num_sge = 1;
    wr.opcode = IBV_WR_SEND;
    wr.send_flags = IBV_SEND_SIGNALED;

    struct ibv_send_wr *bad_wr;
    if (ibv_post_send(r->qp, &wr, &bad_wr) != 0) {
        if (errlen) snprintf(err, errlen, "ibv_post_send failed: %s", strerror(errno));
        return -1;
    }

    return rdma_send_wait(r, err, errlen);
}

#endif /* DS4_HAS_VERBS_H */

/* ----------------------------------------------------------------------- *
 * Connection lifecycle — connect / accept
 * ----------------------------------------------------------------------- */

static void set_socket_options(int fd) {
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
#ifdef SO_NOSIGPIPE
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
}

ds4_dist_conn *ds4_dist_conn_connect(
        const char *host,
        int port,
        ds4_dist_transport_kind kind,
        const char *rdma_device,
        char *err,
        size_t errlen) {
    char portbuf[16];
    snprintf(portbuf, sizeof(portbuf), "%d", port);

    struct addrinfo hints, *res, *ai;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;

    int gai = getaddrinfo(host, portbuf, &hints, &res);
    if (gai != 0) {
        if (errlen) snprintf(err, errlen, "getaddrinfo(%s:%s): %s", host, portbuf, gai_strerror(gai));
        return NULL;
    }

    int fd = -1;
    for (ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        set_socket_options(fd);
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);

    if (fd < 0) {
        if (errlen) snprintf(err, errlen, "unable to connect to %s:%d: %s", host, port, strerror(errno));
        return NULL;
    }

    ds4_dist_conn *c = ds4_dist_conn_new_tcp(fd);
    if (!c) {
        close(fd);
        if (errlen) snprintf(err, errlen, "out of memory");
        return NULL;
    }

#ifdef DS4_HAS_VERBS_H
    if (kind == DS4_DIST_TRANSPORT_RDMA) {
        ds4_dist_rdma_ctx *r = rdma_ctx_create(rdma_device, err, errlen);
        if (!r) {
            ds4_dist_conn_close(c);
            return NULL;
        }
        if (rdma_handshake(c, r, err, errlen) != 0) {
            rdma_ctx_destroy(r);
            ds4_dist_conn_close(c);
            return NULL;
        }
        c->rdma = r;
    }
#else
    if (kind == DS4_DIST_TRANSPORT_RDMA) {
        if (errlen) snprintf(err, errlen, "RDMA support not compiled in");
        ds4_dist_conn_close(c);
        return NULL;
    }
#endif

    return c;
}

ds4_dist_conn *ds4_dist_conn_accept(
        int listen_fd,
        ds4_dist_transport_kind kind,
        const char *rdma_device,
        char *err,
        size_t errlen) {
    struct sockaddr_storage ss;
    socklen_t slen = sizeof(ss);
    int fd = accept(listen_fd, (struct sockaddr *)&ss, &slen);
    if (fd < 0) {
        if (errno == EINTR) {
            if (errlen) snprintf(err, errlen, "EINTR");
        } else {
            if (errlen) snprintf(err, errlen, "accept failed: %s", strerror(errno));
        }
        return NULL;
    }
    set_socket_options(fd);

    ds4_dist_conn *c = ds4_dist_conn_new_tcp(fd);
    if (!c) {
        close(fd);
        if (errlen) snprintf(err, errlen, "out of memory");
        return NULL;
    }

#ifdef DS4_HAS_VERBS_H
    if (kind == DS4_DIST_TRANSPORT_RDMA) {
        ds4_dist_rdma_ctx *r = rdma_ctx_create(rdma_device, err, errlen);
        if (!r) {
            ds4_dist_conn_close(c);
            return NULL;
        }
        if (rdma_handshake(c, r, err, errlen) != 0) {
            rdma_ctx_destroy(r);
            ds4_dist_conn_close(c);
            return NULL;
        }
        c->rdma = r;
    }
#else
    if (kind == DS4_DIST_TRANSPORT_RDMA) {
        if (errlen) snprintf(err, errlen, "RDMA support not compiled in");
        ds4_dist_conn_close(c);
        return NULL;
    }
#endif

    return c;
}

void ds4_dist_conn_shutdown(ds4_dist_conn *c) {
    if (!c) return;
    if (c->fd >= 0) shutdown(c->fd, SHUT_RDWR);
}

void ds4_dist_conn_close(ds4_dist_conn *c) {
    if (!c) return;
#ifdef DS4_HAS_VERBS_H
    if (c->rdma) {
        rdma_ctx_destroy((ds4_dist_rdma_ctx *)c->rdma);
        c->rdma = NULL;
    }
#endif
    if (c->fd >= 0) close(c->fd);
    free(c);
}

/* ----------------------------------------------------------------------- *
 * I/O — send
 * ----------------------------------------------------------------------- */

int ds4_dist_conn_send(
        ds4_dist_conn *c,
        uint32_t type,
        const void *body,
        uint32_t body_bytes) {
    if (!c) return -1;

#ifdef DS4_HAS_VERBS_H
    if (c->rdma) {
        char err[128];
        return rdma_send_frame((ds4_dist_rdma_ctx *)c->rdma, type, body, body_bytes,
                               err, sizeof(err));
    }
#endif

    ds4_dist_transport_header h;
    encode_header(&h, type, body_bytes);
    if (tcp_write_full(c->fd, &h, sizeof(h)) != 0) return -1;
    if (body_bytes > 0 && tcp_write_full(c->fd, body, body_bytes) != 0) return -1;
    return 0;
}

int ds4_dist_conn_send2(
        ds4_dist_conn *c,
        uint32_t type,
        const void *body1,
        uint32_t body1_bytes,
        const void *body2,
        uint32_t body2_bytes) {
    if (!c) return -1;

#ifdef DS4_HAS_VERBS_H
    if (c->rdma) {
        char err[128];
        return rdma_send_frame2((ds4_dist_rdma_ctx *)c->rdma,
                                type, body1, body1_bytes, body2, body2_bytes,
                                err, sizeof(err));
    }
#endif

    ds4_dist_transport_header h;
    encode_header(&h, type, body1_bytes + body2_bytes);
    if (tcp_write_full(c->fd, &h, sizeof(h)) != 0) return -1;
    if (body1_bytes > 0 && tcp_write_full(c->fd, body1, body1_bytes) != 0) return -1;
    if (body2_bytes > 0 && tcp_write_full(c->fd, body2, body2_bytes) != 0) return -1;
    return 0;
}

/* ----------------------------------------------------------------------- *
 * I/O — recv
 * ----------------------------------------------------------------------- */

int ds4_dist_conn_recv_header(
        ds4_dist_conn *c,
        uint32_t *type,
        uint32_t *body_bytes,
        char *err,
        size_t errlen) {
    if (!c) return -1;

#ifdef DS4_HAS_VERBS_H
    if (c->rdma) {
        ds4_dist_rdma_ctx *r = (ds4_dist_rdma_ctx *)c->rdma;
        if (rdma_recv_wait(r, err, errlen) != 0) return -1;

        if (r->recv_len < DS4_DIST_TRANSPORT_HEADER_BYTES) {
            if (errlen) snprintf(err, errlen, "RDMA recv too short: %u bytes", r->recv_len);
            r->recv_ready = false;
            return -1;
        }
        ds4_dist_transport_header *hdr = (ds4_dist_transport_header *)r->recv_ptr;
        if (decode_header(hdr, type, body_bytes) != 0) {
            if (errlen) snprintf(err, errlen, "bad frame magic in RDMA recv");
            r->recv_ready = false;
            return -1;
        }
        r->recv_consumed = DS4_DIST_TRANSPORT_HEADER_BYTES;
        return 1;
    }
#endif

    ds4_dist_transport_header h;
    int rc = tcp_read_full(c->fd, &h, sizeof(h));
    if (rc < 0) {
        if (errlen) snprintf(err, errlen, "failed to read frame header: %s", strerror(errno));
        return -1;
    }
    if (rc == 0) return 0;
    if (decode_header(&h, type, body_bytes) != 0) {
        if (errlen) snprintf(err, errlen, "bad frame magic");
        return -1;
    }
    return 1;
}

int ds4_dist_conn_recv_body(
        ds4_dist_conn *c,
        void *buf,
        uint32_t bytes) {
    if (!c) return -1;

#ifdef DS4_HAS_VERBS_H
    if (c->rdma) {
        ds4_dist_rdma_ctx *r = (ds4_dist_rdma_ctx *)c->rdma;
        uint32_t available = r->recv_len - r->recv_consumed;
        if (bytes > available) return -1;
        memcpy(buf, (char *)r->recv_ptr + r->recv_consumed, bytes);
        r->recv_consumed += bytes;
        if (r->recv_consumed >= r->recv_len) r->recv_ready = false;
        return 1;
    }
#endif

    return tcp_read_full(c->fd, buf, bytes);
}

int ds4_dist_conn_discard(
        ds4_dist_conn *c,
        uint32_t bytes) {
    if (!c) return -1;

#ifdef DS4_HAS_VERBS_H
    if (c->rdma) {
        ds4_dist_rdma_ctx *r = (ds4_dist_rdma_ctx *)c->rdma;
        uint32_t available = r->recv_len - r->recv_consumed;
        if (bytes > available) bytes = available;
        r->recv_consumed += bytes;
        if (r->recv_consumed >= r->recv_len) r->recv_ready = false;
        return 1;
    }
#endif

    unsigned char tmp[4096];
    while (bytes > 0) {
        uint32_t n = bytes < sizeof(tmp) ? bytes : (uint32_t)sizeof(tmp);
        int rc = tcp_read_full(c->fd, tmp, n);
        if (rc <= 0) return rc == 0 ? 0 : -1;
        bytes -= n;
    }
    return 1;
}

/* ----------------------------------------------------------------------- *
 * RDMA availability
 * ----------------------------------------------------------------------- */

bool ds4_dist_rdma_available(void) {
#ifdef DS4_HAS_VERBS_H
    int num = 0;
    struct ibv_device **list = ibv_get_device_list(&num);
    bool avail = list && num > 0;
    if (list) ibv_free_device_list(list);
    return avail;
#else
    return false;
#endif
}

const char *ds4_dist_rdma_auto_device(void) {
#ifdef DS4_HAS_VERBS_H
    int num = 0;
    struct ibv_device **list = ibv_get_device_list(&num);
    if (!list || num == 0) {
        if (list) ibv_free_device_list(list);
        return NULL;
    }
    for (int i = 0; i < num; i++) {
        struct ibv_context *ctx = ibv_open_device(list[i]);
        if (!ctx) continue;
        struct ibv_port_attr attr;
        if (ibv_query_port(ctx, 1, &attr) == 0 && attr.state == IBV_PORT_ACTIVE) {
            const char *name = ibv_get_device_name(list[i]);
            ibv_close_device(ctx);
            ibv_free_device_list(list);
            return name;
        }
        ibv_close_device(ctx);
    }
    ibv_free_device_list(list);
    return NULL;
#else
    return NULL;
#endif
}

uint32_t ds4_dist_rdma_max_tokens(uint64_t hc_values, uint32_t activation_bits) {
    if (hc_values == 0 || activation_bits == 0) return 1;
    uint32_t overhead = 256;
    uint32_t per_token = (uint32_t)(hc_values * activation_bits / 8) + 4;
    uint32_t avail = DS4_DIST_RDMA_MAX_MESSAGE - overhead;
    uint32_t max = avail / per_token;
    return max < 1 ? 1 : max;
}
