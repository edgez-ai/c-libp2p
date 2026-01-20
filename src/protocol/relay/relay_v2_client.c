#include "libp2p/relay_v2.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include "host_internal.h"
#include "libp2p/errors.h"
#include "libp2p/log.h"
#include "libp2p/lpmsg.h"
#include "libp2p/protocol.h"
#include "libp2p/stream.h"
#include "libp2p/stream_internal.h"
#include "multiformats/unsigned_varint/unsigned_varint.h"
#include "peer_id/peer_id.h"
#include "protocol/tcp/protocol_tcp_util.h"
#include "transport/connection.h"

#define RELAY_V2_MAX_MSG_SIZE 4096
#define RELAY_V2_HANDSHAKE_TIMEOUT_MS 60000

/* ----------------------- protobuf helpers ----------------------- */

typedef struct
{
    uint8_t *buf;
    size_t len;
    size_t cap;
} pb_buf_t;

static int pb_buf_reserve(pb_buf_t *b, size_t extra)
{
    if (!b)
        return -1;
    size_t need = b->len + extra;
    if (need <= b->cap)
        return 0;
    size_t newcap = b->cap ? b->cap : 64;
    while (newcap < need)
        newcap *= 2;
    uint8_t *nb = (uint8_t *)realloc(b->buf, newcap);
    if (!nb)
        return -1;
    b->buf = nb;
    b->cap = newcap;
    return 0;
}

static int pb_buf_append(pb_buf_t *b, const uint8_t *data, size_t len)
{
    if (!b || !data)
        return -1;
    if (pb_buf_reserve(b, len) != 0)
        return -1;
    memcpy(b->buf + b->len, data, len);
    b->len += len;
    return 0;
}

static int pb_buf_append_varint(pb_buf_t *b, uint64_t v)
{
    uint8_t tmp[10];
    size_t used = 0;
    if (unsigned_varint_encode(v, tmp, sizeof(tmp), &used) != UNSIGNED_VARINT_OK)
        return -1;
    return pb_buf_append(b, tmp, used);
}

static int pb_buf_append_key(pb_buf_t *b, uint64_t field_no, uint64_t wire_type)
{
    return pb_buf_append_varint(b, (field_no << 3) | wire_type);
}

static int pb_buf_append_bytes(pb_buf_t *b, const uint8_t *data, size_t len)
{
    if (pb_buf_append_varint(b, (uint64_t)len) != 0)
        return -1;
    return pb_buf_append(b, data, len);
}

static int pb_read_varint(const uint8_t *buf, size_t len, size_t *off, uint64_t *out)
{
    if (!buf || !off || !out)
        return -1;
    size_t used = 0;
    uint64_t v = 0;
    while (*off + used < len && used < 10)
    {
        uint8_t byte = buf[*off + used];
        v |= ((uint64_t)(byte & 0x7Fu)) << (7u * used);
        used++;
        if ((byte & 0x80u) == 0)
        {
            *off += used;
            *out = v;
            return 0;
        }
    }
    return -1;
}

static int pb_skip_field(const uint8_t *buf, size_t len, size_t *off, uint64_t wire)
{
    if (!buf || !off)
        return -1;
    if (wire == 0)
    {
        uint64_t tmp = 0;
        return pb_read_varint(buf, len, off, &tmp);
    }
    if (wire == 2)
    {
        uint64_t l = 0;
        if (pb_read_varint(buf, len, off, &l) != 0)
            return -1;
        if (*off + l > len)
            return -1;
        *off += (size_t)l;
        return 0;
    }
    return -1;
}

/* ----------------------- message encoding ----------------------- */

static int encode_hop_reserve(pb_buf_t *out)
{
    if (!out)
        return -1;
    /* HopMessage.Type = RESERVE (field 1, varint) */
    if (pb_buf_append_key(out, 1, 0) != 0)
        return -1;
    if (pb_buf_append_varint(out, 0) != 0)
        return -1;
    return 0;
}

static int encode_stop_status(pb_buf_t *out, libp2p_relay_v2_status_t status)
{
    if (!out)
        return -1;
    /* StopMessage.Type = STATUS (field 1) */
    if (pb_buf_append_key(out, 1, 0) != 0)
        return -1;
    if (pb_buf_append_varint(out, 1) != 0)
        return -1;
    /* StopMessage.Status = status (field 4) */
    if (pb_buf_append_key(out, 4, 0) != 0)
        return -1;
    if (pb_buf_append_varint(out, (uint64_t)status) != 0)
        return -1;
    return 0;
}

/* ----------------------- message decoding ----------------------- */

typedef struct
{
    int type_set;
    uint64_t type;
    int status_set;
    uint64_t status;
    uint64_t expire;
    uint32_t limit_duration;
    uint64_t limit_data;
} hop_msg_t;

typedef struct
{
    int type_set;
    uint64_t type;
} stop_msg_t;

static int parse_reservation(const uint8_t *buf, size_t len, hop_msg_t *out)
{
    size_t off = 0;
    while (off < len)
    {
        uint64_t key = 0;
        if (pb_read_varint(buf, len, &off, &key) != 0)
            return -1;
        uint64_t field = key >> 3;
        uint64_t wire = key & 0x7;
        if (field == 1 && wire == 0)
        {
            uint64_t v = 0;
            if (pb_read_varint(buf, len, &off, &v) != 0)
                return -1;
            out->expire = v;
            continue;
        }
        if (pb_skip_field(buf, len, &off, wire) != 0)
            return -1;
    }
    return 0;
}

static int parse_limit(const uint8_t *buf, size_t len, hop_msg_t *out)
{
    size_t off = 0;
    while (off < len)
    {
        uint64_t key = 0;
        if (pb_read_varint(buf, len, &off, &key) != 0)
            return -1;
        uint64_t field = key >> 3;
        uint64_t wire = key & 0x7;
        if (field == 1 && wire == 0)
        {
            uint64_t v = 0;
            if (pb_read_varint(buf, len, &off, &v) != 0)
                return -1;
            out->limit_duration = (uint32_t)v;
            continue;
        }
        if (field == 2 && wire == 0)
        {
            uint64_t v = 0;
            if (pb_read_varint(buf, len, &off, &v) != 0)
                return -1;
            out->limit_data = v;
            continue;
        }
        if (pb_skip_field(buf, len, &off, wire) != 0)
            return -1;
    }
    return 0;
}

static int parse_hop_message(const uint8_t *buf, size_t len, hop_msg_t *out)
{
    if (!buf || !out)
        return -1;
    memset(out, 0, sizeof(*out));
    size_t off = 0;
    while (off < len)
    {
        uint64_t key = 0;
        if (pb_read_varint(buf, len, &off, &key) != 0)
            return -1;
        uint64_t field = key >> 3;
        uint64_t wire = key & 0x7;
        if (field == 1 && wire == 0)
        {
            uint64_t v = 0;
            if (pb_read_varint(buf, len, &off, &v) != 0)
                return -1;
            out->type_set = 1;
            out->type = v;
            continue;
        }
        if (field == 5 && wire == 0)
        {
            uint64_t v = 0;
            if (pb_read_varint(buf, len, &off, &v) != 0)
                return -1;
            out->status_set = 1;
            out->status = v;
            continue;
        }
        if (field == 3 && wire == 2)
        {
            uint64_t l = 0;
            if (pb_read_varint(buf, len, &off, &l) != 0)
                return -1;
            if (off + l > len)
                return -1;
            if (parse_reservation(buf + off, (size_t)l, out) != 0)
                return -1;
            off += (size_t)l;
            continue;
        }
        if (field == 4 && wire == 2)
        {
            uint64_t l = 0;
            if (pb_read_varint(buf, len, &off, &l) != 0)
                return -1;
            if (off + l > len)
                return -1;
            if (parse_limit(buf + off, (size_t)l, out) != 0)
                return -1;
            off += (size_t)l;
            continue;
        }
        if (pb_skip_field(buf, len, &off, wire) != 0)
            return -1;
    }
    return 0;
}

static int parse_stop_message(const uint8_t *buf, size_t len, stop_msg_t *out)
{
    if (!buf || !out)
        return -1;
    memset(out, 0, sizeof(*out));
    size_t off = 0;
    while (off < len)
    {
        uint64_t key = 0;
        if (pb_read_varint(buf, len, &off, &key) != 0)
            return -1;
        uint64_t field = key >> 3;
        uint64_t wire = key & 0x7;
        if (field == 1 && wire == 0)
        {
            uint64_t v = 0;
            if (pb_read_varint(buf, len, &off, &v) != 0)
                return -1;
            out->type_set = 1;
            out->type = v;
            continue;
        }
        if (pb_skip_field(buf, len, &off, wire) != 0)
            return -1;
    }
    return 0;
}

/* ----------------------- stream -> conn adapter ----------------------- */

typedef struct
{
    libp2p_stream_t *stream;
    int closed;
} relay_stream_conn_t;

static libp2p_conn_err_t map_stream_err(ssize_t v)
{
    switch ((libp2p_err_t)v)
    {
        case LIBP2P_ERR_TIMEOUT:
            return LIBP2P_CONN_ERR_TIMEOUT;
        case LIBP2P_ERR_AGAIN:
            return LIBP2P_CONN_ERR_AGAIN;
        case LIBP2P_ERR_EOF:
            return LIBP2P_CONN_ERR_EOF;
        case LIBP2P_ERR_CLOSED:
            return LIBP2P_CONN_ERR_CLOSED;
        case LIBP2P_ERR_INTERNAL:
        default:
            return LIBP2P_CONN_ERR_INTERNAL;
    }
}

static ssize_t relay_conn_read(libp2p_conn_t *self, void *buf, size_t len)
{
    relay_stream_conn_t *ctx = self ? (relay_stream_conn_t *)self->ctx : NULL;
    if (!ctx || !ctx->stream)
        return LIBP2P_CONN_ERR_NULL_PTR;
    if (ctx->closed)
        return LIBP2P_CONN_ERR_CLOSED;
    ssize_t n = libp2p_stream_read(ctx->stream, buf, len);
    return n >= 0 ? n : map_stream_err(n);
}

static ssize_t relay_conn_write(libp2p_conn_t *self, const void *buf, size_t len)
{
    relay_stream_conn_t *ctx = self ? (relay_stream_conn_t *)self->ctx : NULL;
    if (!ctx || !ctx->stream)
        return LIBP2P_CONN_ERR_NULL_PTR;
    if (ctx->closed)
        return LIBP2P_CONN_ERR_CLOSED;
    ssize_t n = libp2p_stream_write(ctx->stream, buf, len);
    return n >= 0 ? n : map_stream_err(n);
}

static libp2p_conn_err_t relay_conn_set_deadline(libp2p_conn_t *self, uint64_t ms)
{
    relay_stream_conn_t *ctx = self ? (relay_stream_conn_t *)self->ctx : NULL;
    if (!ctx || !ctx->stream)
        return LIBP2P_CONN_ERR_NULL_PTR;
    int rc = libp2p_stream_set_deadline(ctx->stream, ms);
    return rc == 0 ? LIBP2P_CONN_OK : map_stream_err(rc);
}

static const multiaddr_t *relay_conn_local_addr(libp2p_conn_t *self)
{
    relay_stream_conn_t *ctx = self ? (relay_stream_conn_t *)self->ctx : NULL;
    if (!ctx || !ctx->stream)
        return NULL;
    return libp2p_stream_local_addr(ctx->stream);
}

static const multiaddr_t *relay_conn_remote_addr(libp2p_conn_t *self)
{
    relay_stream_conn_t *ctx = self ? (relay_stream_conn_t *)self->ctx : NULL;
    if (!ctx || !ctx->stream)
        return NULL;
    return libp2p_stream_remote_addr(ctx->stream);
}

static libp2p_conn_err_t relay_conn_close(libp2p_conn_t *self)
{
    relay_stream_conn_t *ctx = self ? (relay_stream_conn_t *)self->ctx : NULL;
    if (!ctx || !ctx->stream)
        return LIBP2P_CONN_ERR_NULL_PTR;
    ctx->closed = 1;
    int rc = libp2p_stream_close(ctx->stream);
    return rc == 0 ? LIBP2P_CONN_OK : map_stream_err(rc);
}

static void relay_conn_free(libp2p_conn_t *self)
{
    relay_stream_conn_t *ctx = self ? (relay_stream_conn_t *)self->ctx : NULL;
    if (ctx && ctx->stream)
    {
        libp2p_stream_close(ctx->stream);
        libp2p_stream_free(ctx->stream);
        ctx->stream = NULL;
    }
    free(ctx);
    free(self);
}

static int relay_conn_get_fd(libp2p_conn_t *self)
{
    (void)self;
    return -1;
}

static libp2p_conn_t *relay_conn_from_stream(libp2p_stream_t *s)
{
    if (!s)
        return NULL;
    relay_stream_conn_t *ctx = (relay_stream_conn_t *)calloc(1, sizeof(*ctx));
    if (!ctx)
        return NULL;
    libp2p_conn_t *c = (libp2p_conn_t *)calloc(1, sizeof(*c));
    if (!c)
    {
        free(ctx);
        return NULL;
    }
    static const libp2p_conn_vtbl_t VTBL = {
        .read = relay_conn_read,
        .write = relay_conn_write,
        .set_deadline = relay_conn_set_deadline,
        .local_addr = relay_conn_local_addr,
        .remote_addr = relay_conn_remote_addr,
        .close = relay_conn_close,
        .free = relay_conn_free,
        .get_fd = relay_conn_get_fd,
    };
    ctx->stream = s;
    c->vt = &VTBL;
    c->ctx = ctx;
    return c;
}

/* ----------------------- STOP handler ----------------------- */

typedef struct
{
    libp2p_stream_t *s;
    libp2p_host_t *host;
} relay_stop_ctx_t;

static void *relay_stop_worker(void *arg)
{
    relay_stop_ctx_t *ctx = (relay_stop_ctx_t *)arg;
    if (!ctx)
        return NULL;
    libp2p_stream_t *s = ctx->s;
    libp2p_host_t *host = ctx->host;
    free(ctx);

    if (!s)
    {
        if (host)
            libp2p__worker_dec(host);
        return NULL;
    }

    /* Log that we received an incoming STOP stream */
    const peer_id_t *remote = libp2p_stream_remote_peer(s);
    char peer_str[128] = {0};
    if (remote)
        peer_id_to_string(remote, PEER_ID_FMT_BASE58_LEGACY, peer_str, sizeof(peer_str));
    fprintf(stderr, "[RELAY STOP] received incoming STOP stream from peer=%s\n", peer_str[0] ? peer_str : "(unknown)");

    libp2p_stream_set_read_interest(s, true);

    uint8_t buf[RELAY_V2_MAX_MSG_SIZE];
    ssize_t n = libp2p_lp_recv(s, buf, sizeof(buf));
    if (n <= 0)
    {
        libp2p_stream_close(s);
        libp2p__stream_release_async(s);
        if (host)
            libp2p__worker_dec(host);
        return NULL;
    }

    stop_msg_t smsg;
    if (parse_stop_message(buf, (size_t)n, &smsg) != 0 || !smsg.type_set)
    {
        pb_buf_t out = {0};
        (void)encode_stop_status(&out, LIBP2P_RELAY_V2_STATUS_MALFORMED_MESSAGE);
        if (out.buf && out.len)
            (void)libp2p_lp_send(s, out.buf, out.len);
        free(out.buf);
        libp2p_stream_close(s);
        libp2p__stream_release_async(s);
        if (host)
            libp2p__worker_dec(host);
        return NULL;
    }

    if (smsg.type != 0)
    {
        pb_buf_t out = {0};
        (void)encode_stop_status(&out, LIBP2P_RELAY_V2_STATUS_UNEXPECTED_MESSAGE);
        if (out.buf && out.len)
            (void)libp2p_lp_send(s, out.buf, out.len);
        free(out.buf);
        libp2p_stream_close(s);
        libp2p__stream_release_async(s);
        if (host)
            libp2p__worker_dec(host);
        return NULL;
    }

    pb_buf_t out = {0};
    if (encode_stop_status(&out, LIBP2P_RELAY_V2_STATUS_OK) != 0 || !out.buf || !out.len)
    {
        free(out.buf);
        libp2p_stream_close(s);
        libp2p__stream_release_async(s);
        if (host)
            libp2p__worker_dec(host);
        return NULL;
    }
    (void)libp2p_lp_send(s, out.buf, out.len);
    free(out.buf);

    libp2p_conn_t *raw = relay_conn_from_stream(s);
    if (!raw)
    {
        libp2p_stream_close(s);
        libp2p_stream_free(s);
        libp2p__stream_release_async(s);
        if (host)
            libp2p__worker_dec(host);
        return NULL;
    }

    int rc = libp2p__host_accept_inbound_raw(host, raw);
    if (rc != 0)
    {
        libp2p_conn_free(raw);
        libp2p__stream_release_async(s);
        if (host)
            libp2p__worker_dec(host);
        return NULL;
    }

    /* ownership transferred to connection/session */
    libp2p__stream_release_async(s);
    if (host)
        libp2p__worker_dec(host);
    return NULL;
}

static void relay_stop_on_open(libp2p_stream_t *s, void *ud)
{
    (void)ud;
    if (!s)
        return;
    relay_stop_ctx_t *ctx = (relay_stop_ctx_t *)calloc(1, sizeof(*ctx));
    if (!ctx)
    {
        libp2p_stream_close(s);
        libp2p_stream_free(s);
        return;
    }
    libp2p_host_t *host = libp2p__stream_host(s);
    ctx->s = s;
    ctx->host = host;
    if (!libp2p__stream_retain_async(s))
    {
        free(ctx);
        libp2p_stream_close(s);
        libp2p_stream_free(s);
        return;
    }
    if (host)
        libp2p__worker_inc(host);

    pthread_t th;
    if (pthread_create(&th, NULL, relay_stop_worker, ctx) == 0)
    {
        pthread_detach(th);
        return;
    }

    if (host)
        libp2p__worker_dec(host);
    libp2p__stream_release_async(s);
    free(ctx);
    libp2p_stream_close(s);
    libp2p_stream_free(s);
}

/* ----------------------- public API ----------------------- */

int libp2p_relay_v2_client_start(libp2p_host_t *host)
{
    if (!host)
        return LIBP2P_ERR_NULL_PTR;
    libp2p_protocol_def_t def = {0};
    def.protocol_id = LIBP2P_RELAY_V2_PROTO_STOP;
    def.read_mode = LIBP2P_READ_PULL;
    def.on_open = relay_stop_on_open;
    def.user_data = NULL;
    int rc = libp2p_register_protocol(host, &def);
    fprintf(stderr, "[RELAY] registered STOP protocol handler: %s (rc=%d)\n", LIBP2P_RELAY_V2_PROTO_STOP, rc);
    return rc;
}

int libp2p_relay_v2_client_stop(libp2p_host_t *host)
{
    if (!host)
        return LIBP2P_ERR_NULL_PTR;
    return libp2p_unregister_protocol(host, LIBP2P_RELAY_V2_PROTO_STOP);
}

static int relay_status_to_err(libp2p_relay_v2_status_t st)
{
    if (st == LIBP2P_RELAY_V2_STATUS_OK)
        return 0;
    switch (st)
    {
        case LIBP2P_RELAY_V2_STATUS_RESERVATION_REFUSED:
        case LIBP2P_RELAY_V2_STATUS_RESOURCE_LIMIT_EXCEEDED:
        case LIBP2P_RELAY_V2_STATUS_PERMISSION_DENIED:
        case LIBP2P_RELAY_V2_STATUS_NO_RESERVATION:
            return LIBP2P_ERR_UNSUPPORTED;
        case LIBP2P_RELAY_V2_STATUS_MALFORMED_MESSAGE:
        case LIBP2P_RELAY_V2_STATUS_UNEXPECTED_MESSAGE:
        case LIBP2P_RELAY_V2_STATUS_CONNECTION_FAILED:
        default:
            return LIBP2P_ERR_INTERNAL;
    }
}

int libp2p_relay_v2_reserve(libp2p_host_t *host, const char *relay_multiaddr, int timeout_ms, libp2p_relay_v2_reservation_t *out)
{
    return libp2p_relay_v2_reserve_keep_stream(host, relay_multiaddr, timeout_ms, out, NULL);
}

int libp2p_relay_v2_reserve_keep_stream(libp2p_host_t *host, const char *relay_multiaddr, int timeout_ms, 
                                         libp2p_relay_v2_reservation_t *out, libp2p_stream_t **out_stream)
{
    if (!host || !relay_multiaddr)
        return LIBP2P_ERR_NULL_PTR;

    libp2p_stream_t *s = NULL;
    int rc = libp2p_host_dial_protocol_blocking(host, relay_multiaddr, LIBP2P_RELAY_V2_PROTO_HOP, timeout_ms, &s);
    if (rc != 0 || !s)
        return rc != 0 ? rc : LIBP2P_ERR_INTERNAL;

    pb_buf_t msg = {0};
    if (encode_hop_reserve(&msg) != 0 || !msg.buf || !msg.len)
    {
        free(msg.buf);
        libp2p_stream_close(s);
        libp2p_stream_free(s);
        return LIBP2P_ERR_INTERNAL;
    }

    libp2p_stream_set_deadline(s, RELAY_V2_HANDSHAKE_TIMEOUT_MS);
    rc = (int)libp2p_lp_send(s, msg.buf, msg.len);
    free(msg.buf);
    if (rc < 0)
    {
        libp2p_stream_close(s);
        libp2p_stream_free(s);
        return LIBP2P_ERR_INTERNAL;
    }

    /* Retry loop for reading response - libp2p_lp_recv returns AGAIN immediately
     * if no data is available yet. We need to keep trying until data arrives
     * or we hit our timeout. */
    uint8_t buf[RELAY_V2_MAX_MSG_SIZE];
    ssize_t n;
    uint64_t deadline = now_mono_ms() + RELAY_V2_HANDSHAKE_TIMEOUT_MS;
    for (;;)
    {
        n = libp2p_lp_recv(s, buf, sizeof(buf));
        if (n != LIBP2P_ERR_AGAIN)
            break;
        if (now_mono_ms() >= deadline)
        {
            n = LIBP2P_ERR_TIMEOUT;
            break;
        }
        /* Small sleep to avoid busy-waiting */
        usleep(10000); /* 10ms */
    }
    libp2p_stream_set_deadline(s, 0);
    if (n <= 0)
    {
        libp2p_stream_close(s);
        libp2p_stream_free(s);
        return (int)n < 0 ? (int)n : LIBP2P_ERR_EOF;
    }

    hop_msg_t hmsg;
    if (parse_hop_message(buf, (size_t)n, &hmsg) != 0 || !hmsg.type_set || !hmsg.status_set || hmsg.type != 2)
    {
        fprintf(stderr, "[RELAY] failed to parse hop response (n=%zd type_set=%d status_set=%d type=%d)\n",
                n, hmsg.type_set, hmsg.status_set, hmsg.type);
        libp2p_stream_close(s);
        libp2p_stream_free(s);
        return LIBP2P_ERR_INTERNAL;
    }

    fprintf(stderr, "[RELAY] received hop response: status=%d expire=%llu\n", hmsg.status, (unsigned long long)hmsg.expire);

    if (out)
    {
        out->status = (libp2p_relay_v2_status_t)hmsg.status;
        out->expire_unix = hmsg.expire;
        out->limit_duration_s = hmsg.limit_duration;
        out->limit_data_bytes = hmsg.limit_data;
    }

    int result = relay_status_to_err((libp2p_relay_v2_status_t)hmsg.status);
    
    /* If caller wants to keep the stream and reservation succeeded, return it */
    if (out_stream && result == 0)
    {
        *out_stream = s;
    }
    else
    {
        libp2p_stream_close(s);
        libp2p_stream_free(s);
    }

    return result;
}

int libp2p_relay_v2_build_circuit_addr(const char *relay_multiaddr, const peer_id_t *self, char **out_addr)
{
    if (!relay_multiaddr || !self || !out_addr)
        return LIBP2P_ERR_NULL_PTR;

    const char *p = strstr(relay_multiaddr, "/p2p/");
    if (!p)
        p = strstr(relay_multiaddr, "/ipfs/");
    if (!p)
        return LIBP2P_ERR_UNSUPPORTED;

    char peer_str[128];
    int n = peer_id_to_string(self, PEER_ID_FMT_BASE58_LEGACY, peer_str, sizeof(peer_str));
    if (n <= 0)
        return LIBP2P_ERR_INTERNAL;

    size_t out_len = strlen(relay_multiaddr) + strlen("/p2p-circuit/p2p/") + (size_t)n + 1;
    char *buf = (char *)malloc(out_len);
    if (!buf)
        return LIBP2P_ERR_INTERNAL;

    snprintf(buf, out_len, "%s/p2p-circuit/p2p/%s", relay_multiaddr, peer_str);
    *out_addr = buf;
    return 0;
}
