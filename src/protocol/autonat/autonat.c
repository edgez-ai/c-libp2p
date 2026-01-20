/**
 * AutoNAT v1 implementation for libp2p.
 *
 * The AutoNAT protocol allows a node to discover whether it is publicly
 * reachable by requesting dial-backs from other peers. This is essential
 * for NAT traversal and determining if relay services are needed.
 *
 * Protocol: /libp2p/autonat/1.0.0
 *
 * Message format (protobuf):
 *   message Message {
 *     enum MessageType { DIAL = 0; DIAL_RESPONSE = 1; }
 *     message PeerInfo {
 *       optional bytes id = 1;
 *       repeated bytes addrs = 2;
 *     }
 *     message Dial { optional PeerInfo peer = 1; }
 *     message DialResponse {
 *       enum ResponseStatus {
 *         OK = 0;
 *         E_DIAL_ERROR = 100;
 *         E_DIAL_REFUSED = 101;
 *         E_BAD_REQUEST = 200;
 *         E_INTERNAL_ERROR = 300;
 *       }
 *       optional ResponseStatus status = 1;
 *       optional string statusText = 2;
 *       optional bytes addr = 3;
 *     }
 *     optional MessageType type = 1;
 *     optional Dial dial = 2;
 *     optional DialResponse dialResponse = 3;
 *   }
 */

#include "libp2p/autonat.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>

#include "host_internal.h"
#include "libp2p/errors.h"
#include "libp2p/events.h"
#include "libp2p/log.h"
#include "libp2p/lpmsg.h"
#include "libp2p/peerstore.h"
#include "libp2p/protocol.h"
#include "libp2p/stream.h"
#include "libp2p/stream_internal.h"
#include "multiformats/multiaddr/multiaddr.h"
#include "multiformats/unsigned_varint/unsigned_varint.h"
#include "peer_id/peer_id.h"

#define AUTONAT_MAX_MSG_SIZE 4096
#define AUTONAT_DEFAULT_DIAL_TIMEOUT_MS 15000
#define AUTONAT_DEFAULT_REFRESH_INTERVAL_MS 60000
#define AUTONAT_DEFAULT_BOOT_DELAY_MS 15000
#define AUTONAT_DEFAULT_THROTTLE_GLOBAL_MAX 30
#define AUTONAT_DEFAULT_THROTTLE_PEER_MAX 3
#define AUTONAT_DEFAULT_THROTTLE_INTERVAL_MS 60000
#define AUTONAT_DEFAULT_MIN_PEERS 3
#define AUTONAT_DEFAULT_MIN_CONFIRMATIONS 3

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

static int pb_buf_append_string(pb_buf_t *b, const char *str)
{
    size_t len = str ? strlen(str) : 0;
    return pb_buf_append_bytes(b, (const uint8_t *)str, len);
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

/* ----------------------- AutoNAT message structures ----------------------- */

typedef enum
{
    AUTONAT_MSG_DIAL = 0,
    AUTONAT_MSG_DIAL_RESPONSE = 1
} autonat_msg_type_t;

typedef struct
{
    uint8_t *id;
    size_t id_len;
    uint8_t **addrs;
    size_t *addrs_lens;
    size_t num_addrs;
} autonat_peer_info_t;

typedef struct
{
    autonat_peer_info_t peer;
} autonat_dial_t;

typedef struct
{
    int status_set;
    libp2p_autonat_status_t status;
    char *status_text;
    uint8_t *addr;
    size_t addr_len;
} autonat_dial_response_t;

typedef struct
{
    int type_set;
    autonat_msg_type_t type;
    autonat_dial_t dial;
    autonat_dial_response_t dial_response;
} autonat_message_t;

static void autonat_message_free(autonat_message_t *msg)
{
    if (!msg)
        return;
    free(msg->dial.peer.id);
    for (size_t i = 0; i < msg->dial.peer.num_addrs; i++)
        free(msg->dial.peer.addrs[i]);
    free(msg->dial.peer.addrs);
    free(msg->dial.peer.addrs_lens);
    free(msg->dial_response.status_text);
    free(msg->dial_response.addr);
    memset(msg, 0, sizeof(*msg));
}

/* ----------------------- message encoding ----------------------- */

static int encode_peer_info(pb_buf_t *out, const peer_id_t *peer, const char *const *addrs, size_t num_addrs)
{
    if (!out)
        return -1;

    /* Encode peer ID (field 1, bytes) - peer_id_t already has the raw bytes */
    if (peer && peer->bytes && peer->size > 0)
    {
        if (pb_buf_append_key(out, 1, 2) != 0)
            return -1;
        if (pb_buf_append_bytes(out, peer->bytes, peer->size) != 0)
            return -1;
    }

    /* Encode addresses (field 2, bytes, repeated) */
    for (size_t i = 0; i < num_addrs; i++)
    {
        if (!addrs[i])
            continue;
        int ma_err = 0;
        multiaddr_t *ma = multiaddr_new_from_str(addrs[i], &ma_err);
        if (!ma)
            continue;
        /* Get the multiaddr bytes using proper API */
        uint8_t ma_bytes[256];
        int blen = multiaddr_get_bytes(ma, ma_bytes, sizeof(ma_bytes));
        multiaddr_free(ma);
        if (blen > 0)
        {
            if (pb_buf_append_key(out, 2, 2) != 0)
                return -1;
            if (pb_buf_append_bytes(out, ma_bytes, (size_t)blen) != 0)
                return -1;
        }
    }
    return 0;
}

static int encode_dial_request(pb_buf_t *out, const peer_id_t *peer, const char *const *addrs, size_t num_addrs)
{
    if (!out)
        return -1;

    /* Message.type = DIAL (field 1, varint) */
    if (pb_buf_append_key(out, 1, 0) != 0)
        return -1;
    if (pb_buf_append_varint(out, AUTONAT_MSG_DIAL) != 0)
        return -1;

    /* Encode Dial.peer (field 2, embedded message) */
    pb_buf_t peer_info = {0};
    if (encode_peer_info(&peer_info, peer, addrs, num_addrs) != 0)
    {
        free(peer_info.buf);
        return -1;
    }

    /* Wrap peer info in Dial message */
    pb_buf_t dial = {0};
    if (peer_info.buf && peer_info.len > 0)
    {
        if (pb_buf_append_key(&dial, 1, 2) != 0)
        {
            free(peer_info.buf);
            free(dial.buf);
            return -1;
        }
        if (pb_buf_append_bytes(&dial, peer_info.buf, peer_info.len) != 0)
        {
            free(peer_info.buf);
            free(dial.buf);
            return -1;
        }
    }
    free(peer_info.buf);

    /* Message.dial (field 2, embedded message) */
    if (dial.buf && dial.len > 0)
    {
        if (pb_buf_append_key(out, 2, 2) != 0)
        {
            free(dial.buf);
            return -1;
        }
        if (pb_buf_append_bytes(out, dial.buf, dial.len) != 0)
        {
            free(dial.buf);
            return -1;
        }
    }
    free(dial.buf);
    return 0;
}

static int encode_dial_response(pb_buf_t *out, libp2p_autonat_status_t status, const char *status_text, const uint8_t *addr, size_t addr_len)
{
    if (!out)
        return -1;

    /* Message.type = DIAL_RESPONSE (field 1, varint) */
    if (pb_buf_append_key(out, 1, 0) != 0)
        return -1;
    if (pb_buf_append_varint(out, AUTONAT_MSG_DIAL_RESPONSE) != 0)
        return -1;

    /* Build DialResponse submessage */
    pb_buf_t resp = {0};

    /* DialResponse.status (field 1, varint) */
    if (pb_buf_append_key(&resp, 1, 0) != 0)
    {
        free(resp.buf);
        return -1;
    }
    if (pb_buf_append_varint(&resp, (uint64_t)status) != 0)
    {
        free(resp.buf);
        return -1;
    }

    /* DialResponse.statusText (field 2, string) */
    if (status_text && strlen(status_text) > 0)
    {
        if (pb_buf_append_key(&resp, 2, 2) != 0)
        {
            free(resp.buf);
            return -1;
        }
        if (pb_buf_append_string(&resp, status_text) != 0)
        {
            free(resp.buf);
            return -1;
        }
    }

    /* DialResponse.addr (field 3, bytes) */
    if (addr && addr_len > 0)
    {
        if (pb_buf_append_key(&resp, 3, 2) != 0)
        {
            free(resp.buf);
            return -1;
        }
        if (pb_buf_append_bytes(&resp, addr, addr_len) != 0)
        {
            free(resp.buf);
            return -1;
        }
    }

    /* Message.dialResponse (field 3, embedded message) */
    if (resp.buf && resp.len > 0)
    {
        if (pb_buf_append_key(out, 3, 2) != 0)
        {
            free(resp.buf);
            return -1;
        }
        if (pb_buf_append_bytes(out, resp.buf, resp.len) != 0)
        {
            free(resp.buf);
            return -1;
        }
    }
    free(resp.buf);
    return 0;
}

/* ----------------------- message decoding ----------------------- */

static int parse_peer_info(const uint8_t *buf, size_t len, autonat_peer_info_t *out)
{
    if (!buf || !out)
        return -1;
    size_t off = 0;
    size_t addr_cap = 0;

    while (off < len)
    {
        uint64_t key = 0;
        if (pb_read_varint(buf, len, &off, &key) != 0)
            return -1;
        uint64_t field = key >> 3;
        uint64_t wire = key & 0x7;

        if (field == 1 && wire == 2)
        {
            /* id (bytes) */
            uint64_t l = 0;
            if (pb_read_varint(buf, len, &off, &l) != 0)
                return -1;
            if (off + l > len)
                return -1;
            out->id = (uint8_t *)malloc((size_t)l);
            if (!out->id)
                return -1;
            memcpy(out->id, buf + off, (size_t)l);
            out->id_len = (size_t)l;
            off += (size_t)l;
            continue;
        }
        if (field == 2 && wire == 2)
        {
            /* addrs (bytes, repeated) */
            uint64_t l = 0;
            if (pb_read_varint(buf, len, &off, &l) != 0)
                return -1;
            if (off + l > len)
                return -1;

            /* Grow arrays */
            if (out->num_addrs >= addr_cap)
            {
                size_t newcap = addr_cap ? addr_cap * 2 : 4;
                uint8_t **na = (uint8_t **)realloc(out->addrs, newcap * sizeof(uint8_t *));
                size_t *nl = (size_t *)realloc(out->addrs_lens, newcap * sizeof(size_t));
                if (!na || !nl)
                {
                    free(na);
                    free(nl);
                    return -1;
                }
                out->addrs = na;
                out->addrs_lens = nl;
                addr_cap = newcap;
            }

            out->addrs[out->num_addrs] = (uint8_t *)malloc((size_t)l);
            if (!out->addrs[out->num_addrs])
                return -1;
            memcpy(out->addrs[out->num_addrs], buf + off, (size_t)l);
            out->addrs_lens[out->num_addrs] = (size_t)l;
            out->num_addrs++;
            off += (size_t)l;
            continue;
        }
        if (pb_skip_field(buf, len, &off, wire) != 0)
            return -1;
    }
    return 0;
}

static int parse_dial(const uint8_t *buf, size_t len, autonat_dial_t *out)
{
    if (!buf || !out)
        return -1;
    size_t off = 0;
    while (off < len)
    {
        uint64_t key = 0;
        if (pb_read_varint(buf, len, &off, &key) != 0)
            return -1;
        uint64_t field = key >> 3;
        uint64_t wire = key & 0x7;

        if (field == 1 && wire == 2)
        {
            /* peer (embedded PeerInfo) */
            uint64_t l = 0;
            if (pb_read_varint(buf, len, &off, &l) != 0)
                return -1;
            if (off + l > len)
                return -1;
            if (parse_peer_info(buf + off, (size_t)l, &out->peer) != 0)
                return -1;
            off += (size_t)l;
            continue;
        }
        if (pb_skip_field(buf, len, &off, wire) != 0)
            return -1;
    }
    return 0;
}

static int parse_dial_response(const uint8_t *buf, size_t len, autonat_dial_response_t *out)
{
    if (!buf || !out)
        return -1;
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
            /* status (varint) */
            uint64_t v = 0;
            if (pb_read_varint(buf, len, &off, &v) != 0)
                return -1;
            out->status_set = 1;
            out->status = (libp2p_autonat_status_t)v;
            continue;
        }
        if (field == 2 && wire == 2)
        {
            /* statusText (string) */
            uint64_t l = 0;
            if (pb_read_varint(buf, len, &off, &l) != 0)
                return -1;
            if (off + l > len)
                return -1;
            out->status_text = (char *)malloc((size_t)l + 1);
            if (!out->status_text)
                return -1;
            memcpy(out->status_text, buf + off, (size_t)l);
            out->status_text[l] = '\0';
            off += (size_t)l;
            continue;
        }
        if (field == 3 && wire == 2)
        {
            /* addr (bytes) */
            uint64_t l = 0;
            if (pb_read_varint(buf, len, &off, &l) != 0)
                return -1;
            if (off + l > len)
                return -1;
            out->addr = (uint8_t *)malloc((size_t)l);
            if (!out->addr)
                return -1;
            memcpy(out->addr, buf + off, (size_t)l);
            out->addr_len = (size_t)l;
            off += (size_t)l;
            continue;
        }
        if (pb_skip_field(buf, len, &off, wire) != 0)
            return -1;
    }
    return 0;
}

static int parse_autonat_message(const uint8_t *buf, size_t len, autonat_message_t *out)
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
            /* type (varint) */
            uint64_t v = 0;
            if (pb_read_varint(buf, len, &off, &v) != 0)
                return -1;
            out->type_set = 1;
            out->type = (autonat_msg_type_t)v;
            continue;
        }
        if (field == 2 && wire == 2)
        {
            /* dial (embedded Dial) */
            uint64_t l = 0;
            if (pb_read_varint(buf, len, &off, &l) != 0)
                return -1;
            if (off + l > len)
                return -1;
            if (parse_dial(buf + off, (size_t)l, &out->dial) != 0)
                return -1;
            off += (size_t)l;
            continue;
        }
        if (field == 3 && wire == 2)
        {
            /* dialResponse (embedded DialResponse) */
            uint64_t l = 0;
            if (pb_read_varint(buf, len, &off, &l) != 0)
                return -1;
            if (off + l > len)
                return -1;
            if (parse_dial_response(buf + off, (size_t)l, &out->dial_response) != 0)
                return -1;
            off += (size_t)l;
            continue;
        }
        if (pb_skip_field(buf, len, &off, wire) != 0)
            return -1;
    }
    return 0;
}

/* ----------------------- AutoNAT service structure ----------------------- */

typedef struct reachability_cb_node
{
    libp2p_autonat_reachability_cb cb;
    void *user_data;
    struct reachability_cb_node *next;
} reachability_cb_node_t;

typedef struct throttle_entry
{
    peer_id_t peer;
    int count;
    uint64_t reset_time;
    struct throttle_entry *next;
} throttle_entry_t;

struct libp2p_autonat_service
{
    libp2p_host_t *host;
    libp2p_autonat_opts_t opts;

    pthread_mutex_t mtx;
    pthread_t probe_thread;
    int probe_thread_started;
    int stop_requested;

    /* Reachability state */
    libp2p_autonat_reachability_t reachability;
    char *public_addr;
    int success_count;
    int failure_count;

    /* Callbacks */
    reachability_cb_node_t *callbacks;

    /* Throttling for server-side dial-backs */
    int global_dialback_count;
    uint64_t global_reset_time;
    throttle_entry_t *peer_throttle;
};

/* ----------------------- time helpers ----------------------- */

static uint64_t now_mono_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

/* ----------------------- server-side: handling incoming requests ----------------------- */

typedef struct
{
    libp2p_stream_t *s;
    libp2p_autonat_service_t *svc;
} autonat_server_ctx_t;

static int is_dialable_addr(const char *addr_str)
{
    if (!addr_str)
        return 0;
    /* Reject loopback, unspecified, link-local, private addresses */
    if (strstr(addr_str, "/ip4/127.") != NULL)
        return 0;
    if (strstr(addr_str, "/ip4/0.0.0.0") != NULL)
        return 0;
    if (strstr(addr_str, "/ip6/::1") != NULL)
        return 0;
    if (strstr(addr_str, "/ip6/::") != NULL && strstr(addr_str, "/ip6/::/") == NULL)
        return 0; /* ::1 or similar */
    if (strstr(addr_str, "/ip4/10.") != NULL)
        return 0;
    if (strstr(addr_str, "/ip4/192.168.") != NULL)
        return 0;
    if (strstr(addr_str, "/ip4/172.16.") != NULL)
        return 0;
    if (strstr(addr_str, "/ip4/172.17.") != NULL)
        return 0;
    if (strstr(addr_str, "/ip4/172.18.") != NULL)
        return 0;
    if (strstr(addr_str, "/ip4/172.19.") != NULL)
        return 0;
    if (strstr(addr_str, "/ip4/172.2") != NULL)
        return 0;
    if (strstr(addr_str, "/ip4/172.30.") != NULL)
        return 0;
    if (strstr(addr_str, "/ip4/172.31.") != NULL)
        return 0;
    /* Reject relay addresses */
    if (strstr(addr_str, "/p2p-circuit") != NULL)
        return 0;
    return 1;
}

static int check_throttle(libp2p_autonat_service_t *svc, const peer_id_t *peer)
{
    if (!svc || !peer)
        return 0;

    uint64_t now = now_mono_ms();

    /* Global throttle */
    if (now >= svc->global_reset_time)
    {
        svc->global_dialback_count = 0;
        svc->global_reset_time = now + (uint64_t)svc->opts.throttle_interval_ms;
    }
    if (svc->global_dialback_count >= svc->opts.throttle_global_max)
        return 0;

    /* Per-peer throttle */
    throttle_entry_t *te = svc->peer_throttle;
    while (te)
    {
        if (peer_id_equals(&te->peer, peer) == 1)
        {
            if (now >= te->reset_time)
            {
                te->count = 0;
                te->reset_time = now + (uint64_t)svc->opts.throttle_interval_ms;
            }
            if (te->count >= svc->opts.throttle_peer_max)
                return 0;
            te->count++;
            svc->global_dialback_count++;
            return 1;
        }
        te = te->next;
    }

    /* New peer entry */
    te = (throttle_entry_t *)calloc(1, sizeof(*te));
    if (!te)
        return 0;
    /* Copy peer_id manually since peer_id_copy doesn't exist */
    te->peer.size = peer->size;
    te->peer.bytes = (uint8_t *)malloc(peer->size);
    if (te->peer.bytes)
        memcpy(te->peer.bytes, peer->bytes, peer->size);
    te->count = 1;
    te->reset_time = now + (uint64_t)svc->opts.throttle_interval_ms;
    te->next = svc->peer_throttle;
    svc->peer_throttle = te;
    svc->global_dialback_count++;
    return 1;
}

static void *autonat_server_worker(void *arg)
{
    autonat_server_ctx_t *ctx = (autonat_server_ctx_t *)arg;
    if (!ctx)
        return NULL;

    libp2p_stream_t *s = ctx->s;
    libp2p_autonat_service_t *svc = ctx->svc;
    free(ctx);

    if (!s || !svc)
    {
        if (s)
        {
            libp2p_stream_close(s);
            libp2p__stream_release_async(s);
        }
        return NULL;
    }

    libp2p_host_t *host = svc->host;
    const peer_id_t *remote = libp2p_stream_remote_peer(s);

    char peer_str[128] = {0};
    if (remote)
        peer_id_to_string(remote, PEER_ID_FMT_BASE58_LEGACY, peer_str, sizeof(peer_str));
    fprintf(stderr, "[AUTONAT] received dial request from peer=%s\n", peer_str[0] ? peer_str : "(unknown)");

    libp2p_stream_set_read_interest(s, true);

    uint8_t buf[AUTONAT_MAX_MSG_SIZE];
    ssize_t n = libp2p_lp_recv(s, buf, sizeof(buf));
    if (n <= 0)
    {
        fprintf(stderr, "[AUTONAT] failed to read request from peer=%s\n", peer_str);
        libp2p_stream_close(s);
        libp2p__stream_release_async(s);
        if (host)
            libp2p__worker_dec(host);
        return NULL;
    }

    autonat_message_t msg;
    if (parse_autonat_message(buf, (size_t)n, &msg) != 0 || !msg.type_set || msg.type != AUTONAT_MSG_DIAL)
    {
        fprintf(stderr, "[AUTONAT] malformed dial request from peer=%s\n", peer_str);
        pb_buf_t out = {0};
        encode_dial_response(&out, LIBP2P_AUTONAT_STATUS_E_BAD_REQUEST, "malformed message", NULL, 0);
        if (out.buf && out.len)
            (void)libp2p_lp_send(s, out.buf, out.len);
        free(out.buf);
        autonat_message_free(&msg);
        libp2p_stream_close(s);
        libp2p__stream_release_async(s);
        if (host)
            libp2p__worker_dec(host);
        return NULL;
    }

    /* Check throttle */
    pthread_mutex_lock(&svc->mtx);
    int allowed = check_throttle(svc, remote);
    pthread_mutex_unlock(&svc->mtx);

    if (!allowed)
    {
        fprintf(stderr, "[AUTONAT] dial-back refused (throttled) for peer=%s\n", peer_str);
        pb_buf_t out = {0};
        encode_dial_response(&out, LIBP2P_AUTONAT_STATUS_E_DIAL_REFUSED, "rate limited", NULL, 0);
        if (out.buf && out.len)
            (void)libp2p_lp_send(s, out.buf, out.len);
        free(out.buf);
        autonat_message_free(&msg);
        libp2p_stream_close(s);
        libp2p__stream_release_async(s);
        if (host)
            libp2p__worker_dec(host);
        return NULL;
    }

    /* Try to dial back one of the provided addresses */
    uint8_t *success_addr = NULL;
    size_t success_addr_len = 0;
    int dial_success = 0;

    for (size_t i = 0; i < msg.dial.peer.num_addrs && !dial_success; i++)
    {
        uint8_t *addr_bytes = msg.dial.peer.addrs[i];
        size_t addr_len = msg.dial.peer.addrs_lens[i];
        if (!addr_bytes || !addr_len)
            continue;

        int ma_err = 0;
        multiaddr_t *ma = multiaddr_new_from_bytes(addr_bytes, addr_len, &ma_err);
        if (!ma)
            continue;

        char *addr_str = multiaddr_to_str(ma, &ma_err);
        multiaddr_free(ma);
        if (!addr_str)
            continue;

        /* Skip non-dialable addresses */
        if (!is_dialable_addr(addr_str))
        {
            fprintf(stderr, "[AUTONAT] skipping non-dialable addr: %s\n", addr_str);
            free(addr_str);
            continue;
        }

        fprintf(stderr, "[AUTONAT] attempting dial-back to %s\n", addr_str);

        /* Attempt to dial with a short timeout */
        libp2p_stream_t *ds = NULL;
        int rc = libp2p_host_dial_protocol_blocking(host, addr_str, "/ipfs/id/1.0.0",
                                                     svc->opts.dial_timeout_ms, &ds);
        if (rc == 0 && ds)
        {
            fprintf(stderr, "[AUTONAT] dial-back SUCCESS to %s\n", addr_str);
            dial_success = 1;
            success_addr = (uint8_t *)malloc(addr_len);
            if (success_addr)
            {
                memcpy(success_addr, addr_bytes, addr_len);
                success_addr_len = addr_len;
            }
            libp2p_stream_close(ds);
            libp2p_stream_free(ds);
        }
        else
        {
            fprintf(stderr, "[AUTONAT] dial-back FAILED to %s (rc=%d)\n", addr_str, rc);
        }
        free(addr_str);
    }

    /* Send response */
    pb_buf_t out = {0};
    if (dial_success)
    {
        encode_dial_response(&out, LIBP2P_AUTONAT_STATUS_OK, NULL, success_addr, success_addr_len);
    }
    else
    {
        encode_dial_response(&out, LIBP2P_AUTONAT_STATUS_E_DIAL_ERROR, "all addresses unreachable", NULL, 0);
    }

    if (out.buf && out.len)
        (void)libp2p_lp_send(s, out.buf, out.len);
    free(out.buf);
    free(success_addr);
    autonat_message_free(&msg);
    libp2p_stream_close(s);
    libp2p__stream_release_async(s);
    if (host)
        libp2p__worker_dec(host);
    return NULL;
}

static void autonat_on_open(libp2p_stream_t *s, void *ud)
{
    libp2p_autonat_service_t *svc = (libp2p_autonat_service_t *)ud;
    if (!s || !svc)
    {
        if (s)
        {
            libp2p_stream_close(s);
            libp2p_stream_free(s);
        }
        return;
    }

    if (!svc->opts.enable_service)
    {
        libp2p_stream_close(s);
        libp2p_stream_free(s);
        return;
    }

    autonat_server_ctx_t *ctx = (autonat_server_ctx_t *)calloc(1, sizeof(*ctx));
    if (!ctx)
    {
        libp2p_stream_close(s);
        libp2p_stream_free(s);
        return;
    }
    ctx->s = s;
    ctx->svc = svc;

    if (!libp2p__stream_retain_async(s))
    {
        free(ctx);
        libp2p_stream_close(s);
        libp2p_stream_free(s);
        return;
    }

    if (svc->host)
        libp2p__worker_inc(svc->host);

    pthread_t th;
    if (pthread_create(&th, NULL, autonat_server_worker, ctx) == 0)
    {
        pthread_detach(th);
        return;
    }

    if (svc->host)
        libp2p__worker_dec(svc->host);
    libp2p__stream_release_async(s);
    free(ctx);
    libp2p_stream_close(s);
    libp2p_stream_free(s);
}

/* ----------------------- client-side: probing ----------------------- */

static void notify_reachability_change(libp2p_autonat_service_t *svc,
                                        libp2p_autonat_reachability_t old_status,
                                        libp2p_autonat_reachability_t new_status,
                                        const char *public_addr)
{
    reachability_cb_node_t *cb = svc->callbacks;
    while (cb)
    {
        if (cb->cb)
            cb->cb(old_status, new_status, public_addr, cb->user_data);
        cb = cb->next;
    }

    /* Also emit event */
    if (new_status == LIBP2P_AUTONAT_REACHABILITY_PUBLIC && public_addr)
    {
        libp2p_event_t evt = {0};
        evt.kind = LIBP2P_EVT_EXTERNAL_ADDR_CONFIRMED;
        evt.u.external_addr_confirmed.addr = public_addr;
        libp2p_event_publish(svc->host, &evt);
    }
}

static int do_probe_peer(libp2p_autonat_service_t *svc, const peer_id_t *peer,
                          const char *peer_addr, const char *const *our_addrs, size_t num_addrs,
                          libp2p_autonat_dial_result_t *result)
{
    if (!svc || !peer || !peer_addr || !result)
        return LIBP2P_ERR_NULL_PTR;

    memset(result, 0, sizeof(*result));

    /* Open stream to peer */
    libp2p_stream_t *s = NULL;
    int rc = libp2p_host_dial_protocol_blocking(svc->host, peer_addr, LIBP2P_AUTONAT_PROTO_ID,
                                                 svc->opts.dial_timeout_ms, &s);
    if (rc != 0 || !s)
    {
        result->status = LIBP2P_AUTONAT_STATUS_E_INTERNAL_ERROR;
        return rc != 0 ? rc : LIBP2P_ERR_INTERNAL;
    }

    /* Encode and send dial request */
    pb_buf_t msg = {0};
    const peer_id_t *local_peer = svc->host->have_identity ? &svc->host->local_peer : NULL;
    if (encode_dial_request(&msg, local_peer, our_addrs, num_addrs) != 0 || !msg.buf || !msg.len)
    {
        free(msg.buf);
        libp2p_stream_close(s);
        libp2p_stream_free(s);
        result->status = LIBP2P_AUTONAT_STATUS_E_INTERNAL_ERROR;
        return LIBP2P_ERR_INTERNAL;
    }

    ssize_t sent = libp2p_lp_send(s, msg.buf, msg.len);
    free(msg.buf);
    if (sent < 0)
    {
        libp2p_stream_close(s);
        libp2p_stream_free(s);
        result->status = LIBP2P_AUTONAT_STATUS_E_INTERNAL_ERROR;
        return LIBP2P_ERR_INTERNAL;
    }

    /* Read response */
    uint8_t buf[AUTONAT_MAX_MSG_SIZE];
    ssize_t n = libp2p_lp_recv(s, buf, sizeof(buf));
    libp2p_stream_close(s);
    libp2p_stream_free(s);

    if (n <= 0)
    {
        result->status = LIBP2P_AUTONAT_STATUS_E_INTERNAL_ERROR;
        return LIBP2P_ERR_EOF;
    }

    autonat_message_t resp;
    if (parse_autonat_message(buf, (size_t)n, &resp) != 0 || !resp.type_set ||
        resp.type != AUTONAT_MSG_DIAL_RESPONSE || !resp.dial_response.status_set)
    {
        autonat_message_free(&resp);
        result->status = LIBP2P_AUTONAT_STATUS_E_BAD_REQUEST;
        return LIBP2P_ERR_INTERNAL;
    }

    result->status = resp.dial_response.status;
    if (resp.dial_response.status_text)
        result->status_text = strdup(resp.dial_response.status_text);

    if (resp.dial_response.addr && resp.dial_response.addr_len > 0)
    {
        int ma_err = 0;
        multiaddr_t *ma = multiaddr_new_from_bytes(resp.dial_response.addr, resp.dial_response.addr_len, &ma_err);
        if (ma)
        {
            result->addr = multiaddr_to_str(ma, &ma_err);
            multiaddr_free(ma);
        }
    }

    autonat_message_free(&resp);
    return 0;
}

static char **get_our_public_addrs(libp2p_host_t *host, size_t *num_addrs)
{
    *num_addrs = 0;
    if (!host)
        return NULL;

    /* Get listen addresses from peerstore or host */
    const multiaddr_t *const *listen_addrs = NULL;
    size_t num_listen = 0;
    /* For now, use a simple approach - get addresses from internal host state */
    /* This is a simplified implementation */

    /* Allocate array for string addresses */
    size_t cap = 8;
    char **addrs = (char **)calloc(cap, sizeof(char *));
    if (!addrs)
        return NULL;

    /* Get listener addresses */
    pthread_mutex_lock(&host->mtx);
    listener_node_t *ln = host->listeners;
    while (ln)
    {
        if (ln->addr_str && is_dialable_addr(ln->addr_str))
        {
            if (*num_addrs >= cap)
            {
                cap *= 2;
                char **na = (char **)realloc(addrs, cap * sizeof(char *));
                if (!na)
                    break;
                addrs = na;
            }
            addrs[*num_addrs] = strdup(ln->addr_str);
            if (addrs[*num_addrs])
                (*num_addrs)++;
        }
        ln = ln->next;
    }
    pthread_mutex_unlock(&host->mtx);

    if (*num_addrs == 0)
    {
        free(addrs);
        return NULL;
    }
    return addrs;
}

static void free_addr_array(char **addrs, size_t num_addrs)
{
    if (!addrs)
        return;
    for (size_t i = 0; i < num_addrs; i++)
        free(addrs[i]);
    free(addrs);
}

static void *autonat_probe_thread(void *arg)
{
    libp2p_autonat_service_t *svc = (libp2p_autonat_service_t *)arg;
    if (!svc)
        return NULL;

    /* Boot delay */
    usleep((useconds_t)svc->opts.boot_delay_ms * 1000);

    while (!svc->stop_requested)
    {
        pthread_mutex_lock(&svc->mtx);
        int stop = svc->stop_requested;
        pthread_mutex_unlock(&svc->mtx);
        if (stop)
            break;

        /* Get connected peers from peerstore/connmanager */
        /* For simplicity, we'll skip automatic peer discovery and rely on manual probing */
        /* In a full implementation, you would:
         * 1. Get list of connected peers
         * 2. Select a subset to probe
         * 3. Send AutoNAT dial requests
         * 4. Aggregate results to determine reachability
         */

        fprintf(stderr, "[AUTONAT] probe cycle (reachability=%d, success=%d, failure=%d)\n",
                svc->reachability, svc->success_count, svc->failure_count);

        /* Sleep until next probe interval */
        for (int i = 0; i < svc->opts.refresh_interval_ms / 1000 && !svc->stop_requested; i++)
        {
            sleep(1);
        }
    }

    return NULL;
}

/* ----------------------- public API ----------------------- */

void libp2p_autonat_opts_default(libp2p_autonat_opts_t *opts)
{
    if (!opts)
        return;
    memset(opts, 0, sizeof(*opts));
    opts->struct_size = sizeof(*opts);
    opts->enable_service = true;
    opts->dial_timeout_ms = AUTONAT_DEFAULT_DIAL_TIMEOUT_MS;
    opts->throttle_global_max = AUTONAT_DEFAULT_THROTTLE_GLOBAL_MAX;
    opts->throttle_peer_max = AUTONAT_DEFAULT_THROTTLE_PEER_MAX;
    opts->throttle_interval_ms = AUTONAT_DEFAULT_THROTTLE_INTERVAL_MS;
    opts->refresh_interval_ms = AUTONAT_DEFAULT_REFRESH_INTERVAL_MS;
    opts->boot_delay_ms = AUTONAT_DEFAULT_BOOT_DELAY_MS;
    opts->min_peers_required = AUTONAT_DEFAULT_MIN_PEERS;
    opts->min_confirmations = AUTONAT_DEFAULT_MIN_CONFIRMATIONS;
}

int libp2p_autonat_new(libp2p_host_t *host, const libp2p_autonat_opts_t *opts, libp2p_autonat_service_t **out)
{
    if (!host || !out)
        return LIBP2P_ERR_NULL_PTR;

    libp2p_autonat_service_t *svc = (libp2p_autonat_service_t *)calloc(1, sizeof(*svc));
    if (!svc)
        return LIBP2P_ERR_INTERNAL;

    svc->host = host;
    if (opts && opts->struct_size == sizeof(*opts))
        svc->opts = *opts;
    else
        libp2p_autonat_opts_default(&svc->opts);

    pthread_mutex_init(&svc->mtx, NULL);
    svc->reachability = LIBP2P_AUTONAT_REACHABILITY_UNKNOWN;
    svc->global_reset_time = now_mono_ms() + (uint64_t)svc->opts.throttle_interval_ms;

    /* Register protocol handler */
    libp2p_protocol_def_t def = {0};
    def.protocol_id = LIBP2P_AUTONAT_PROTO_ID;
    def.read_mode = LIBP2P_READ_PULL;
    def.on_open = autonat_on_open;
    def.user_data = svc;
    int rc = libp2p_register_protocol(host, &def);
    if (rc != 0)
    {
        pthread_mutex_destroy(&svc->mtx);
        free(svc);
        return rc;
    }

    fprintf(stderr, "[AUTONAT] registered protocol handler: %s\n", LIBP2P_AUTONAT_PROTO_ID);

    *out = svc;
    return 0;
}

int libp2p_autonat_start(libp2p_autonat_service_t *svc)
{
    if (!svc)
        return LIBP2P_ERR_NULL_PTR;

    pthread_mutex_lock(&svc->mtx);
    if (svc->probe_thread_started)
    {
        pthread_mutex_unlock(&svc->mtx);
        return 0;
    }
    svc->stop_requested = 0;
    pthread_mutex_unlock(&svc->mtx);

    if (pthread_create(&svc->probe_thread, NULL, autonat_probe_thread, svc) != 0)
        return LIBP2P_ERR_INTERNAL;

    svc->probe_thread_started = 1;
    fprintf(stderr, "[AUTONAT] started probe thread\n");
    return 0;
}

int libp2p_autonat_stop(libp2p_autonat_service_t *svc)
{
    if (!svc)
        return LIBP2P_ERR_NULL_PTR;

    pthread_mutex_lock(&svc->mtx);
    svc->stop_requested = 1;
    pthread_mutex_unlock(&svc->mtx);

    if (svc->probe_thread_started)
    {
        pthread_join(svc->probe_thread, NULL);
        svc->probe_thread_started = 0;
    }

    fprintf(stderr, "[AUTONAT] stopped\n");
    return 0;
}

void libp2p_autonat_free(libp2p_autonat_service_t *svc)
{
    if (!svc)
        return;

    libp2p_autonat_stop(svc);
    libp2p_unregister_protocol(svc->host, LIBP2P_AUTONAT_PROTO_ID);

    /* Free throttle entries */
    throttle_entry_t *te = svc->peer_throttle;
    while (te)
    {
        throttle_entry_t *next = te->next;
        peer_id_destroy(&te->peer);
        free(te);
        te = next;
    }

    /* Free callbacks */
    reachability_cb_node_t *cb = svc->callbacks;
    while (cb)
    {
        reachability_cb_node_t *next = cb->next;
        free(cb);
        cb = next;
    }

    free(svc->public_addr);
    pthread_mutex_destroy(&svc->mtx);
    free(svc);
}

libp2p_autonat_reachability_t libp2p_autonat_get_reachability(libp2p_autonat_service_t *svc)
{
    if (!svc)
        return LIBP2P_AUTONAT_REACHABILITY_UNKNOWN;
    pthread_mutex_lock(&svc->mtx);
    libp2p_autonat_reachability_t r = svc->reachability;
    pthread_mutex_unlock(&svc->mtx);
    return r;
}

int libp2p_autonat_get_public_addr(libp2p_autonat_service_t *svc, char *out_addr, size_t out_len)
{
    if (!svc || !out_addr || out_len == 0)
        return LIBP2P_ERR_NULL_PTR;

    pthread_mutex_lock(&svc->mtx);
    if (svc->reachability != LIBP2P_AUTONAT_REACHABILITY_PUBLIC || !svc->public_addr)
    {
        pthread_mutex_unlock(&svc->mtx);
        return LIBP2P_ERR_INTERNAL;
    }
    size_t len = strlen(svc->public_addr);
    if (len >= out_len)
    {
        pthread_mutex_unlock(&svc->mtx);
        return LIBP2P_ERR_INTERNAL;
    }
    memcpy(out_addr, svc->public_addr, len + 1);
    pthread_mutex_unlock(&svc->mtx);
    return 0;
}

int libp2p_autonat_on_reachability_changed(libp2p_autonat_service_t *svc,
                                            libp2p_autonat_reachability_cb cb,
                                            void *user_data)
{
    if (!svc || !cb)
        return LIBP2P_ERR_NULL_PTR;

    reachability_cb_node_t *node = (reachability_cb_node_t *)calloc(1, sizeof(*node));
    if (!node)
        return LIBP2P_ERR_INTERNAL;

    node->cb = cb;
    node->user_data = user_data;

    pthread_mutex_lock(&svc->mtx);
    node->next = svc->callbacks;
    svc->callbacks = node;
    pthread_mutex_unlock(&svc->mtx);

    return 0;
}

int libp2p_autonat_probe_peer(libp2p_autonat_service_t *svc, const peer_id_t *peer,
                               const char *const *addrs, size_t num_addrs, int timeout_ms,
                               libp2p_autonat_dial_result_t *result)
{
    if (!svc || !peer || !result)
        return LIBP2P_ERR_NULL_PTR;

    /* Get our addresses to send */
    size_t our_num = 0;
    char **our_addrs = get_our_public_addrs(svc->host, &our_num);
    if (!our_addrs || our_num == 0)
    {
        free_addr_array(our_addrs, our_num);
        result->status = LIBP2P_AUTONAT_STATUS_E_INTERNAL_ERROR;
        result->status_text = strdup("no dialable addresses");
        return LIBP2P_ERR_INTERNAL;
    }

    /* Find an address for the peer */
    const char *peer_addr = (addrs && num_addrs > 0) ? addrs[0] : NULL;
    if (!peer_addr)
    {
        /* Try to get from peerstore */
        if (svc->host->peerstore)
        {
            const multiaddr_t **ps_addrs = NULL;
            size_t ps_num = 0;
            if (libp2p_peerstore_get_addrs(svc->host->peerstore, peer, &ps_addrs, &ps_num) == 0 && ps_num > 0)
            {
                int ma_err = 0;
                char *a = multiaddr_to_str(ps_addrs[0], &ma_err);
                if (a)
                {
                    int rc = do_probe_peer(svc, peer, a, (const char *const *)our_addrs, our_num, result);
                    free(a);
                    free_addr_array(our_addrs, our_num);

                    /* Update reachability state */
                    pthread_mutex_lock(&svc->mtx);
                    libp2p_autonat_reachability_t old = svc->reachability;
                    if (result->status == LIBP2P_AUTONAT_STATUS_OK)
                    {
                        svc->success_count++;
                        svc->failure_count = 0;
                        if (svc->success_count >= svc->opts.min_confirmations)
                        {
                            svc->reachability = LIBP2P_AUTONAT_REACHABILITY_PUBLIC;
                            free(svc->public_addr);
                            svc->public_addr = result->addr ? strdup(result->addr) : NULL;
                        }
                    }
                    else if (result->status == LIBP2P_AUTONAT_STATUS_E_DIAL_ERROR)
                    {
                        svc->failure_count++;
                        svc->success_count = 0;
                        if (svc->failure_count >= svc->opts.min_confirmations)
                        {
                            svc->reachability = LIBP2P_AUTONAT_REACHABILITY_PRIVATE;
                            free(svc->public_addr);
                            svc->public_addr = NULL;
                        }
                    }
                    libp2p_autonat_reachability_t new = svc->reachability;
                    pthread_mutex_unlock(&svc->mtx);

                    if (old != new)
                        notify_reachability_change(svc, old, new, svc->public_addr);

                    return rc;
                }
            }
        }
        free_addr_array(our_addrs, our_num);
        result->status = LIBP2P_AUTONAT_STATUS_E_INTERNAL_ERROR;
        result->status_text = strdup("no peer address");
        return LIBP2P_ERR_INTERNAL;
    }

    int rc = do_probe_peer(svc, peer, peer_addr, (const char *const *)our_addrs, our_num, result);
    free_addr_array(our_addrs, our_num);

    /* Update reachability state */
    pthread_mutex_lock(&svc->mtx);
    libp2p_autonat_reachability_t old = svc->reachability;
    if (result->status == LIBP2P_AUTONAT_STATUS_OK)
    {
        svc->success_count++;
        svc->failure_count = 0;
        if (svc->success_count >= svc->opts.min_confirmations)
        {
            svc->reachability = LIBP2P_AUTONAT_REACHABILITY_PUBLIC;
            free(svc->public_addr);
            svc->public_addr = result->addr ? strdup(result->addr) : NULL;
        }
    }
    else if (result->status == LIBP2P_AUTONAT_STATUS_E_DIAL_ERROR)
    {
        svc->failure_count++;
        svc->success_count = 0;
        if (svc->failure_count >= svc->opts.min_confirmations)
        {
            svc->reachability = LIBP2P_AUTONAT_REACHABILITY_PRIVATE;
            free(svc->public_addr);
            svc->public_addr = NULL;
        }
    }
    libp2p_autonat_reachability_t new = svc->reachability;
    pthread_mutex_unlock(&svc->mtx);

    if (old != new)
        notify_reachability_change(svc, old, new, svc->public_addr);

    return rc;
}

int libp2p_autonat_force_probe(libp2p_autonat_service_t *svc)
{
    if (!svc)
        return LIBP2P_ERR_NULL_PTR;
    /* Signal the probe thread to run immediately (simplified: just log) */
    fprintf(stderr, "[AUTONAT] force probe requested\n");
    return 0;
}
