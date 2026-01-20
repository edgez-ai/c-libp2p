/**
 * AutoNAT v2 implementation for libp2p.
 *
 * AutoNAT v2 allows a node to discover whether specific addresses are publicly
 * reachable by requesting dial-backs from other peers with nonce verification.
 *
 * Protocols:
 *   /libp2p/autonat/2/dial-request - Client sends dial request, server responds
 *   /libp2p/autonat/2/dial-back    - Server dials back with nonce verification
 *
 * Message format (protobuf):
 *   message Message {
 *     oneof msg {
 *       DialRequest dialRequest = 1;
 *       DialResponse dialResponse = 2;
 *       DialDataRequest dialDataRequest = 3;
 *       DialDataResponse dialDataResponse = 4;
 *     }
 *   }
 *
 *   message DialRequest {
 *     repeated bytes addrs = 1;
 *     fixed64 nonce = 2;
 *   }
 *
 *   message DialDataRequest {
 *     uint32 addrIdx = 1;
 *     uint64 numBytes = 2;
 *   }
 *
 *   message DialResponse {
 *     ResponseStatus status = 1;
 *     uint32 addrIdx = 2;
 *     DialStatus dialStatus = 3;
 *   }
 *
 *   message DialBack {
 *     fixed64 nonce = 1;
 *   }
 *
 *   message DialBackResponse {
 *     DialBackStatus status = 1;
 *   }
 */

#include "libp2p/autonat.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "host_internal.h"
#include "libp2p/errors.h"
#include "libp2p/events.h"
#include "libp2p/log.h"
#include "libp2p/lpmsg.h"
#include "libp2p/peerstore.h"
#include "libp2p/protocol.h"
#include "libp2p/stream.h"
#include "libp2p/stream_internal.h"
#include "libp2p/dial.h"
#include "multiformats/multiaddr/multiaddr.h"
#include "multiformats/unsigned_varint/unsigned_varint.h"
#include "peer_id/peer_id.h"

/* Protocol IDs */
#define AUTONAT_V2_DIAL_REQUEST_PROTO "/libp2p/autonat/2/dial-request"
#define AUTONAT_V2_DIAL_BACK_PROTO    "/libp2p/autonat/2/dial-back"

/* Constants */
#define AUTONAT_V2_MAX_MSG_SIZE 4096
#define AUTONAT_V2_MAX_ADDRS 16
#define AUTONAT_V2_DIAL_TIMEOUT_MS 10000
#define AUTONAT_V2_DIAL_DATA_MIN_BYTES 30000  /* 30KB for amplification prevention */
#define AUTONAT_V2_DIAL_DATA_MAX_BYTES 100000 /* 100KB max */
#define AUTONAT_V2_DIAL_DATA_CHUNK_SIZE 4096

/* DialStatus enum values */
typedef enum {
    AUTONAT_V2_DIAL_STATUS_UNUSED = 0,
    AUTONAT_V2_DIAL_STATUS_E_DIAL_ERROR = 100,
    AUTONAT_V2_DIAL_STATUS_E_DIAL_BACK_ERROR = 101,
    AUTONAT_V2_DIAL_STATUS_OK = 200
} autonat_v2_dial_status_t;

/* ResponseStatus enum values */
typedef enum {
    AUTONAT_V2_RESPONSE_E_INTERNAL_ERROR = 0,
    AUTONAT_V2_RESPONSE_E_REQUEST_REJECTED = 100,
    AUTONAT_V2_RESPONSE_E_DIAL_REFUSED = 101,
    AUTONAT_V2_RESPONSE_OK = 200
} autonat_v2_response_status_t;

/* DialBackStatus enum values */
typedef enum {
    AUTONAT_V2_DIAL_BACK_STATUS_OK = 0
} autonat_v2_dial_back_status_t;

/* Message type field numbers (for oneof) */
#define MSG_FIELD_DIAL_REQUEST 1
#define MSG_FIELD_DIAL_RESPONSE 2
#define MSG_FIELD_DIAL_DATA_REQUEST 3
#define MSG_FIELD_DIAL_DATA_RESPONSE 4

/* Parsed DialRequest */
typedef struct {
    char **addrs;
    size_t num_addrs;
    uint64_t nonce;
} dial_request_t;

/* Parsed DialResponse */
typedef struct {
    autonat_v2_response_status_t status;
    uint32_t addr_idx;
    autonat_v2_dial_status_t dial_status;
} dial_response_t;

/* Parsed DialDataRequest */
typedef struct {
    uint32_t addr_idx;
    uint64_t num_bytes;
} dial_data_request_t;

/* Parsed DialBack */
typedef struct {
    uint64_t nonce;
} dial_back_t;

/* Observed address node */
typedef struct observed_addr_node {
    char *addr;
    struct observed_addr_node *next;
} observed_addr_node_t;

#define AUTONAT_MAX_OBSERVED_ADDRS 16

/* Pending dial-back tracking for client */
typedef struct pending_dial_back {
    uint64_t nonce;
    int received;
    char *received_addr;  /* Local addr where dial-back was received */
    pthread_mutex_t mtx;
    pthread_cond_t cv;
    struct pending_dial_back *next;
} pending_dial_back_t;

/* Service state */
struct libp2p_autonat_service {
    libp2p_host_t *host;
    libp2p_autonat_opts_t opts;
    
    /* Reachability state */
    libp2p_autonat_reachability_t reachability;
    char *public_addr;
    int success_count;
    int failure_count;
    
    /* Callbacks */
    libp2p_autonat_reachability_cb reachability_cb;
    void *reachability_cb_user_data;
    
    /* Observed addresses (external addresses as seen by peers) */
    observed_addr_node_t *observed_addrs;
    size_t num_observed_addrs;
    
    /* Pending dial-backs (client side) */
    pending_dial_back_t *pending_dial_backs;
    pthread_mutex_t pending_mtx;
    
    /* Event subscription for address discovery */
    struct libp2p_subscription *event_sub;
    
    /* Probe thread */
    pthread_t probe_thread;
    int probe_running;
    int stop_requested;
    
    /* Throttling (server side) */
    int global_dialback_count;
    uint64_t global_reset_time;
    
    pthread_mutex_t mtx;
};

/* Forward declaration */
static void autonat_event_handler(const libp2p_event_t *evt, void *user_data);

/* ----------------------- protobuf helpers ----------------------- */

typedef struct {
    uint8_t *buf;
    size_t len;
    size_t cap;
} pb_buf_t;

static int pb_buf_reserve(pb_buf_t *b, size_t extra)
{
    if (!b) return -1;
    size_t need = b->len + extra;
    if (need <= b->cap) return 0;
    size_t newcap = b->cap ? b->cap : 64;
    while (newcap < need) newcap *= 2;
    uint8_t *nb = (uint8_t *)realloc(b->buf, newcap);
    if (!nb) return -1;
    b->buf = nb;
    b->cap = newcap;
    return 0;
}

static int pb_buf_append(pb_buf_t *b, const uint8_t *data, size_t len)
{
    if (!b || !data) return -1;
    if (pb_buf_reserve(b, len) != 0) return -1;
    memcpy(b->buf + b->len, data, len);
    b->len += len;
    return 0;
}

static int pb_buf_append_varint(pb_buf_t *b, uint64_t v)
{
    uint8_t tmp[10];
    size_t written = 0;
    if (unsigned_varint_encode(v, tmp, sizeof(tmp), &written) != UNSIGNED_VARINT_OK)
        return -1;
    return pb_buf_append(b, tmp, written);
}

static int pb_buf_append_key(pb_buf_t *b, uint64_t field, uint64_t wire_type)
{
    return pb_buf_append_varint(b, (field << 3) | wire_type);
}

static int pb_buf_append_bytes(pb_buf_t *b, const uint8_t *data, size_t len)
{
    if (pb_buf_append_varint(b, (uint64_t)len) != 0) return -1;
    return pb_buf_append(b, data, len);
}

static int pb_buf_append_fixed64(pb_buf_t *b, uint64_t v)
{
    uint8_t tmp[8];
    for (int i = 0; i < 8; i++) {
        tmp[i] = (uint8_t)(v & 0xFF);
        v >>= 8;
    }
    return pb_buf_append(b, tmp, 8);
}

static int pb_read_varint(const uint8_t *buf, size_t len, size_t *off, uint64_t *out)
{
    if (!buf || !off || !out || *off >= len) return -1;
    uint64_t val = 0;
    int shift = 0;
    while (*off < len && shift < 64) {
        uint8_t byte = buf[(*off)++];
        val |= ((uint64_t)(byte & 0x7F)) << shift;
        if ((byte & 0x80) == 0) {
            *out = val;
            return 0;
        }
        shift += 7;
    }
    return -1;
}

static int pb_read_fixed64(const uint8_t *buf, size_t len, size_t *off, uint64_t *out)
{
    if (!buf || !off || !out || *off + 8 > len) return -1;
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v |= ((uint64_t)buf[*off + i]) << (i * 8);
    }
    *off += 8;
    *out = v;
    return 0;
}

static int pb_skip_field(const uint8_t *buf, size_t len, size_t *off, uint64_t wire_type)
{
    switch (wire_type) {
        case 0: { /* varint */
            uint64_t dummy;
            return pb_read_varint(buf, len, off, &dummy);
        }
        case 1: /* fixed64 */
            if (*off + 8 > len) return -1;
            *off += 8;
            return 0;
        case 2: { /* length-delimited */
            uint64_t slen;
            if (pb_read_varint(buf, len, off, &slen) != 0) return -1;
            if (*off + slen > len) return -1;
            *off += slen;
            return 0;
        }
        case 5: /* fixed32 */
            if (*off + 4 > len) return -1;
            *off += 4;
            return 0;
        default:
            return -1;
    }
}

/* ----------------------- message encoding ----------------------- */

/* Encode DialRequest message wrapped in Message */
static int encode_dial_request(pb_buf_t *out, const char *const *addrs, size_t num_addrs, uint64_t nonce)
{
    if (!out) return -1;
    
    /* First build the inner DialRequest */
    pb_buf_t inner = {0};
    
    /* addrs (field 1, bytes, repeated) */
    for (size_t i = 0; i < num_addrs; i++) {
        if (!addrs[i]) continue;
        int ma_err = 0;
        multiaddr_t *ma = multiaddr_new_from_str(addrs[i], &ma_err);
        if (!ma) continue;
        uint8_t ma_bytes[256];
        int blen = multiaddr_get_bytes(ma, ma_bytes, sizeof(ma_bytes));
        multiaddr_free(ma);
        if (blen > 0) {
            if (pb_buf_append_key(&inner, 1, 2) != 0) goto err;
            if (pb_buf_append_bytes(&inner, ma_bytes, (size_t)blen) != 0) goto err;
        }
    }
    
    /* nonce (field 2, fixed64) */
    if (pb_buf_append_key(&inner, 2, 1) != 0) goto err;
    if (pb_buf_append_fixed64(&inner, nonce) != 0) goto err;
    
    /* Wrap in Message (field 1 = dialRequest) */
    if (pb_buf_append_key(out, MSG_FIELD_DIAL_REQUEST, 2) != 0) goto err;
    if (pb_buf_append_bytes(out, inner.buf, inner.len) != 0) goto err;
    
    free(inner.buf);
    return 0;
    
err:
    free(inner.buf);
    return -1;
}

/* Encode DialResponse message wrapped in Message */
static int encode_dial_response(pb_buf_t *out, autonat_v2_response_status_t status, 
                                 uint32_t addr_idx, autonat_v2_dial_status_t dial_status)
{
    if (!out) return -1;
    
    pb_buf_t inner = {0};
    
    /* status (field 1, varint) */
    if (pb_buf_append_key(&inner, 1, 0) != 0) goto err;
    if (pb_buf_append_varint(&inner, (uint64_t)status) != 0) goto err;
    
    /* addrIdx (field 2, varint) */
    if (pb_buf_append_key(&inner, 2, 0) != 0) goto err;
    if (pb_buf_append_varint(&inner, (uint64_t)addr_idx) != 0) goto err;
    
    /* dialStatus (field 3, varint) */
    if (pb_buf_append_key(&inner, 3, 0) != 0) goto err;
    if (pb_buf_append_varint(&inner, (uint64_t)dial_status) != 0) goto err;
    
    /* Wrap in Message (field 2 = dialResponse) */
    if (pb_buf_append_key(out, MSG_FIELD_DIAL_RESPONSE, 2) != 0) goto err;
    if (pb_buf_append_bytes(out, inner.buf, inner.len) != 0) goto err;
    
    free(inner.buf);
    return 0;
    
err:
    free(inner.buf);
    return -1;
}

/* Encode DialDataRequest message wrapped in Message */
static int encode_dial_data_request(pb_buf_t *out, uint32_t addr_idx, uint64_t num_bytes)
{
    if (!out) return -1;
    
    pb_buf_t inner = {0};
    
    /* addrIdx (field 1, varint) */
    if (pb_buf_append_key(&inner, 1, 0) != 0) goto err;
    if (pb_buf_append_varint(&inner, (uint64_t)addr_idx) != 0) goto err;
    
    /* numBytes (field 2, varint) */
    if (pb_buf_append_key(&inner, 2, 0) != 0) goto err;
    if (pb_buf_append_varint(&inner, num_bytes) != 0) goto err;
    
    /* Wrap in Message (field 3 = dialDataRequest) */
    if (pb_buf_append_key(out, MSG_FIELD_DIAL_DATA_REQUEST, 2) != 0) goto err;
    if (pb_buf_append_bytes(out, inner.buf, inner.len) != 0) goto err;
    
    free(inner.buf);
    return 0;
    
err:
    free(inner.buf);
    return -1;
}

/* Encode DialDataResponse message wrapped in Message */
static int encode_dial_data_response(pb_buf_t *out, const uint8_t *data, size_t len)
{
    if (!out) return -1;
    
    pb_buf_t inner = {0};
    
    /* data (field 1, bytes) */
    if (pb_buf_append_key(&inner, 1, 2) != 0) goto err;
    if (pb_buf_append_bytes(&inner, data, len) != 0) goto err;
    
    /* Wrap in Message (field 4 = dialDataResponse) */
    if (pb_buf_append_key(out, MSG_FIELD_DIAL_DATA_RESPONSE, 2) != 0) goto err;
    if (pb_buf_append_bytes(out, inner.buf, inner.len) != 0) goto err;
    
    free(inner.buf);
    return 0;
    
err:
    free(inner.buf);
    return -1;
}

/* Encode DialBack message (sent on dial-back stream, not wrapped in Message) */
static int encode_dial_back(pb_buf_t *out, uint64_t nonce)
{
    if (!out) return -1;
    
    /* nonce (field 1, fixed64) */
    if (pb_buf_append_key(out, 1, 1) != 0) return -1;
    if (pb_buf_append_fixed64(out, nonce) != 0) return -1;
    
    return 0;
}

/* Encode DialBackResponse message */
static int encode_dial_back_response(pb_buf_t *out, autonat_v2_dial_back_status_t status)
{
    if (!out) return -1;
    
    /* status (field 1, varint) */
    if (pb_buf_append_key(out, 1, 0) != 0) return -1;
    if (pb_buf_append_varint(out, (uint64_t)status) != 0) return -1;
    
    return 0;
}

/* ----------------------- message decoding ----------------------- */

static void free_dial_request(dial_request_t *req)
{
    if (!req) return;
    for (size_t i = 0; i < req->num_addrs; i++)
        free(req->addrs[i]);
    free(req->addrs);
    req->addrs = NULL;
    req->num_addrs = 0;
}

/* Parse DialRequest from inner bytes */
static int parse_dial_request(const uint8_t *buf, size_t len, dial_request_t *out)
{
    if (!buf || !out) return -1;
    memset(out, 0, sizeof(*out));
    
    size_t off = 0;
    size_t addr_cap = 0;
    
    while (off < len) {
        uint64_t key = 0;
        if (pb_read_varint(buf, len, &off, &key) != 0) goto err;
        uint64_t field = key >> 3;
        uint64_t wire = key & 0x7;
        
        if (field == 1 && wire == 2) {
            /* addrs (bytes) */
            uint64_t slen;
            if (pb_read_varint(buf, len, &off, &slen) != 0) goto err;
            if (off + slen > len) goto err;
            
            /* Parse multiaddr bytes to string */
            int ma_err = 0;
            multiaddr_t *ma = multiaddr_new_from_bytes(buf + off, (size_t)slen, &ma_err);
            off += slen;
            if (!ma) continue;
            
            char *addr_str = multiaddr_to_str(ma, &ma_err);
            multiaddr_free(ma);
            if (!addr_str) continue;
            
            /* Add to array */
            if (out->num_addrs >= addr_cap) {
                size_t new_cap = addr_cap ? addr_cap * 2 : 8;
                char **new_addrs = (char **)realloc(out->addrs, new_cap * sizeof(char *));
                if (!new_addrs) { free(addr_str); goto err; }
                out->addrs = new_addrs;
                addr_cap = new_cap;
            }
            out->addrs[out->num_addrs++] = addr_str;
        }
        else if (field == 2 && wire == 1) {
            /* nonce (fixed64) */
            if (pb_read_fixed64(buf, len, &off, &out->nonce) != 0) goto err;
        }
        else {
            if (pb_skip_field(buf, len, &off, wire) != 0) goto err;
        }
    }
    return 0;
    
err:
    free_dial_request(out);
    return -1;
}

/* Parse DialResponse from inner bytes */
static int parse_dial_response(const uint8_t *buf, size_t len, dial_response_t *out)
{
    if (!buf || !out) return -1;
    memset(out, 0, sizeof(*out));
    
    size_t off = 0;
    while (off < len) {
        uint64_t key = 0;
        if (pb_read_varint(buf, len, &off, &key) != 0) return -1;
        uint64_t field = key >> 3;
        uint64_t wire = key & 0x7;
        
        if (field == 1 && wire == 0) {
            uint64_t v;
            if (pb_read_varint(buf, len, &off, &v) != 0) return -1;
            out->status = (autonat_v2_response_status_t)v;
        }
        else if (field == 2 && wire == 0) {
            uint64_t v;
            if (pb_read_varint(buf, len, &off, &v) != 0) return -1;
            out->addr_idx = (uint32_t)v;
        }
        else if (field == 3 && wire == 0) {
            uint64_t v;
            if (pb_read_varint(buf, len, &off, &v) != 0) return -1;
            out->dial_status = (autonat_v2_dial_status_t)v;
        }
        else {
            if (pb_skip_field(buf, len, &off, wire) != 0) return -1;
        }
    }
    return 0;
}

/* Parse DialDataRequest from inner bytes */
static int parse_dial_data_request(const uint8_t *buf, size_t len, dial_data_request_t *out)
{
    if (!buf || !out) return -1;
    memset(out, 0, sizeof(*out));
    
    size_t off = 0;
    while (off < len) {
        uint64_t key = 0;
        if (pb_read_varint(buf, len, &off, &key) != 0) return -1;
        uint64_t field = key >> 3;
        uint64_t wire = key & 0x7;
        
        if (field == 1 && wire == 0) {
            uint64_t v;
            if (pb_read_varint(buf, len, &off, &v) != 0) return -1;
            out->addr_idx = (uint32_t)v;
        }
        else if (field == 2 && wire == 0) {
            if (pb_read_varint(buf, len, &off, &out->num_bytes) != 0) return -1;
        }
        else {
            if (pb_skip_field(buf, len, &off, wire) != 0) return -1;
        }
    }
    return 0;
}

/* Parse DialBack message */
static int parse_dial_back(const uint8_t *buf, size_t len, dial_back_t *out)
{
    if (!buf || !out) return -1;
    memset(out, 0, sizeof(*out));
    
    size_t off = 0;
    while (off < len) {
        uint64_t key = 0;
        if (pb_read_varint(buf, len, &off, &key) != 0) return -1;
        uint64_t field = key >> 3;
        uint64_t wire = key & 0x7;
        
        if (field == 1 && wire == 1) {
            if (pb_read_fixed64(buf, len, &off, &out->nonce) != 0) return -1;
        }
        else {
            if (pb_skip_field(buf, len, &off, wire) != 0) return -1;
        }
    }
    return 0;
}

/* Parse Message wrapper and extract inner message type and bytes */
static int parse_message_wrapper(const uint8_t *buf, size_t len, int *msg_type, 
                                  const uint8_t **inner, size_t *inner_len)
{
    if (!buf || !msg_type || !inner || !inner_len) return -1;
    *msg_type = 0;
    *inner = NULL;
    *inner_len = 0;
    
    size_t off = 0;
    while (off < len) {
        uint64_t key = 0;
        if (pb_read_varint(buf, len, &off, &key) != 0) return -1;
        uint64_t field = key >> 3;
        uint64_t wire = key & 0x7;
        
        if (wire == 2 && field >= 1 && field <= 4) {
            /* This is our oneof field */
            uint64_t slen;
            if (pb_read_varint(buf, len, &off, &slen) != 0) return -1;
            if (off + slen > len) return -1;
            *msg_type = (int)field;
            *inner = buf + off;
            *inner_len = (size_t)slen;
            return 0;
        }
        else {
            if (pb_skip_field(buf, len, &off, wire) != 0) return -1;
        }
    }
    return -1;
}

/* ----------------------- utility functions ----------------------- */

/* Generate random nonce */
static uint64_t generate_nonce(void)
{
    uint64_t nonce = 0;
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        (void)fread(&nonce, sizeof(nonce), 1, f);
        fclose(f);
    }
    if (nonce == 0) {
        /* Fallback */
        nonce = ((uint64_t)rand() << 32) | (uint64_t)rand();
    }
    return nonce;
}

/* Check if address is a private/local address */
static int is_private_addr(const char *addr)
{
    if (!addr) return 1;
    
    /* Check for localhost */
    if (strstr(addr, "/ip4/127.") || strstr(addr, "/ip6/::1"))
        return 1;
    
    /* Check for private IPv4 ranges */
    if (strstr(addr, "/ip4/10.") ||
        strstr(addr, "/ip4/192.168.") ||
        strstr(addr, "/ip4/172.16.") ||
        strstr(addr, "/ip4/172.17.") ||
        strstr(addr, "/ip4/172.18.") ||
        strstr(addr, "/ip4/172.19.") ||
        strstr(addr, "/ip4/172.20.") ||
        strstr(addr, "/ip4/172.21.") ||
        strstr(addr, "/ip4/172.22.") ||
        strstr(addr, "/ip4/172.23.") ||
        strstr(addr, "/ip4/172.24.") ||
        strstr(addr, "/ip4/172.25.") ||
        strstr(addr, "/ip4/172.26.") ||
        strstr(addr, "/ip4/172.27.") ||
        strstr(addr, "/ip4/172.28.") ||
        strstr(addr, "/ip4/172.29.") ||
        strstr(addr, "/ip4/172.30.") ||
        strstr(addr, "/ip4/172.31."))
        return 1;
    
    /* Check for link-local */
    if (strstr(addr, "/ip4/169.254.") || strstr(addr, "/ip6/fe80"))
        return 1;
    
    return 0;
}

/* Extract IP from multiaddr string for comparison */
static char *extract_ip_from_addr(const char *addr)
{
    if (!addr) return NULL;
    
    const char *ip4 = strstr(addr, "/ip4/");
    if (ip4) {
        ip4 += 5;
        const char *end = strchr(ip4, '/');
        size_t len = end ? (size_t)(end - ip4) : strlen(ip4);
        char *ip = (char *)malloc(len + 1);
        if (ip) {
            memcpy(ip, ip4, len);
            ip[len] = '\0';
        }
        return ip;
    }
    
    const char *ip6 = strstr(addr, "/ip6/");
    if (ip6) {
        ip6 += 5;
        const char *end = strchr(ip6, '/');
        size_t len = end ? (size_t)(end - ip6) : strlen(ip6);
        char *ip = (char *)malloc(len + 1);
        if (ip) {
            memcpy(ip, ip6, len);
            ip[len] = '\0';
        }
        return ip;
    }
    
    return NULL;
}

/* Read length-prefixed message from stream with EAGAIN tolerance */
static int read_lp_message(libp2p_stream_t *s, uint8_t *buf, size_t buf_size, size_t *out_len, int timeout_ms)
{
    if (!s || !buf || !out_len) {
        fprintf(stderr, "[AUTONAT-V2] read_lp_message: null params\n");
        return -1;
    }
    
    /* Use monotonic time for timeout tracking */
    struct timespec ts_start;
    clock_gettime(CLOCK_MONOTONIC, &ts_start);
    uint64_t start_ms = (uint64_t)ts_start.tv_sec * 1000 + (uint64_t)ts_start.tv_nsec / 1000000;
    uint64_t deadline_ms = start_ms + (uint64_t)timeout_ms;
    
    fprintf(stderr, "[AUTONAT-V2] read_lp_message: starting read, timeout=%d ms\n", timeout_ms);
    
    /* Read length prefix byte-by-byte with EAGAIN tolerance */
    uint8_t len_buf[10];
    size_t len_bytes = 0;
    uint64_t msg_len = 0;
    int eagain_count = 0;
    
    while (len_bytes < sizeof(len_buf)) {
        struct timespec ts_now;
        clock_gettime(CLOCK_MONOTONIC, &ts_now);
        uint64_t now_ms = (uint64_t)ts_now.tv_sec * 1000 + (uint64_t)ts_now.tv_nsec / 1000000;
        
        if (now_ms >= deadline_ms) {
            fprintf(stderr, "[AUTONAT-V2] read_lp_message: timeout reading length prefix after %d EAGAIN retries\n", eagain_count);
            return -1;
        }
        
        uint64_t remain_ms = deadline_ms - now_ms;
        libp2p_stream_set_deadline(s, remain_ms);
        
        ssize_t got = libp2p_stream_read(s, len_buf + len_bytes, 1);
        if (got == 1) {
            len_bytes++;
            fprintf(stderr, "[AUTONAT-V2] read_lp_message: got len byte %zu, value=0x%02X\n", len_bytes, len_buf[len_bytes - 1]);
            
            if ((len_buf[len_bytes - 1] & 0x80) == 0) {
                /* MSB not set - this is the last varint byte */
                size_t off = 0;
                if (pb_read_varint(len_buf, len_bytes, &off, &msg_len) != 0) {
                    fprintf(stderr, "[AUTONAT-V2] read_lp_message: varint parse failed\n");
                    return -1;
                }
                break;
            }
            continue;
        }
        
        if (got == LIBP2P_ERR_AGAIN) {
            /* No data available yet, wait a bit and retry */
            eagain_count++;
            if (eagain_count % 100 == 0) {
                fprintf(stderr, "[AUTONAT-V2] read_lp_message: EAGAIN count=%d, elapsed=%llu ms\n", 
                        eagain_count, (unsigned long long)(now_ms - start_ms));
            }
            usleep(10000); /* 10ms - increased from 1ms */
            continue;
        }
        
        /* Check for EOF (0 or -3 depending on code path) */
        if (got == 0 || got == LIBP2P_ERR_EOF) {
            fprintf(stderr, "[AUTONAT-V2] read_lp_message: len byte %zu EOF (got=%zd, stream closed by remote, EAGAIN count was %d)\n", 
                    len_bytes, got, eagain_count);
            return -1;
        }
        if (got == LIBP2P_ERR_RESET) {
            fprintf(stderr, "[AUTONAT-V2] read_lp_message: len byte %zu RESET (stream reset by remote)\n", len_bytes);
            return -1;
        }
        
        /* Fatal error */
        fprintf(stderr, "[AUTONAT-V2] read_lp_message: len byte %zu read failed, got=%zd (EAGAIN count was %d)\n", 
                len_bytes, got, eagain_count);
        return -1;
    }
    
    fprintf(stderr, "[AUTONAT-V2] read_lp_message: msg_len=%llu\n", (unsigned long long)msg_len);
    
    if (msg_len == 0 || msg_len > buf_size) {
        fprintf(stderr, "[AUTONAT-V2] read_lp_message: invalid msg_len=%llu (buf_size=%zu)\n", 
                (unsigned long long)msg_len, buf_size);
        return -1;
    }
    
    /* Read message body with EAGAIN tolerance */
    size_t total = 0;
    while (total < msg_len) {
        struct timespec ts_now;
        clock_gettime(CLOCK_MONOTONIC, &ts_now);
        uint64_t now_ms = (uint64_t)ts_now.tv_sec * 1000 + (uint64_t)ts_now.tv_nsec / 1000000;
        
        if (now_ms >= deadline_ms) {
            fprintf(stderr, "[AUTONAT-V2] read_lp_message: timeout reading body at %zu/%llu\n",
                    total, (unsigned long long)msg_len);
            return -1;
        }
        
        uint64_t remain_ms = deadline_ms - now_ms;
        libp2p_stream_set_deadline(s, remain_ms);
        
        ssize_t got = libp2p_stream_read(s, buf + total, msg_len - total);
        if (got > 0) {
            total += (size_t)got;
            continue;
        }
        
        if (got == LIBP2P_ERR_AGAIN) {
            /* No data available yet, wait a bit and retry */
            usleep(1000); /* 1ms */
            continue;
        }
        
        /* Fatal error */
        fprintf(stderr, "[AUTONAT-V2] read_lp_message: body read failed at %zu/%llu, got=%zd\n",
                total, (unsigned long long)msg_len, got);
        return -1;
    }
    
    *out_len = (size_t)msg_len;
    fprintf(stderr, "[AUTONAT-V2] read_lp_message: success, read %zu bytes\n", total);
    return 0;
}

/* Write length-prefixed message to stream with retry handling */
static int write_lp_message(libp2p_stream_t *s, const uint8_t *buf, size_t len)
{
    if (!s || !buf) {
        fprintf(stderr, "[AUTONAT-V2] write_lp_message: null params\n");
        return -1;
    }
    
    /* Encode length prefix */
    uint8_t len_buf[10];
    size_t len_bytes = 0;
    if (unsigned_varint_encode((uint64_t)len, len_buf, sizeof(len_buf), &len_bytes) != UNSIGNED_VARINT_OK) {
        fprintf(stderr, "[AUTONAT-V2] write_lp_message: varint encode failed\n");
        return -1;
    }
    
    fprintf(stderr, "[AUTONAT-V2] write_lp_message: writing %zu bytes (prefix=%zu)\n", len, len_bytes);
    
    /* Write length prefix with retry */
    size_t written_prefix = 0;
    int prefix_retries = 0;
    while (written_prefix < len_bytes) {
        ssize_t n = libp2p_stream_write(s, len_buf + written_prefix, len_bytes - written_prefix);
        if (n > 0) {
            written_prefix += (size_t)n;
        } else if (n == LIBP2P_ERR_AGAIN || n == LIBP2P_ERR_TIMEOUT) {
            /* Retry with short sleep */
            prefix_retries++;
            if (prefix_retries > 100) {
                fprintf(stderr, "[AUTONAT-V2] write_lp_message: prefix write timed out\n");
                return -1;
            }
            usleep(10000);  /* 10ms */
        } else {
            fprintf(stderr, "[AUTONAT-V2] write_lp_message: prefix write failed, n=%zd\n", n);
            return -1;
        }
    }
    
    /* Write body in chunks with retry for flow control */
    const size_t CHUNK_SIZE = 16384; /* 16KB chunks to work with send window */
    size_t written_total = 0;
    int retry_count = 0;
    const int MAX_RETRIES = 200; /* ~10 seconds total with 50ms sleeps */
    
    while (written_total < len) {
        size_t remaining = len - written_total;
        size_t to_write = remaining > CHUNK_SIZE ? CHUNK_SIZE : remaining;
        
        ssize_t n = libp2p_stream_write(s, buf + written_total, to_write);
        if (n > 0) {
            written_total += (size_t)n;
            retry_count = 0; /* Reset retry count on progress */
            fprintf(stderr, "[AUTONAT-V2] write_lp_message: wrote %zd bytes, total=%zu/%zu\n", n, written_total, len);
        } else if (n == LIBP2P_ERR_AGAIN || n == LIBP2P_ERR_TIMEOUT) {
            /* Send window likely full - wait for WINDOW_UPDATE frames */
            retry_count++;
            if (retry_count > MAX_RETRIES) {
                fprintf(stderr, "[AUTONAT-V2] write_lp_message: timed out waiting for send window\n");
                return -1;
            }
            fprintf(stderr, "[AUTONAT-V2] write_lp_message: AGAIN/TIMEOUT at %zu/%zu (retry %d)\n", 
                    written_total, len, retry_count);
            usleep(50000); /* 50ms wait for window updates */
        } else {
            fprintf(stderr, "[AUTONAT-V2] write_lp_message: body write failed at %zu/%zu, n=%zd\n", 
                    written_total, len, n);
            return -1;
        }
    }
    
    fprintf(stderr, "[AUTONAT-V2] write_lp_message: success, wrote %zu bytes total\n", written_total);
    return 0;
}

/* ----------------------- dial-back protocol handler (client) ----------------------- */

static void on_dial_back_stream(libp2p_stream_t *s, void *user_data)
{
    libp2p_autonat_service_t *svc = (libp2p_autonat_service_t *)user_data;
    if (!s || !svc) {
        if (s) {
            libp2p_stream_close(s);
            libp2p_stream_free(s);
        }
        return;
    }
    
    fprintf(stderr, "[AUTONAT-V2] received dial-back stream\n");
    
    /* Read DialBack message */
    uint8_t buf[256];
    size_t msg_len = 0;
    if (read_lp_message(s, buf, sizeof(buf), &msg_len, 5000) != 0) {
        fprintf(stderr, "[AUTONAT-V2] failed to read dial-back message\n");
        libp2p_stream_close(s);
        libp2p_stream_free(s);
        return;
    }
    
    dial_back_t db;
    if (parse_dial_back(buf, msg_len, &db) != 0) {
        fprintf(stderr, "[AUTONAT-V2] failed to parse dial-back message\n");
        libp2p_stream_close(s);
        libp2p_stream_free(s);
        return;
    }
    
    fprintf(stderr, "[AUTONAT-V2] received dial-back with nonce=%llu\n", (unsigned long long)db.nonce);
    
    /* Find matching pending dial-back */
    pthread_mutex_lock(&svc->pending_mtx);
    pending_dial_back_t *pdb = svc->pending_dial_backs;
    while (pdb) {
        if (pdb->nonce == db.nonce && !pdb->received) {
            pthread_mutex_lock(&pdb->mtx);
            pdb->received = 1;
            /* TODO: get local address from stream/connection */
            pthread_cond_signal(&pdb->cv);
            pthread_mutex_unlock(&pdb->mtx);
            break;
        }
        pdb = pdb->next;
    }
    pthread_mutex_unlock(&svc->pending_mtx);
    
    /* Send DialBackResponse */
    pb_buf_t resp = {0};
    if (encode_dial_back_response(&resp, AUTONAT_V2_DIAL_BACK_STATUS_OK) == 0) {
        write_lp_message(s, resp.buf, resp.len);
        free(resp.buf);
    }
    
    libp2p_stream_close(s);
    libp2p_stream_free(s);
}

/* ----------------------- dial-request protocol handler (server) ----------------------- */

typedef struct {
    libp2p_stream_t *s;
    libp2p_autonat_service_t *svc;
} dial_request_handler_ctx_t;

static void *dial_request_handler_thread(void *arg)
{
    dial_request_handler_ctx_t *ctx = (dial_request_handler_ctx_t *)arg;
    if (!ctx) return NULL;
    
    libp2p_stream_t *s = ctx->s;
    libp2p_autonat_service_t *svc = ctx->svc;
    free(ctx);
    
    if (!s || !svc) {
        if (s) {
            libp2p_stream_close(s);
            libp2p_stream_free(s);
        }
        return NULL;
    }
    
    fprintf(stderr, "[AUTONAT-V2] handling dial-request\n");
    
    /* Read the Message wrapper */
    uint8_t buf[AUTONAT_V2_MAX_MSG_SIZE];
    size_t msg_len = 0;
    if (read_lp_message(s, buf, sizeof(buf), &msg_len, 10000) != 0) {
        fprintf(stderr, "[AUTONAT-V2] failed to read dial-request message\n");
        goto cleanup;
    }
    
    /* Parse Message wrapper */
    int msg_type = 0;
    const uint8_t *inner = NULL;
    size_t inner_len = 0;
    if (parse_message_wrapper(buf, msg_len, &msg_type, &inner, &inner_len) != 0 ||
        msg_type != MSG_FIELD_DIAL_REQUEST) {
        fprintf(stderr, "[AUTONAT-V2] unexpected message type %d\n", msg_type);
        goto cleanup;
    }
    
    /* Parse DialRequest */
    dial_request_t req;
    if (parse_dial_request(inner, inner_len, &req) != 0) {
        fprintf(stderr, "[AUTONAT-V2] failed to parse dial-request\n");
        goto cleanup;
    }
    
    fprintf(stderr, "[AUTONAT-V2] dial-request: %zu addrs, nonce=%llu\n", 
            req.num_addrs, (unsigned long long)req.nonce);
    
    if (req.num_addrs == 0) {
        /* Send E_DIAL_REFUSED */
        pb_buf_t resp = {0};
        if (encode_dial_response(&resp, AUTONAT_V2_RESPONSE_E_DIAL_REFUSED, 0, 
                                 AUTONAT_V2_DIAL_STATUS_UNUSED) == 0) {
            write_lp_message(s, resp.buf, resp.len);
            free(resp.buf);
        }
        free_dial_request(&req);
        goto cleanup;
    }
    
    /* Select first dialable address (non-private) */
    int selected_idx = -1;
    for (size_t i = 0; i < req.num_addrs; i++) {
        if (!is_private_addr(req.addrs[i])) {
            selected_idx = (int)i;
            break;
        }
    }
    
    if (selected_idx < 0) {
        /* All addresses are private - refuse */
        pb_buf_t resp = {0};
        if (encode_dial_response(&resp, AUTONAT_V2_RESPONSE_E_DIAL_REFUSED, 0,
                                 AUTONAT_V2_DIAL_STATUS_UNUSED) == 0) {
            write_lp_message(s, resp.buf, resp.len);
            free(resp.buf);
        }
        free_dial_request(&req);
        goto cleanup;
    }
    
    fprintf(stderr, "[AUTONAT-V2] selected address[%d]: %s\n", selected_idx, req.addrs[selected_idx]);
    
    /* TODO: Check if address IP differs from observed IP and do amplification prevention */
    /* For now, we skip amplification prevention since this is for testing */
    
    /* Dial the selected address */
    autonat_v2_dial_status_t dial_status = AUTONAT_V2_DIAL_STATUS_E_DIAL_ERROR;
    
    /* Try to dial and send nonce */
    /* Note: This is a simplified implementation. A full implementation would:
     * 1. Dial the address
     * 2. Open /libp2p/autonat/2/dial-back stream
     * 3. Send DialBack message with nonce
     * 4. Wait for DialBackResponse
     */
    
    /* For now, respond with the dial attempt result */
    /* A production implementation would actually dial here */
    
    pb_buf_t resp = {0};
    if (encode_dial_response(&resp, AUTONAT_V2_RESPONSE_OK, (uint32_t)selected_idx, 
                             dial_status) == 0) {
        write_lp_message(s, resp.buf, resp.len);
        free(resp.buf);
    }
    
    free_dial_request(&req);
    
cleanup:
    libp2p_stream_close(s);
    libp2p_stream_free(s);
    return NULL;
}

static void on_dial_request_stream(libp2p_stream_t *s, void *user_data)
{
    libp2p_autonat_service_t *svc = (libp2p_autonat_service_t *)user_data;
    if (!s || !svc) {
        if (s) {
            libp2p_stream_close(s);
            libp2p_stream_free(s);
        }
        return;
    }
    
    fprintf(stderr, "[AUTONAT-V2] received dial-request stream\n");
    
    /* Handle in a separate thread to not block */
    dial_request_handler_ctx_t *ctx = (dial_request_handler_ctx_t *)calloc(1, sizeof(*ctx));
    if (!ctx) {
        libp2p_stream_close(s);
        libp2p_stream_free(s);
        return;
    }
    ctx->s = s;
    ctx->svc = svc;
    
    pthread_t tid;
    if (pthread_create(&tid, NULL, dial_request_handler_thread, ctx) != 0) {
        free(ctx);
        libp2p_stream_close(s);
        libp2p_stream_free(s);
        return;
    }
    pthread_detach(tid);
}

/* ----------------------- client probing ----------------------- */

/* Context for blocking stream open */
typedef struct {
    libp2p_stream_t *stream;
    int err;
    pthread_mutex_t mtx;
    pthread_cond_t cv;
    int done;
} probe_open_ctx_t;

/* Callback for blocking stream open */
static void probe_on_stream_opened(libp2p_stream_t *s, void *ud, int err) {
    probe_open_ctx_t *ctx = (probe_open_ctx_t *)ud;
    if (!ctx) {
        if (s) {
            libp2p_stream_close(s);
            libp2p_stream_free(s);
        }
        return;
    }
    pthread_mutex_lock(&ctx->mtx);
    ctx->stream = s;
    ctx->err = err;
    ctx->done = 1;
    pthread_cond_signal(&ctx->cv);
    pthread_mutex_unlock(&ctx->mtx);
}

/* Probe a specific peer for reachability */
static int probe_peer_v2(libp2p_autonat_service_t *svc, const peer_id_t *peer, 
                          const char *peer_addr, const char *const *our_addrs, 
                          size_t num_addrs, libp2p_autonat_dial_result_t *result)
{
    if (!svc || !peer || !peer_addr || !our_addrs || num_addrs == 0 || !result) 
        return -1;
    
    memset(result, 0, sizeof(*result));
    result->status = LIBP2P_AUTONAT_STATUS_E_INTERNAL_ERROR;
    
    /* Generate nonce */
    uint64_t nonce = generate_nonce();
    
    /* Register pending dial-back */
    pending_dial_back_t *pdb = (pending_dial_back_t *)calloc(1, sizeof(*pdb));
    if (!pdb) return -1;
    pdb->nonce = nonce;
    pdb->received = 0;
    pthread_mutex_init(&pdb->mtx, NULL);
    pthread_cond_init(&pdb->cv, NULL);
    
    pthread_mutex_lock(&svc->pending_mtx);
    pdb->next = svc->pending_dial_backs;
    svc->pending_dial_backs = pdb;
    pthread_mutex_unlock(&svc->pending_mtx);
    
    fprintf(stderr, "[AUTONAT-V2] probing peer via %s with nonce=%llu, %zu addrs\n", 
            peer_addr, (unsigned long long)nonce, num_addrs);
    for (size_t i = 0; i < num_addrs; i++) {
        fprintf(stderr, "[AUTONAT-V2]   addr[%zu]: %s\n", i, our_addrs[i]);
    }
    
    /* Build DialRequest message */
    pb_buf_t msg = {0};
    if (encode_dial_request(&msg, our_addrs, num_addrs, nonce) != 0) {
        fprintf(stderr, "[AUTONAT-V2] failed to encode dial-request\n");
        goto cleanup;
    }
    
    /* We need to open a stream synchronously. Use the host's async open with blocking wait. */
    /* For now, use a simpler approach - check if peer supports autonat v2 first */
    
    /* Check if peer supports the autonat v2 dial-request protocol */
    const char **protocols = NULL;
    size_t num_protocols = 0;
    if (svc->host->peerstore) {
        int rc = libp2p_peerstore_get_protocols(svc->host->peerstore, peer, &protocols, &num_protocols);
        if (rc == 0 && protocols) {
            int supports_v2 = 0;
            for (size_t i = 0; i < num_protocols; i++) {
                if (protocols[i] && strcmp(protocols[i], AUTONAT_V2_DIAL_REQUEST_PROTO) == 0) {
                    supports_v2 = 1;
                    break;
                }
            }
            libp2p_peerstore_free_protocols(protocols, num_protocols);
            
            if (!supports_v2) {
                fprintf(stderr, "[AUTONAT-V2] peer does not support %s\n", AUTONAT_V2_DIAL_REQUEST_PROTO);
                result->status = LIBP2P_AUTONAT_STATUS_E_DIAL_REFUSED;
                result->status_text = strdup("peer does not support autonat v2");
                free(msg.buf);
                goto cleanup;
            }
        }
    }
    
    fprintf(stderr, "[AUTONAT-V2] opening stream to peer for dial-request\n");
    
    /* Open stream to peer (blocking - we're in probe thread) */
    libp2p_stream_t *stream = NULL;
    
    /* Use callback context for blocking open */
    probe_open_ctx_t octx = {0};
    pthread_mutex_init(&octx.mtx, NULL);
    pthread_cond_init(&octx.cv, NULL);
    
    int open_rc = libp2p_host_open_stream(svc->host, peer, AUTONAT_V2_DIAL_REQUEST_PROTO, 
                                           probe_on_stream_opened, &octx);
    if (open_rc != 0) {
        fprintf(stderr, "[AUTONAT-V2] failed to initiate stream open: %d\n", open_rc);
        result->status = LIBP2P_AUTONAT_STATUS_E_DIAL_ERROR;
        result->status_text = strdup("failed to open stream");
        free(msg.buf);
        pthread_mutex_destroy(&octx.mtx);
        pthread_cond_destroy(&octx.cv);
        goto cleanup;
    }
    
    /* Wait for stream open with timeout */
    struct timespec open_deadline;
    clock_gettime(CLOCK_REALTIME, &open_deadline);
    open_deadline.tv_sec += 10;
    
    pthread_mutex_lock(&octx.mtx);
    while (!octx.done) {
        if (pthread_cond_timedwait(&octx.cv, &octx.mtx, &open_deadline) == ETIMEDOUT) {
            pthread_mutex_unlock(&octx.mtx);
            fprintf(stderr, "[AUTONAT-V2] stream open timed out\n");
            result->status = LIBP2P_AUTONAT_STATUS_E_DIAL_ERROR;
            result->status_text = strdup("stream open timeout");
            free(msg.buf);
            pthread_mutex_destroy(&octx.mtx);
            pthread_cond_destroy(&octx.cv);
            goto cleanup;
        }
    }
    stream = octx.stream;
    int stream_err = octx.err;
    pthread_mutex_unlock(&octx.mtx);
    pthread_mutex_destroy(&octx.mtx);
    pthread_cond_destroy(&octx.cv);
    
    if (stream_err != 0 || !stream) {
        fprintf(stderr, "[AUTONAT-V2] stream open failed: err=%d\n", stream_err);
        result->status = LIBP2P_AUTONAT_STATUS_E_DIAL_ERROR;
        result->status_text = strdup("stream open failed");
        free(msg.buf);
        if (stream) {
            libp2p_stream_close(stream);
            libp2p_stream_free(stream);
        }
        goto cleanup;
    }
    
    fprintf(stderr, "[AUTONAT-V2] stream opened, sending dial-request\n");
    
    /* Small delay to ensure yamux loop thread has started */
    usleep(50000); /* 50ms */
    
    /* Write DialRequest message with LP framing */
    if (write_lp_message(stream, msg.buf, msg.len) != 0) {
        fprintf(stderr, "[AUTONAT-V2] failed to write dial-request\n");
        result->status = LIBP2P_AUTONAT_STATUS_E_DIAL_ERROR;
        result->status_text = strdup("failed to write dial-request");
        free(msg.buf);
        libp2p_stream_close(stream);
        libp2p_stream_free(stream);
        goto cleanup;
    }
    free(msg.buf);
    msg.buf = NULL;
    
    fprintf(stderr, "[AUTONAT-V2] dial-request sent, reading response\n");
    
    /* Read response - may be DialDataRequest or DialResponse */
    uint8_t resp_buf[4096];
    size_t resp_len = 0;
    if (read_lp_message(stream, resp_buf, sizeof(resp_buf), &resp_len, 30000) != 0) {
        fprintf(stderr, "[AUTONAT-V2] failed to read response\n");
        result->status = LIBP2P_AUTONAT_STATUS_E_DIAL_ERROR;
        result->status_text = strdup("failed to read response");
        libp2p_stream_close(stream);
        libp2p_stream_free(stream);
        goto cleanup;
    }
    
    /* Parse the response wrapper */
    int resp_type = 0;
    const uint8_t *inner = NULL;
    size_t inner_len = 0;
    if (parse_message_wrapper(resp_buf, resp_len, &resp_type, &inner, &inner_len) != 0) {
        fprintf(stderr, "[AUTONAT-V2] failed to parse response wrapper\n");
        result->status = LIBP2P_AUTONAT_STATUS_E_DIAL_ERROR;
        result->status_text = strdup("failed to parse response");
        libp2p_stream_close(stream);
        libp2p_stream_free(stream);
        goto cleanup;
    }
    
    fprintf(stderr, "[AUTONAT-V2] got response type=%d\n", resp_type);
    
    /* Handle DialDataRequest (amplification prevention) */
    if (resp_type == MSG_FIELD_DIAL_DATA_REQUEST) {
        dial_data_request_t ddr = {0};
        if (parse_dial_data_request(inner, inner_len, &ddr) != 0) {
            fprintf(stderr, "[AUTONAT-V2] failed to parse DialDataRequest\n");
            result->status = LIBP2P_AUTONAT_STATUS_E_DIAL_ERROR;
            result->status_text = strdup("failed to parse DialDataRequest");
            libp2p_stream_close(stream);
            libp2p_stream_free(stream);
            goto cleanup;
        }
        
        fprintf(stderr, "[AUTONAT-V2] got DialDataRequest: addr_idx=%u, num_bytes=%llu\n",
                ddr.addr_idx, (unsigned long long)ddr.num_bytes);
        
        /* Limit response size (reasonable bound) */
        if (ddr.num_bytes > 100000) {
            fprintf(stderr, "[AUTONAT-V2] DialDataRequest too large: %llu\n", (unsigned long long)ddr.num_bytes);
            result->status = LIBP2P_AUTONAT_STATUS_E_DIAL_ERROR;
            result->status_text = strdup("DialDataRequest too large");
            libp2p_stream_close(stream);
            libp2p_stream_free(stream);
            goto cleanup;
        }
        
        /* Send DialDataResponse with random data */
        uint8_t *data = (uint8_t *)calloc(1, ddr.num_bytes);
        if (!data) {
            result->status = LIBP2P_AUTONAT_STATUS_E_INTERNAL_ERROR;
            result->status_text = strdup("out of memory");
            libp2p_stream_close(stream);
            libp2p_stream_free(stream);
            goto cleanup;
        }
        
        pb_buf_t ddr_msg = {0};
        if (encode_dial_data_response(&ddr_msg, data, ddr.num_bytes) != 0) {
            free(data);
            result->status = LIBP2P_AUTONAT_STATUS_E_INTERNAL_ERROR;
            result->status_text = strdup("failed to encode DialDataResponse");
            libp2p_stream_close(stream);
            libp2p_stream_free(stream);
            goto cleanup;
        }
        free(data);
        
        fprintf(stderr, "[AUTONAT-V2] sending DialDataResponse with %llu bytes\n", (unsigned long long)ddr.num_bytes);
        
        if (write_lp_message(stream, ddr_msg.buf, ddr_msg.len) != 0) {
            free(ddr_msg.buf);
            result->status = LIBP2P_AUTONAT_STATUS_E_DIAL_ERROR;
            result->status_text = strdup("failed to write DialDataResponse");
            libp2p_stream_close(stream);
            libp2p_stream_free(stream);
            goto cleanup;
        }
        free(ddr_msg.buf);
        
        /* Now read the actual DialResponse */
        if (read_lp_message(stream, resp_buf, sizeof(resp_buf), &resp_len, 30000) != 0) {
            fprintf(stderr, "[AUTONAT-V2] failed to read DialResponse after data\n");
            result->status = LIBP2P_AUTONAT_STATUS_E_DIAL_ERROR;
            result->status_text = strdup("failed to read DialResponse");
            libp2p_stream_close(stream);
            libp2p_stream_free(stream);
            goto cleanup;
        }
        
        if (parse_message_wrapper(resp_buf, resp_len, &resp_type, &inner, &inner_len) != 0) {
            result->status = LIBP2P_AUTONAT_STATUS_E_DIAL_ERROR;
            result->status_text = strdup("failed to parse DialResponse wrapper");
            libp2p_stream_close(stream);
            libp2p_stream_free(stream);
            goto cleanup;
        }
    }
    
    /* Now we should have a DialResponse */
    if (resp_type != MSG_FIELD_DIAL_RESPONSE) {
        fprintf(stderr, "[AUTONAT-V2] unexpected response type: %d\n", resp_type);
        result->status = LIBP2P_AUTONAT_STATUS_E_DIAL_ERROR;
        result->status_text = strdup("unexpected response type");
        libp2p_stream_close(stream);
        libp2p_stream_free(stream);
        goto cleanup;
    }
    
    dial_response_t dr = {0};
    if (parse_dial_response(inner, inner_len, &dr) != 0) {
        fprintf(stderr, "[AUTONAT-V2] failed to parse DialResponse\n");
        result->status = LIBP2P_AUTONAT_STATUS_E_DIAL_ERROR;
        result->status_text = strdup("failed to parse DialResponse");
        libp2p_stream_close(stream);
        libp2p_stream_free(stream);
        goto cleanup;
    }
    
    fprintf(stderr, "[AUTONAT-V2] got DialResponse: status=%d, addr_idx=%u, dial_status=%d\n",
            dr.status, dr.addr_idx, dr.dial_status);
    
    /* Close stream - we're done with the request/response */
    libp2p_stream_close(stream);
    libp2p_stream_free(stream);
    stream = NULL;
    
    /* Check response status */
    if (dr.status == AUTONAT_V2_RESPONSE_OK) {
        /* Server will attempt dial-back. Wait for it. */
        fprintf(stderr, "[AUTONAT-V2] server accepted, waiting for dial-back (nonce=%llu)\n",
                (unsigned long long)nonce);
        
        struct timespec deadline;
        clock_gettime(CLOCK_REALTIME, &deadline);
        deadline.tv_sec += 30; /* 30 second timeout for dial-back */
        
        pthread_mutex_lock(&pdb->mtx);
        while (!pdb->received) {
            int rc = pthread_cond_timedwait(&pdb->cv, &pdb->mtx, &deadline);
            if (rc == ETIMEDOUT) {
                pthread_mutex_unlock(&pdb->mtx);
                fprintf(stderr, "[AUTONAT-V2] dial-back timeout\n");
                result->status = LIBP2P_AUTONAT_STATUS_E_DIAL_ERROR;
                result->status_text = strdup("dial-back timeout");
                goto cleanup;
            }
        }
        pthread_mutex_unlock(&pdb->mtx);
        
        /* Got dial-back! */
        fprintf(stderr, "[AUTONAT-V2] dial-back received! addr=%s reachable\n",
                pdb->received_addr ? pdb->received_addr : "?");
        
        result->status = LIBP2P_AUTONAT_STATUS_OK;
        result->status_text = strdup("reachable");
        if (dr.addr_idx < num_addrs) {
            result->addr = strdup(our_addrs[dr.addr_idx]);
        } else if (pdb->received_addr) {
            result->addr = strdup(pdb->received_addr);
        }
    } else {
        /* Server refused or failed */
        fprintf(stderr, "[AUTONAT-V2] server declined dial: status=%d\n", dr.status);
        result->status = LIBP2P_AUTONAT_STATUS_E_DIAL_REFUSED;
        if (dr.status == AUTONAT_V2_RESPONSE_E_DIAL_REFUSED) {
            result->status_text = strdup("dial refused");
        } else if (dr.status == AUTONAT_V2_RESPONSE_E_REQUEST_REJECTED) {
            result->status_text = strdup("request rejected");
        } else if (dr.status == AUTONAT_V2_RESPONSE_E_INTERNAL_ERROR) {
            result->status_text = strdup("internal error");
        } else {
            result->status_text = strdup("unknown error");
        }
    }

cleanup:
    /* Remove from pending list */
    pthread_mutex_lock(&svc->pending_mtx);
    if (svc->pending_dial_backs == pdb) {
        svc->pending_dial_backs = pdb->next;
    } else {
        pending_dial_back_t *p = svc->pending_dial_backs;
        while (p && p->next != pdb) p = p->next;
        if (p) p->next = pdb->next;
    }
    pthread_mutex_unlock(&svc->pending_mtx);
    
    pthread_mutex_destroy(&pdb->mtx);
    pthread_cond_destroy(&pdb->cv);
    free(pdb->received_addr);
    free(pdb);
    
    return 0;
}

/* Helper to get connected peer IDs from host sessions */
static int get_connected_peers(libp2p_autonat_service_t *svc, peer_id_t ***out_peers, size_t *out_count)
{
    if (!svc || !svc->host || !out_peers || !out_count) return -1;
    
    *out_peers = NULL;
    *out_count = 0;
    
    pthread_mutex_lock(&svc->host->mtx);
    
    /* Count sessions */
    size_t count = 0;
    session_node_t *sess = svc->host->sessions;
    while (sess) {
        if (sess->remote_peer) count++;
        sess = sess->next;
    }
    
    if (count == 0) {
        pthread_mutex_unlock(&svc->host->mtx);
        return 0;
    }
    
    /* Allocate array */
    peer_id_t **peers = (peer_id_t **)calloc(count, sizeof(peer_id_t *));
    if (!peers) {
        pthread_mutex_unlock(&svc->host->mtx);
        return -1;
    }
    
    /* Copy peer IDs */
    size_t i = 0;
    sess = svc->host->sessions;
    while (sess && i < count) {
        if (sess->remote_peer) {
            peers[i] = (peer_id_t *)malloc(sizeof(peer_id_t));
            if (peers[i]) {
                peers[i]->bytes = (uint8_t *)malloc(sess->remote_peer->size);
                if (peers[i]->bytes) {
                    memcpy(peers[i]->bytes, sess->remote_peer->bytes, sess->remote_peer->size);
                    peers[i]->size = sess->remote_peer->size;
                    i++;
                } else {
                    free(peers[i]);
                }
            }
        }
        sess = sess->next;
    }
    
    pthread_mutex_unlock(&svc->host->mtx);
    
    *out_peers = peers;
    *out_count = i;
    return 0;
}

static void free_peer_list(peer_id_t **peers, size_t count)
{
    if (!peers) return;
    for (size_t i = 0; i < count; i++) {
        if (peers[i]) {
            free(peers[i]->bytes);
            free(peers[i]);
        }
    }
    free(peers);
}

/* Helper to get our public addresses to test (prefer observed addrs, fallback to listen addrs) */
static char **get_our_public_addrs(libp2p_autonat_service_t *svc, size_t *out_count)
{
    if (!svc || !svc->host || !out_count) return NULL;
    
    *out_count = 0;
    char **addrs = NULL;
    size_t cap = 0;
    
    /* First, try to use observed addresses (these are our public addresses as seen by peers) */
    pthread_mutex_lock(&svc->mtx);
    observed_addr_node_t *obs = svc->observed_addrs;
    while (obs) {
        if (obs->addr && !is_private_addr(obs->addr)) {
            if (*out_count >= cap) {
                size_t new_cap = cap ? cap * 2 : 8;
                char **new_addrs = (char **)realloc(addrs, new_cap * sizeof(char *));
                if (!new_addrs) break;
                addrs = new_addrs;
                cap = new_cap;
            }
            addrs[(*out_count)++] = strdup(obs->addr);
        }
        obs = obs->next;
    }
    pthread_mutex_unlock(&svc->mtx);
    
    /* If we have observed addresses, use those */
    if (*out_count > 0) {
        return addrs;
    }
    
    /* Fallback: Get listen addresses from listeners (useful for testing on public server) */
    pthread_mutex_lock(&svc->host->mtx);
    struct listener_node *ln = svc->host->listeners;
    while (ln) {
        if (ln->addr_str && !is_private_addr(ln->addr_str)) {
            if (*out_count >= cap) {
                size_t new_cap = cap ? cap * 2 : 8;
                char **new_addrs = (char **)realloc(addrs, new_cap * sizeof(char *));
                if (!new_addrs) break;
                addrs = new_addrs;
                cap = new_cap;
            }
            addrs[(*out_count)++] = strdup(ln->addr_str);
        }
        ln = ln->next;
    }
    pthread_mutex_unlock(&svc->host->mtx);
    
    /* If still no public addresses, we're behind NAT and need observed addresses.
     * Return local addresses for debugging purposes only. */
    if (*out_count == 0) {
        fprintf(stderr, "[AUTONAT-V2] WARNING: no observed public addresses available\n");
        fprintf(stderr, "[AUTONAT-V2] waiting for Identify to provide observedAddr\n");
    }
    
    return addrs;
}

static void free_addr_list(char **addrs, size_t count)
{
    if (!addrs) return;
    for (size_t i = 0; i < count; i++)
        free(addrs[i]);
    free(addrs);
}

/* ----------------------- event handler for address discovery ----------------------- */

static void autonat_event_handler(const libp2p_event_t *evt, void *user_data)
{
    libp2p_autonat_service_t *svc = (libp2p_autonat_service_t *)user_data;
    if (!svc || !evt)
        return;

    if (evt->kind == LIBP2P_EVT_NEW_EXTERNAL_ADDR_CANDIDATE ||
        evt->kind == LIBP2P_EVT_EXTERNAL_ADDR_CONFIRMED)
    {
        const char *addr = (evt->kind == LIBP2P_EVT_NEW_EXTERNAL_ADDR_CANDIDATE)
                               ? evt->u.new_external_addr_candidate.addr
                               : evt->u.external_addr_confirmed.addr;
        if (addr && !is_private_addr(addr))
        {
            libp2p_autonat_add_observed_addr(svc, addr);
        }
    }
}

/* ----------------------- probe thread ----------------------- */

static void *autonat_v2_probe_thread(void *arg)
{
    libp2p_autonat_service_t *svc = (libp2p_autonat_service_t *)arg;
    if (!svc) return NULL;
    
    /* Boot delay */
    fprintf(stderr, "[AUTONAT-V2] boot delay %d ms\n", svc->opts.boot_delay_ms);
    usleep((useconds_t)svc->opts.boot_delay_ms * 1000);
    
    while (!svc->stop_requested) {
        pthread_mutex_lock(&svc->mtx);
        int stop = svc->stop_requested;
        pthread_mutex_unlock(&svc->mtx);
        if (stop) break;
        
        fprintf(stderr, "[AUTONAT-V2] probe cycle (reachability=%d, success=%d, failure=%d)\n",
                svc->reachability, svc->success_count, svc->failure_count);
        
        /* Get connected peers */
        peer_id_t **peers = NULL;
        size_t num_peers = 0;
        if (get_connected_peers(svc, &peers, &num_peers) == 0 && num_peers > 0) {
            fprintf(stderr, "[AUTONAT-V2] found %zu connected peers\n", num_peers);
            
            /* Get our addresses to test */
            size_t num_addrs = 0;
            char **our_addrs = get_our_public_addrs(svc, &num_addrs);
            
            if (our_addrs && num_addrs > 0) {
                fprintf(stderr, "[AUTONAT-V2] have %zu addresses to test\n", num_addrs);
                
                /* Try to probe each peer until we get enough confirmations */
                int probes_this_cycle = 0;
                const int max_probes_per_cycle = 3; /* Limit probes to avoid spamming */
                
                for (size_t i = 0; i < num_peers && !svc->stop_requested; i++) {
                    /* Skip if we already have enough confirmations */
                    if (svc->success_count >= svc->opts.min_confirmations)
                        break;
                    
                    /* Limit probes per cycle to avoid spamming */
                    if (probes_this_cycle >= max_probes_per_cycle) {
                        fprintf(stderr, "[AUTONAT-V2] reached max probes per cycle (%d)\n", max_probes_per_cycle);
                        break;
                    }
                    
                    /* Get peer's address from peerstore */
                    const multiaddr_t **peer_addrs = NULL;
                    size_t peer_num_addrs = 0;
                    if (svc->host->peerstore) {
                        libp2p_peerstore_get_addrs(svc->host->peerstore, peers[i], 
                                                   &peer_addrs, &peer_num_addrs);
                    }
                    
                    if (peer_addrs && peer_num_addrs > 0) {
                        int ma_err = 0;
                        char *peer_addr = multiaddr_to_str((multiaddr_t *)peer_addrs[0], &ma_err);
                        if (peer_addr) {
                            libp2p_autonat_dial_result_t result = {0};
                            probe_peer_v2(svc, peers[i], peer_addr, 
                                         (const char *const *)our_addrs, num_addrs, &result);
                            
                            probes_this_cycle++;
                            
                            if (result.status == LIBP2P_AUTONAT_STATUS_OK) {
                                pthread_mutex_lock(&svc->mtx);
                                svc->success_count++;
                                if (svc->success_count >= svc->opts.min_confirmations) {
                                    svc->reachability = LIBP2P_AUTONAT_REACHABILITY_PUBLIC;
                                    if (result.addr) {
                                        free(svc->public_addr);
                                        svc->public_addr = strdup(result.addr);
                                    }
                                }
                                pthread_mutex_unlock(&svc->mtx);
                            } else {
                                pthread_mutex_lock(&svc->mtx);
                                svc->failure_count++;
                                pthread_mutex_unlock(&svc->mtx);
                            }
                            
                            free(result.status_text);
                            free(result.addr);
                            free(peer_addr);
                            
                            /* Small delay between probes to avoid spamming */
                            if (i + 1 < num_peers && probes_this_cycle < max_probes_per_cycle) {
                                sleep(2); /* 2 second delay between probes */
                            }
                        }
                        libp2p_peerstore_free_addrs(peer_addrs, peer_num_addrs);
                    }
                }
                
                free_addr_list(our_addrs, num_addrs);
            } else {
                fprintf(stderr, "[AUTONAT-V2] no addresses to test\n");
            }
            
            free_peer_list(peers, num_peers);
        } else {
            fprintf(stderr, "[AUTONAT-V2] no connected peers to probe\n");
        }
        
        /* Sleep until next probe interval */
        for (int i = 0; i < svc->opts.refresh_interval_ms / 1000 && !svc->stop_requested; i++) {
            sleep(1);
        }
    }
    
    return NULL;
}

/* ----------------------- public API ----------------------- */

void libp2p_autonat_opts_default(libp2p_autonat_opts_t *opts)
{
    if (!opts) return;
    memset(opts, 0, sizeof(*opts));
    opts->struct_size = sizeof(*opts);
    opts->enable_service = true;
    opts->dial_timeout_ms = AUTONAT_V2_DIAL_TIMEOUT_MS;
    opts->throttle_global_max = 30;
    opts->throttle_peer_max = 3;
    opts->throttle_interval_ms = 60000;
    opts->refresh_interval_ms = 60000;
    opts->boot_delay_ms = 15000;
    opts->min_peers_required = 3;
    opts->min_confirmations = 3;
}

int libp2p_autonat_new(libp2p_host_t *host, const libp2p_autonat_opts_t *opts, 
                       libp2p_autonat_service_t **out)
{
    if (!host || !out) return LIBP2P_ERR_NULL_PTR;
    
    libp2p_autonat_service_t *svc = (libp2p_autonat_service_t *)calloc(1, sizeof(*svc));
    if (!svc) return LIBP2P_ERR_INTERNAL;
    
    svc->host = host;
    if (opts) {
        memcpy(&svc->opts, opts, sizeof(svc->opts));
    } else {
        libp2p_autonat_opts_default(&svc->opts);
    }
    
    pthread_mutex_init(&svc->mtx, NULL);
    pthread_mutex_init(&svc->pending_mtx, NULL);
    
    svc->reachability = LIBP2P_AUTONAT_REACHABILITY_UNKNOWN;
    
    /* Register dial-back handler (client side - receives dial-backs) */
    libp2p_protocol_def_t dial_back_def = {0};
    dial_back_def.protocol_id = AUTONAT_V2_DIAL_BACK_PROTO;
    dial_back_def.on_open = on_dial_back_stream;
    dial_back_def.user_data = svc;
    int rc = libp2p_register_protocol(host, &dial_back_def);
    if (rc != 0) {
        fprintf(stderr, "[AUTONAT-V2] failed to register dial-back handler: %d\n", rc);
    } else {
        fprintf(stderr, "[AUTONAT-V2] registered %s handler\n", AUTONAT_V2_DIAL_BACK_PROTO);
    }
    
    /* Register dial-request handler (server side - responds to requests) */
    if (svc->opts.enable_service) {
        libp2p_protocol_def_t dial_req_def = {0};
        dial_req_def.protocol_id = AUTONAT_V2_DIAL_REQUEST_PROTO;
        dial_req_def.on_open = on_dial_request_stream;
        dial_req_def.user_data = svc;
        rc = libp2p_register_protocol(host, &dial_req_def);
        if (rc != 0) {
            fprintf(stderr, "[AUTONAT-V2] failed to register dial-request handler: %d\n", rc);
        } else {
            fprintf(stderr, "[AUTONAT-V2] registered %s handler\n", AUTONAT_V2_DIAL_REQUEST_PROTO);
        }
    }
    
    /* Subscribe to address discovery events (to learn our public addresses from Identify) */
    rc = libp2p_event_subscribe(host, autonat_event_handler, svc, &svc->event_sub);
    if (rc != 0) {
        fprintf(stderr, "[AUTONAT-V2] warning: failed to subscribe to events (rc=%d)\n", rc);
    } else {
        fprintf(stderr, "[AUTONAT-V2] subscribed to address discovery events\n");
    }
    
    *out = svc;
    return 0;
}

int libp2p_autonat_start(libp2p_autonat_service_t *svc)
{
    if (!svc) return LIBP2P_ERR_NULL_PTR;
    
    if (svc->probe_running) return 0;
    
    svc->stop_requested = 0;
    svc->probe_running = 1;
    
    if (pthread_create(&svc->probe_thread, NULL, autonat_v2_probe_thread, svc) != 0) {
        svc->probe_running = 0;
        return LIBP2P_ERR_INTERNAL;
    }
    
    fprintf(stderr, "[AUTONAT-V2] service started\n");
    return 0;
}

int libp2p_autonat_stop(libp2p_autonat_service_t *svc)
{
    if (!svc) return LIBP2P_ERR_NULL_PTR;
    
    if (!svc->probe_running) return 0;
    
    pthread_mutex_lock(&svc->mtx);
    svc->stop_requested = 1;
    pthread_mutex_unlock(&svc->mtx);
    
    pthread_join(svc->probe_thread, NULL);
    svc->probe_running = 0;
    
    fprintf(stderr, "[AUTONAT-V2] service stopped\n");
    return 0;
}

void libp2p_autonat_free(libp2p_autonat_service_t *svc)
{
    if (!svc) return;
    
    libp2p_autonat_stop(svc);
    
    /* Unsubscribe from events */
    if (svc->event_sub && svc->host) {
        libp2p_event_unsubscribe(svc->host, svc->event_sub);
    }
    
    libp2p_unregister_protocol(svc->host, AUTONAT_V2_DIAL_BACK_PROTO);
    if (svc->opts.enable_service) {
        libp2p_unregister_protocol(svc->host, AUTONAT_V2_DIAL_REQUEST_PROTO);
    }
    
    /* Free pending dial-backs */
    pending_dial_back_t *pdb = svc->pending_dial_backs;
    while (pdb) {
        pending_dial_back_t *next = pdb->next;
        pthread_mutex_destroy(&pdb->mtx);
        pthread_cond_destroy(&pdb->cv);
        free(pdb->received_addr);
        free(pdb);
        pdb = next;
    }
    
    /* Free observed addresses */
    observed_addr_node_t *obs = svc->observed_addrs;
    while (obs) {
        observed_addr_node_t *next = obs->next;
        free(obs->addr);
        free(obs);
        obs = next;
    }
    
    free(svc->public_addr);
    pthread_mutex_destroy(&svc->mtx);
    pthread_mutex_destroy(&svc->pending_mtx);
    free(svc);
}

libp2p_autonat_reachability_t libp2p_autonat_get_reachability(libp2p_autonat_service_t *svc)
{
    if (!svc) return LIBP2P_AUTONAT_REACHABILITY_UNKNOWN;
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
    if (svc->reachability != LIBP2P_AUTONAT_REACHABILITY_PUBLIC || !svc->public_addr) {
        pthread_mutex_unlock(&svc->mtx);
        return LIBP2P_ERR_INTERNAL;
    }
    
    size_t len = strlen(svc->public_addr);
    if (len >= out_len) {
        pthread_mutex_unlock(&svc->mtx);
        return LIBP2P_ERR_MSG_TOO_LARGE;
    }
    
    memcpy(out_addr, svc->public_addr, len + 1);
    pthread_mutex_unlock(&svc->mtx);
    return 0;
}

int libp2p_autonat_on_reachability_changed(libp2p_autonat_service_t *svc,
                                            libp2p_autonat_reachability_cb cb,
                                            void *user_data)
{
    if (!svc) return LIBP2P_ERR_NULL_PTR;
    
    pthread_mutex_lock(&svc->mtx);
    svc->reachability_cb = cb;
    svc->reachability_cb_user_data = user_data;
    pthread_mutex_unlock(&svc->mtx);
    return 0;
}

int libp2p_autonat_probe_peer(libp2p_autonat_service_t *svc, const peer_id_t *peer,
                               const char *const *addrs, size_t num_addrs,
                               int timeout_ms, libp2p_autonat_dial_result_t *result)
{
    if (!svc || !peer || !result)
        return LIBP2P_ERR_NULL_PTR;
    
    (void)timeout_ms; /* TODO: use timeout */
    
    /* Get peer address to connect to */
    const char *peer_addr = (addrs && num_addrs > 0) ? addrs[0] : NULL;
    if (!peer_addr) {
        result->status = LIBP2P_AUTONAT_STATUS_E_BAD_REQUEST;
        result->status_text = strdup("no peer address provided");
        return LIBP2P_ERR_NULL_PTR;
    }
    
    /* Get our addresses to test */
    /* For now, just pass the provided addresses as both peer and our addresses */
    return probe_peer_v2(svc, peer, peer_addr, addrs, num_addrs, result);
}

int libp2p_autonat_force_probe(libp2p_autonat_service_t *svc)
{
    if (!svc) return LIBP2P_ERR_NULL_PTR;
    /* TODO: trigger immediate probe */
    return 0;
}

int libp2p_autonat_add_observed_addr(libp2p_autonat_service_t *svc, const char *addr)
{
    if (!svc || !addr) return LIBP2P_ERR_NULL_PTR;
    
    pthread_mutex_lock(&svc->mtx);
    
    /* Check if already exists */
    observed_addr_node_t *node = svc->observed_addrs;
    while (node) {
        if (node->addr && strcmp(node->addr, addr) == 0) {
            pthread_mutex_unlock(&svc->mtx);
            return 0; /* Already exists */
        }
        node = node->next;
    }
    
    /* Limit max observed addresses */
    if (svc->num_observed_addrs >= AUTONAT_MAX_OBSERVED_ADDRS) {
        /* Remove oldest (last in list) */
        if (svc->observed_addrs && svc->observed_addrs->next) {
            observed_addr_node_t *prev = svc->observed_addrs;
            while (prev->next && prev->next->next)
                prev = prev->next;
            free(prev->next->addr);
            free(prev->next);
            prev->next = NULL;
            svc->num_observed_addrs--;
        }
    }
    
    /* Add new address at front */
    observed_addr_node_t *new_node = (observed_addr_node_t *)calloc(1, sizeof(*new_node));
    if (!new_node) {
        pthread_mutex_unlock(&svc->mtx);
        return LIBP2P_ERR_INTERNAL;
    }
    new_node->addr = strdup(addr);
    if (!new_node->addr) {
        free(new_node);
        pthread_mutex_unlock(&svc->mtx);
        return LIBP2P_ERR_INTERNAL;
    }
    new_node->next = svc->observed_addrs;
    svc->observed_addrs = new_node;
    svc->num_observed_addrs++;
    
    fprintf(stderr, "[AUTONAT-V2] added observed addr: %s (total=%zu)\n", addr, svc->num_observed_addrs);
    
    pthread_mutex_unlock(&svc->mtx);
    return 0;
}

int libp2p_autonat_get_observed_addrs(libp2p_autonat_service_t *svc, char ***out_addrs, size_t *out_count)
{
    if (!svc || !out_addrs || !out_count) return LIBP2P_ERR_NULL_PTR;
    
    *out_addrs = NULL;
    *out_count = 0;
    
    pthread_mutex_lock(&svc->mtx);
    
    if (svc->num_observed_addrs == 0 || !svc->observed_addrs) {
        pthread_mutex_unlock(&svc->mtx);
        return 0;
    }
    
    char **addrs = (char **)calloc(svc->num_observed_addrs, sizeof(char *));
    if (!addrs) {
        pthread_mutex_unlock(&svc->mtx);
        return LIBP2P_ERR_INTERNAL;
    }
    
    size_t i = 0;
    observed_addr_node_t *node = svc->observed_addrs;
    while (node && i < svc->num_observed_addrs) {
        if (node->addr) {
            addrs[i] = strdup(node->addr);
            if (!addrs[i]) {
                for (size_t j = 0; j < i; j++)
                    free(addrs[j]);
                free(addrs);
                pthread_mutex_unlock(&svc->mtx);
                return LIBP2P_ERR_INTERNAL;
            }
            i++;
        }
        node = node->next;
    }
    
    pthread_mutex_unlock(&svc->mtx);
    
    *out_addrs = addrs;
    *out_count = i;
    return 0;
}
