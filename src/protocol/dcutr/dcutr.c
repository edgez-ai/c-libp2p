/**
 * DCUtR (Direct Connection Upgrade through Relay) implementation for libp2p.
 *
 * DCUtR allows two peers connected via a relay to upgrade to a direct connection
 * using hole punching techniques. This is essential for efficient peer-to-peer
 * communication when both peers are behind NATs.
 *
 * Protocol: /libp2p/dcutr
 *
 * Message format (protobuf):
 *   message HolePunch {
 *     enum Type { CONNECT = 0; SYNC = 1; }
 *     optional Type type = 1;
 *     repeated bytes ObsAddrs = 2;
 *   }
 *
 * Flow:
 *   1. Initiator (A) sends CONNECT with its observed addresses
 *   2. Responder (B) receives CONNECT, sends CONNECT back with its observed addresses
 *   3. Initiator sends SYNC to signal start of hole punching
 *   4. Both peers simultaneously attempt to connect to each other's addresses
 *   5. First successful connection wins
 */

#include "libp2p/dcutr.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <fcntl.h>

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
#include "protocol/tcp/protocol_tcp_conn.h"

#define DCUTR_MAX_MSG_SIZE 4096
#define DCUTR_DEFAULT_HOLE_PUNCH_TIMEOUT_MS 5000
#define DCUTR_DEFAULT_MAX_RETRY_ATTEMPTS 3
#define DCUTR_DEFAULT_RETRY_DELAY_MS 500
#define DCUTR_MAX_OBSERVED_ADDRS 16
#define DCUTR_SIMULTANEOUS_CONNECT_DELAY_US 10000  /* 10ms delay for coordination */

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

/* ----------------------- DCUtR message structures ----------------------- */

typedef struct
{
    int type_set;
    libp2p_dcutr_msg_type_t type;
    uint8_t **obs_addrs;
    size_t *obs_addrs_lens;
    size_t num_obs_addrs;
} dcutr_message_t;

static void dcutr_message_free(dcutr_message_t *msg)
{
    if (!msg)
        return;
    for (size_t i = 0; i < msg->num_obs_addrs; i++)
        free(msg->obs_addrs[i]);
    free(msg->obs_addrs);
    free(msg->obs_addrs_lens);
    memset(msg, 0, sizeof(*msg));
}

/* ----------------------- message encoding ----------------------- */

static int encode_dcutr_message(pb_buf_t *out, libp2p_dcutr_msg_type_t type,
                                 const char *const *addrs, size_t num_addrs)
{
    if (!out)
        return -1;

    /* HolePunch.type (field 1, varint) */
    if (pb_buf_append_key(out, 1, 0) != 0)
        return -1;
    if (pb_buf_append_varint(out, (uint64_t)type) != 0)
        return -1;

    /* HolePunch.ObsAddrs (field 2, bytes, repeated) */
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

/* ----------------------- message decoding ----------------------- */

static int parse_dcutr_message(const uint8_t *buf, size_t len, dcutr_message_t *out)
{
    if (!buf || !out)
        return -1;
    memset(out, 0, sizeof(*out));
    size_t off = 0;
    size_t addr_cap = 0;

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
            out->type = (libp2p_dcutr_msg_type_t)v;
            continue;
        }
        if (field == 2 && wire == 2)
        {
            /* ObsAddrs (bytes, repeated) */
            uint64_t l = 0;
            if (pb_read_varint(buf, len, &off, &l) != 0)
                return -1;
            if (off + l > len)
                return -1;

            /* Grow arrays */
            if (out->num_obs_addrs >= addr_cap)
            {
                size_t newcap = addr_cap ? addr_cap * 2 : 4;
                uint8_t **na = (uint8_t **)realloc(out->obs_addrs, newcap * sizeof(uint8_t *));
                size_t *nl = (size_t *)realloc(out->obs_addrs_lens, newcap * sizeof(size_t));
                if (!na || !nl)
                {
                    free(na);
                    free(nl);
                    return -1;
                }
                out->obs_addrs = na;
                out->obs_addrs_lens = nl;
                addr_cap = newcap;
            }

            out->obs_addrs[out->num_obs_addrs] = (uint8_t *)malloc((size_t)l);
            if (!out->obs_addrs[out->num_obs_addrs])
                return -1;
            memcpy(out->obs_addrs[out->num_obs_addrs], buf + off, (size_t)l);
            out->obs_addrs_lens[out->num_obs_addrs] = (size_t)l;
            out->num_obs_addrs++;
            off += (size_t)l;
            continue;
        }
        if (pb_skip_field(buf, len, &off, wire) != 0)
            return -1;
    }
    return 0;
}

/* ----------------------- DCUtR service structure ----------------------- */

typedef struct upgrade_cb_node
{
    libp2p_dcutr_upgrade_cb cb;
    void *user_data;
    struct upgrade_cb_node *next;
} upgrade_cb_node_t;

typedef struct observed_addr_node
{
    char *addr;
    struct observed_addr_node *next;
} observed_addr_node_t;

struct libp2p_dcutr_service
{
    libp2p_host_t *host;
    libp2p_dcutr_opts_t opts;

    pthread_mutex_t mtx;

    /* Observed addresses for this node */
    observed_addr_node_t *observed_addrs;
    size_t num_observed_addrs;

    /* Upgrade callbacks */
    upgrade_cb_node_t *callbacks;

    /* Event subscription for address discovery */
    libp2p_subscription_t *event_sub;
};

/* ----------------------- time helpers ----------------------- */

static uint64_t now_mono_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

/* ----------------------- address helpers ----------------------- */

static int is_public_addr(const char *addr_str)
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
    if (strstr(addr_str, "/ip6/::") != NULL)
        return 0;
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

static int parse_multiaddr_for_tcp(const char *addr_str, char *ip_out, size_t ip_len, int *port_out)
{
    if (!addr_str || !ip_out || !port_out)
        return -1;

    /* Parse /ip4/x.x.x.x/tcp/port or /ip6/.../tcp/port */
    const char *ip_start = NULL;
    const char *port_str = NULL;
    int is_ipv6 = 0;

    if (strncmp(addr_str, "/ip4/", 5) == 0)
    {
        ip_start = addr_str + 5;
    }
    else if (strncmp(addr_str, "/ip6/", 5) == 0)
    {
        ip_start = addr_str + 5;
        is_ipv6 = 1;
    }
    else
    {
        return -1;
    }

    const char *tcp_pos = strstr(ip_start, "/tcp/");
    if (!tcp_pos)
        return -1;

    size_t ip_size = (size_t)(tcp_pos - ip_start);
    if (ip_size >= ip_len)
        return -1;

    memcpy(ip_out, ip_start, ip_size);
    ip_out[ip_size] = '\0';

    port_str = tcp_pos + 5;
    char *end = NULL;
    long port = strtol(port_str, &end, 10);
    if (port <= 0 || port > 65535)
        return -1;

    *port_out = (int)port;
    return is_ipv6 ? 6 : 4;
}

/* ----------------------- hole punching ----------------------- */

typedef struct
{
    char addr[256];
    int success;
    int fd;
} hole_punch_attempt_t;

static void *hole_punch_worker(void *arg)
{
    hole_punch_attempt_t *attempt = (hole_punch_attempt_t *)arg;
    if (!attempt)
        return NULL;

    char ip[128];
    int port = 0;
    int ip_ver = parse_multiaddr_for_tcp(attempt->addr, ip, sizeof(ip), &port);
    if (ip_ver <= 0)
    {
        fprintf(stderr, "[DCUTR] cannot parse addr for hole punch: %s\n", attempt->addr);
        return NULL;
    }

    /* Create socket */
    int domain = (ip_ver == 6) ? AF_INET6 : AF_INET;
    int fd = socket(domain, SOCK_STREAM, 0);
    if (fd < 0)
    {
        fprintf(stderr, "[DCUTR] socket creation failed: %s\n", strerror(errno));
        return NULL;
    }

    /* Enable address reuse for simultaneous open */
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_REUSEPORT
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif

    /* Set non-blocking for timeout handling */
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    /* Attempt connection */
    struct sockaddr_storage addr_storage;
    socklen_t addr_len;

    if (ip_ver == 4)
    {
        struct sockaddr_in *addr4 = (struct sockaddr_in *)&addr_storage;
        memset(addr4, 0, sizeof(*addr4));
        addr4->sin_family = AF_INET;
        addr4->sin_port = htons((uint16_t)port);
        if (inet_pton(AF_INET, ip, &addr4->sin_addr) != 1)
        {
            close(fd);
            return NULL;
        }
        addr_len = sizeof(*addr4);
    }
    else
    {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&addr_storage;
        memset(addr6, 0, sizeof(*addr6));
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = htons((uint16_t)port);
        if (inet_pton(AF_INET6, ip, &addr6->sin6_addr) != 1)
        {
            close(fd);
            return NULL;
        }
        addr_len = sizeof(*addr6);
    }

    fprintf(stderr, "[DCUTR] attempting hole punch to %s:%d\n", ip, port);

    int rc = connect(fd, (struct sockaddr *)&addr_storage, addr_len);
    if (rc == 0)
    {
        /* Immediate success (rare) */
        attempt->success = 1;
        attempt->fd = fd;
        fprintf(stderr, "[DCUTR] hole punch immediate success to %s\n", attempt->addr);
        return NULL;
    }

    if (errno != EINPROGRESS)
    {
        fprintf(stderr, "[DCUTR] hole punch connect failed: %s\n", strerror(errno));
        close(fd);
        return NULL;
    }

    /* Wait for connection with select */
    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(fd, &wfds);

    struct timeval tv;
    tv.tv_sec = DCUTR_DEFAULT_HOLE_PUNCH_TIMEOUT_MS / 1000;
    tv.tv_usec = (DCUTR_DEFAULT_HOLE_PUNCH_TIMEOUT_MS % 1000) * 1000;

    rc = select(fd + 1, NULL, &wfds, NULL, &tv);
    if (rc > 0 && FD_ISSET(fd, &wfds))
    {
        int err = 0;
        socklen_t errlen = sizeof(err);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen);
        if (err == 0)
        {
            attempt->success = 1;
            attempt->fd = fd;
            fprintf(stderr, "[DCUTR] hole punch SUCCESS to %s\n", attempt->addr);
            return NULL;
        }
        fprintf(stderr, "[DCUTR] hole punch connect error: %s\n", strerror(err));
    }
    else
    {
        fprintf(stderr, "[DCUTR] hole punch timeout to %s\n", attempt->addr);
    }

    close(fd);
    return NULL;
}

static int attempt_hole_punch(libp2p_dcutr_service_t *svc, const char *const *remote_addrs,
                               size_t num_remote_addrs, char **success_addr, int *success_fd)
{
    if (!svc || !remote_addrs || num_remote_addrs == 0)
        return -1;

    /* Start parallel hole punch attempts */
    size_t num_attempts = num_remote_addrs < 8 ? num_remote_addrs : 8;
    hole_punch_attempt_t *attempts = (hole_punch_attempt_t *)calloc(num_attempts, sizeof(*attempts));
    pthread_t *threads = (pthread_t *)calloc(num_attempts, sizeof(*threads));
    if (!attempts || !threads)
    {
        free(attempts);
        free(threads);
        return -1;
    }

    /* Small delay for coordination (TCP simultaneous open timing) */
    usleep(DCUTR_SIMULTANEOUS_CONNECT_DELAY_US);

    /* Launch threads */
    for (size_t i = 0; i < num_attempts; i++)
    {
        snprintf(attempts[i].addr, sizeof(attempts[i].addr), "%s", remote_addrs[i]);
        attempts[i].fd = -1;
        if (pthread_create(&threads[i], NULL, hole_punch_worker, &attempts[i]) != 0)
        {
            threads[i] = 0;
        }
    }

    /* Wait for all threads */
    for (size_t i = 0; i < num_attempts; i++)
    {
        if (threads[i])
            pthread_join(threads[i], NULL);
    }

    /* Check for success */
    int result = -1;
    for (size_t i = 0; i < num_attempts; i++)
    {
        if (attempts[i].success && attempts[i].fd >= 0)
        {
            if (result < 0)
            {
                result = 0;
                if (success_addr)
                    *success_addr = strdup(attempts[i].addr);
                if (success_fd)
                    *success_fd = attempts[i].fd;
            }
            else
            {
                /* Close extra successful connections */
                close(attempts[i].fd);
            }
        }
    }

    free(attempts);
    free(threads);
    return result;
}

/* ----------------------- server-side: handling incoming DCUtR ----------------------- */

typedef struct
{
    libp2p_stream_t *s;
    libp2p_dcutr_service_t *svc;
} dcutr_server_ctx_t;

static void notify_upgrade(libp2p_dcutr_service_t *svc, const peer_id_t *peer,
                            const char *addr, libp2p_dcutr_result_t result)
{
    pthread_mutex_lock(&svc->mtx);
    upgrade_cb_node_t *cb = svc->callbacks;
    while (cb)
    {
        if (cb->cb)
            cb->cb(peer, addr, result, cb->user_data);
        cb = cb->next;
    }
    pthread_mutex_unlock(&svc->mtx);
}

static char **get_observed_addrs_locked(libp2p_dcutr_service_t *svc, size_t *out_count)
{
    *out_count = 0;
    if (!svc->observed_addrs)
        return NULL;

    char **addrs = (char **)calloc(svc->num_observed_addrs, sizeof(char *));
    if (!addrs)
        return NULL;

    observed_addr_node_t *node = svc->observed_addrs;
    size_t i = 0;
    while (node && i < svc->num_observed_addrs)
    {
        addrs[i] = strdup(node->addr);
        if (!addrs[i])
        {
            for (size_t j = 0; j < i; j++)
                free(addrs[j]);
            free(addrs);
            return NULL;
        }
        i++;
        node = node->next;
    }
    *out_count = i;
    return addrs;
}

static void free_addr_array(char **addrs, size_t count)
{
    if (!addrs)
        return;
    for (size_t i = 0; i < count; i++)
        free(addrs[i]);
    free(addrs);
}

static void *dcutr_server_worker(void *arg)
{
    dcutr_server_ctx_t *ctx = (dcutr_server_ctx_t *)arg;
    if (!ctx)
        return NULL;

    libp2p_stream_t *s = ctx->s;
    libp2p_dcutr_service_t *svc = ctx->svc;
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
    fprintf(stderr, "[DCUTR] received CONNECT from peer=%s\n", peer_str[0] ? peer_str : "(unknown)");

    libp2p_stream_set_read_interest(s, true);

    /* Read CONNECT message */
    uint8_t buf[DCUTR_MAX_MSG_SIZE];
    ssize_t n = libp2p_lp_recv(s, buf, sizeof(buf));
    if (n <= 0)
    {
        fprintf(stderr, "[DCUTR] failed to read CONNECT from peer=%s\n", peer_str);
        libp2p_stream_close(s);
        libp2p__stream_release_async(s);
        if (host)
            libp2p__worker_dec(host);
        return NULL;
    }

    dcutr_message_t msg;
    if (parse_dcutr_message(buf, (size_t)n, &msg) != 0 || !msg.type_set ||
        msg.type != LIBP2P_DCUTR_MSG_CONNECT)
    {
        fprintf(stderr, "[DCUTR] malformed CONNECT from peer=%s\n", peer_str);
        dcutr_message_free(&msg);
        libp2p_stream_close(s);
        libp2p__stream_release_async(s);
        if (host)
            libp2p__worker_dec(host);
        return NULL;
    }

    /* Extract remote observed addresses */
    char **remote_addrs = NULL;
    size_t num_remote_addrs = 0;
    if (msg.num_obs_addrs > 0)
    {
        remote_addrs = (char **)calloc(msg.num_obs_addrs, sizeof(char *));
        if (remote_addrs)
        {
            for (size_t i = 0; i < msg.num_obs_addrs; i++)
            {
                int ma_err = 0;
                multiaddr_t *ma = multiaddr_new_from_bytes(msg.obs_addrs[i], msg.obs_addrs_lens[i], &ma_err);
                if (ma)
                {
                    remote_addrs[num_remote_addrs] = multiaddr_to_str(ma, &ma_err);
                    if (remote_addrs[num_remote_addrs])
                    {
                        fprintf(stderr, "[DCUTR] peer %s observed addr: %s\n", peer_str, remote_addrs[num_remote_addrs]);
                        num_remote_addrs++;
                    }
                    multiaddr_free(ma);
                }
            }
        }
    }
    dcutr_message_free(&msg);

    /* Get our observed addresses */
    pthread_mutex_lock(&svc->mtx);
    size_t num_our_addrs = 0;
    char **our_addrs = get_observed_addrs_locked(svc, &num_our_addrs);
    pthread_mutex_unlock(&svc->mtx);

    /* Send CONNECT response with our addresses */
    pb_buf_t out = {0};
    if (encode_dcutr_message(&out, LIBP2P_DCUTR_MSG_CONNECT, (const char *const *)our_addrs, num_our_addrs) != 0)
    {
        free(out.buf);
        free_addr_array(our_addrs, num_our_addrs);
        free_addr_array(remote_addrs, num_remote_addrs);
        libp2p_stream_close(s);
        libp2p__stream_release_async(s);
        if (host)
            libp2p__worker_dec(host);
        return NULL;
    }

    if (libp2p_lp_send(s, out.buf, out.len) < 0)
    {
        fprintf(stderr, "[DCUTR] failed to send CONNECT response\n");
        free(out.buf);
        free_addr_array(our_addrs, num_our_addrs);
        free_addr_array(remote_addrs, num_remote_addrs);
        libp2p_stream_close(s);
        libp2p__stream_release_async(s);
        if (host)
            libp2p__worker_dec(host);
        return NULL;
    }
    free(out.buf);
    free_addr_array(our_addrs, num_our_addrs);

    /* Wait for SYNC message */
    n = libp2p_lp_recv(s, buf, sizeof(buf));
    if (n <= 0)
    {
        fprintf(stderr, "[DCUTR] failed to read SYNC from peer=%s\n", peer_str);
        free_addr_array(remote_addrs, num_remote_addrs);
        libp2p_stream_close(s);
        libp2p__stream_release_async(s);
        if (host)
            libp2p__worker_dec(host);
        return NULL;
    }

    dcutr_message_t sync_msg;
    if (parse_dcutr_message(buf, (size_t)n, &sync_msg) != 0 || !sync_msg.type_set ||
        sync_msg.type != LIBP2P_DCUTR_MSG_SYNC)
    {
        fprintf(stderr, "[DCUTR] expected SYNC, got type=%d\n", sync_msg.type);
        dcutr_message_free(&sync_msg);
        free_addr_array(remote_addrs, num_remote_addrs);
        libp2p_stream_close(s);
        libp2p__stream_release_async(s);
        if (host)
            libp2p__worker_dec(host);
        return NULL;
    }
    dcutr_message_free(&sync_msg);

    fprintf(stderr, "[DCUTR] received SYNC, starting hole punch\n");

    /* Attempt hole punch */
    char *success_addr = NULL;
    int success_fd = -1;
    int rc = attempt_hole_punch(svc, (const char *const *)remote_addrs, num_remote_addrs,
                                 &success_addr, &success_fd);

    free_addr_array(remote_addrs, num_remote_addrs);
    libp2p_stream_close(s);
    libp2p__stream_release_async(s);

    if (rc == 0 && success_addr && success_fd >= 0)
    {
        fprintf(stderr, "[DCUTR] hole punch SUCCESS via %s (fd=%d)\n", success_addr, success_fd);
        notify_upgrade(svc, remote, success_addr, LIBP2P_DCUTR_RESULT_SUCCESS);

        /* Create a libp2p connection from the hole-punched socket and hand off to host */
        libp2p_conn_t *raw = make_tcp_conn(success_fd);
        if (raw && host)
        {
            int accept_rc = libp2p__host_accept_inbound_raw(host, raw);
            if (accept_rc == 0)
            {
                fprintf(stderr, "[DCUTR] successfully handed off hole-punched connection to host\n");
            }
            else
            {
                fprintf(stderr, "[DCUTR] failed to hand off connection (rc=%d)\n", accept_rc);
                libp2p_conn_free(raw);
            }
        }
        else
        {
            if (!raw)
                fprintf(stderr, "[DCUTR] failed to create connection from fd\n");
            close(success_fd);
        }
    }
    else
    {
        fprintf(stderr, "[DCUTR] hole punch FAILED for peer=%s\n", peer_str);
        notify_upgrade(svc, remote, NULL, LIBP2P_DCUTR_RESULT_HOLE_PUNCH_FAILED);
        if (success_fd >= 0)
            close(success_fd);
    }

    free(success_addr);
    if (host)
        libp2p__worker_dec(host);
    return NULL;
}

static void dcutr_on_open(libp2p_stream_t *s, void *ud)
{
    libp2p_dcutr_service_t *svc = (libp2p_dcutr_service_t *)ud;
    if (!s || !svc)
    {
        if (s)
        {
            libp2p_stream_close(s);
            libp2p_stream_free(s);
        }
        return;
    }

    dcutr_server_ctx_t *ctx = (dcutr_server_ctx_t *)calloc(1, sizeof(*ctx));
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
    if (pthread_create(&th, NULL, dcutr_server_worker, ctx) == 0)
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

/* ----------------------- event handler for address discovery ----------------------- */

/* Helper to duplicate a peer_id_t */
static peer_id_t *dcutr_peer_id_dup(const peer_id_t *src)
{
    if (!src || !src->bytes || src->size == 0)
        return NULL;
    peer_id_t *dst = (peer_id_t *)calloc(1, sizeof(*dst));
    if (!dst)
        return NULL;
    dst->bytes = (uint8_t *)malloc(src->size);
    if (!dst->bytes)
    {
        free(dst);
        return NULL;
    }
    memcpy(dst->bytes, src->bytes, src->size);
    dst->size = src->size;
    return dst;
}

static void dcutr_peer_id_free(peer_id_t *pid)
{
    if (!pid)
        return;
    free(pid->bytes);
    free(pid);
}

/* Context for async DCUtR upgrade worker */
typedef struct dcutr_auto_upgrade_ctx
{
    libp2p_dcutr_service_t *svc;
    peer_id_t *peer;
} dcutr_auto_upgrade_ctx_t;

/* Worker thread to initiate DCUtR upgrade asynchronously */
static void *dcutr_auto_upgrade_worker(void *arg)
{
    dcutr_auto_upgrade_ctx_t *ctx = (dcutr_auto_upgrade_ctx_t *)arg;
    if (!ctx)
        return NULL;

    libp2p_dcutr_service_t *svc = ctx->svc;
    peer_id_t *peer = ctx->peer;
    free(ctx);

    if (!svc || !peer)
    {
        if (peer)
            dcutr_peer_id_free(peer);
        return NULL;
    }

    char peer_str[128] = {0};
    peer_id_to_string(peer, PEER_ID_FMT_BASE58_LEGACY, peer_str, sizeof(peer_str));

    /* Small delay to let the relay connection stabilize */
    usleep(500000); /* 500ms */

    fprintf(stderr, "[DCUTR] auto-initiating upgrade for relay connection to peer=%s\n", peer_str);

    int rc = libp2p_dcutr_upgrade(svc, peer, svc->opts.hole_punch_timeout_ms);
    if (rc == 0)
    {
        fprintf(stderr, "[DCUTR] auto-upgrade SUCCESS for peer=%s\n", peer_str);
    }
    else
    {
        fprintf(stderr, "[DCUTR] auto-upgrade FAILED for peer=%s (rc=%d)\n", peer_str, rc);
    }

    dcutr_peer_id_free(peer);
    return NULL;
}

static void dcutr_event_handler(const libp2p_event_t *evt, void *user_data)
{
    libp2p_dcutr_service_t *svc = (libp2p_dcutr_service_t *)user_data;
    if (!svc || !evt)
        return;

    if (evt->kind == LIBP2P_EVT_NEW_EXTERNAL_ADDR_CANDIDATE ||
        evt->kind == LIBP2P_EVT_EXTERNAL_ADDR_CONFIRMED)
    {
        const char *addr = (evt->kind == LIBP2P_EVT_NEW_EXTERNAL_ADDR_CANDIDATE)
                               ? evt->u.new_external_addr_candidate.addr
                               : evt->u.external_addr_confirmed.addr;
        if (addr && is_public_addr(addr))
        {
            libp2p_dcutr_add_observed_addr(svc, addr);
        }
    }
    else if (evt->kind == LIBP2P_EVT_CONN_OPENED)
    {
        /* Check if this is a relay connection (contains /p2p-circuit) */
        const char *addr = evt->u.conn_opened.addr;
        const peer_id_t *peer = evt->u.conn_opened.peer;
        bool inbound = evt->u.conn_opened.inbound;

        if (addr && peer && strstr(addr, "/p2p-circuit") != NULL)
        {
            char peer_str[128] = {0};
            peer_id_to_string(peer, PEER_ID_FMT_BASE58_LEGACY, peer_str, sizeof(peer_str));
            fprintf(stderr, "[DCUTR] detected relay connection to peer=%s inbound=%d addr=%s\n",
                    peer_str, inbound, addr);

            /* Check if we have observed addresses (meaning we're behind NAT) */
            pthread_mutex_lock(&svc->mtx);
            size_t num_addrs = svc->num_observed_addrs;
            pthread_mutex_unlock(&svc->mtx);

            if (num_addrs > 0)
            {
                /* We're behind NAT - initiate DCUtR upgrade asynchronously */
                dcutr_auto_upgrade_ctx_t *ctx = (dcutr_auto_upgrade_ctx_t *)calloc(1, sizeof(*ctx));
                if (ctx)
                {
                    ctx->svc = svc;
                    ctx->peer = dcutr_peer_id_dup(peer);
                    if (ctx->peer)
                    {
                        pthread_t th;
                        if (pthread_create(&th, NULL, dcutr_auto_upgrade_worker, ctx) == 0)
                        {
                            pthread_detach(th);
                        }
                        else
                        {
                            dcutr_peer_id_free(ctx->peer);
                            free(ctx);
                        }
                    }
                    else
                    {
                        free(ctx);
                    }
                }
            }
            else
            {
                fprintf(stderr, "[DCUTR] no observed addresses yet, skipping auto-upgrade\n");
            }
        }
    }
}

/* ----------------------- public API ----------------------- */

void libp2p_dcutr_opts_default(libp2p_dcutr_opts_t *opts)
{
    if (!opts)
        return;
    memset(opts, 0, sizeof(*opts));
    opts->struct_size = sizeof(*opts);
    opts->hole_punch_timeout_ms = DCUTR_DEFAULT_HOLE_PUNCH_TIMEOUT_MS;
    opts->max_retry_attempts = DCUTR_DEFAULT_MAX_RETRY_ATTEMPTS;
    opts->retry_delay_ms = DCUTR_DEFAULT_RETRY_DELAY_MS;
    opts->enable_tcp_simultaneous_open = true;
}

int libp2p_dcutr_new(libp2p_host_t *host, const libp2p_dcutr_opts_t *opts, libp2p_dcutr_service_t **out)
{
    if (!host || !out)
        return LIBP2P_ERR_NULL_PTR;

    libp2p_dcutr_service_t *svc = (libp2p_dcutr_service_t *)calloc(1, sizeof(*svc));
    if (!svc)
        return LIBP2P_ERR_INTERNAL;

    svc->host = host;
    if (opts && opts->struct_size == sizeof(*opts))
        svc->opts = *opts;
    else
        libp2p_dcutr_opts_default(&svc->opts);

    pthread_mutex_init(&svc->mtx, NULL);

    /* Register protocol handler */
    libp2p_protocol_def_t def = {0};
    def.protocol_id = LIBP2P_DCUTR_PROTO_ID;
    def.read_mode = LIBP2P_READ_PULL;
    def.on_open = dcutr_on_open;
    def.user_data = svc;
    int rc = libp2p_register_protocol(host, &def);
    if (rc != 0)
    {
        pthread_mutex_destroy(&svc->mtx);
        free(svc);
        return rc;
    }

    /* Subscribe to address discovery events */
    rc = libp2p_event_subscribe(host, dcutr_event_handler, svc, &svc->event_sub);
    if (rc != 0)
    {
        fprintf(stderr, "[DCUTR] warning: failed to subscribe to events\n");
    }

    fprintf(stderr, "[DCUTR] registered protocol handler: %s\n", LIBP2P_DCUTR_PROTO_ID);

    *out = svc;
    return 0;
}

void libp2p_dcutr_free(libp2p_dcutr_service_t *svc)
{
    if (!svc)
        return;

    /* Unsubscribe from events */
    if (svc->event_sub && svc->host)
    {
        libp2p_event_unsubscribe(svc->host, svc->event_sub);
    }

    libp2p_unregister_protocol(svc->host, LIBP2P_DCUTR_PROTO_ID);

    /* Free observed addresses */
    observed_addr_node_t *addr = svc->observed_addrs;
    while (addr)
    {
        observed_addr_node_t *next = addr->next;
        free(addr->addr);
        free(addr);
        addr = next;
    }

    /* Free callbacks */
    upgrade_cb_node_t *cb = svc->callbacks;
    while (cb)
    {
        upgrade_cb_node_t *next = cb->next;
        free(cb);
        cb = next;
    }

    pthread_mutex_destroy(&svc->mtx);
    free(svc);
}

int libp2p_dcutr_on_upgrade(libp2p_dcutr_service_t *svc, libp2p_dcutr_upgrade_cb cb, void *user_data)
{
    if (!svc || !cb)
        return LIBP2P_ERR_NULL_PTR;

    upgrade_cb_node_t *node = (upgrade_cb_node_t *)calloc(1, sizeof(*node));
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

int libp2p_dcutr_add_observed_addr(libp2p_dcutr_service_t *svc, const char *addr)
{
    if (!svc || !addr)
        return LIBP2P_ERR_NULL_PTR;

    pthread_mutex_lock(&svc->mtx);

    /* Check if already present */
    observed_addr_node_t *node = svc->observed_addrs;
    while (node)
    {
        if (strcmp(node->addr, addr) == 0)
        {
            pthread_mutex_unlock(&svc->mtx);
            return 0; /* Already exists */
        }
        node = node->next;
    }

    /* Check limit */
    if (svc->num_observed_addrs >= DCUTR_MAX_OBSERVED_ADDRS)
    {
        pthread_mutex_unlock(&svc->mtx);
        return LIBP2P_ERR_INTERNAL;
    }

    /* Add new address */
    node = (observed_addr_node_t *)calloc(1, sizeof(*node));
    if (!node)
    {
        pthread_mutex_unlock(&svc->mtx);
        return LIBP2P_ERR_INTERNAL;
    }
    node->addr = strdup(addr);
    if (!node->addr)
    {
        free(node);
        pthread_mutex_unlock(&svc->mtx);
        return LIBP2P_ERR_INTERNAL;
    }

    node->next = svc->observed_addrs;
    svc->observed_addrs = node;
    svc->num_observed_addrs++;

    fprintf(stderr, "[DCUTR] added observed addr: %s (total=%zu)\n", addr, svc->num_observed_addrs);

    pthread_mutex_unlock(&svc->mtx);
    return 0;
}

int libp2p_dcutr_get_observed_addrs(libp2p_dcutr_service_t *svc, char ***out_addrs, size_t *out_count)
{
    if (!svc || !out_addrs || !out_count)
        return LIBP2P_ERR_NULL_PTR;

    pthread_mutex_lock(&svc->mtx);
    *out_addrs = get_observed_addrs_locked(svc, out_count);
    pthread_mutex_unlock(&svc->mtx);

    return (*out_addrs != NULL || *out_count == 0) ? 0 : LIBP2P_ERR_INTERNAL;
}

/* ----------------------- blocking stream open helper ----------------------- */

typedef struct
{
    libp2p_stream_t *s;
    int rc;
} dcutr_open_ctx_t;

static void dcutr_on_stream_open(libp2p_stream_t *s, void *ud, int err)
{
    dcutr_open_ctx_t *ctx = (dcutr_open_ctx_t *)ud;
    if (!ctx)
        return;
    ctx->s = s;
    ctx->rc = err;
}

/* ----------------------- public API ----------------------- */

int libp2p_dcutr_upgrade(libp2p_dcutr_service_t *svc, const peer_id_t *peer, int timeout_ms)
{
    if (!svc || !peer)
        return LIBP2P_ERR_NULL_PTR;

    char peer_str[128] = {0};
    peer_id_to_string(peer, PEER_ID_FMT_BASE58_LEGACY, peer_str, sizeof(peer_str));
    fprintf(stderr, "[DCUTR] initiating upgrade to peer=%s\n", peer_str);

    /* Get our observed addresses */
    pthread_mutex_lock(&svc->mtx);
    size_t num_our_addrs = 0;
    char **our_addrs = get_observed_addrs_locked(svc, &num_our_addrs);
    pthread_mutex_unlock(&svc->mtx);

    if (!our_addrs || num_our_addrs == 0)
    {
        fprintf(stderr, "[DCUTR] no observed addresses available\n");
        free_addr_array(our_addrs, num_our_addrs);
        return LIBP2P_ERR_INTERNAL;
    }

    /* Open DCUtR stream to peer using callback pattern */
    dcutr_open_ctx_t open_ctx = {0};
    int rc = libp2p_host_open_stream(svc->host, peer, LIBP2P_DCUTR_PROTO_ID,
                                      dcutr_on_stream_open, &open_ctx);
    if (rc != 0 || open_ctx.rc != 0 || !open_ctx.s)
    {
        fprintf(stderr, "[DCUTR] failed to open stream to peer=%s (rc=%d, cb_rc=%d)\n", 
                peer_str, rc, open_ctx.rc);
        free_addr_array(our_addrs, num_our_addrs);
        return rc != 0 ? rc : (open_ctx.rc != 0 ? open_ctx.rc : LIBP2P_ERR_INTERNAL);
    }
    libp2p_stream_t *s = open_ctx.s;

    /* Send CONNECT with our addresses */
    pb_buf_t msg = {0};
    if (encode_dcutr_message(&msg, LIBP2P_DCUTR_MSG_CONNECT, (const char *const *)our_addrs, num_our_addrs) != 0)
    {
        free(msg.buf);
        free_addr_array(our_addrs, num_our_addrs);
        libp2p_stream_close(s);
        libp2p_stream_free(s);
        return LIBP2P_ERR_INTERNAL;
    }
    free_addr_array(our_addrs, num_our_addrs);

    if (libp2p_lp_send(s, msg.buf, msg.len) < 0)
    {
        fprintf(stderr, "[DCUTR] failed to send CONNECT\n");
        free(msg.buf);
        libp2p_stream_close(s);
        libp2p_stream_free(s);
        return LIBP2P_ERR_INTERNAL;
    }
    free(msg.buf);

    /* Read CONNECT response with peer's addresses */
    uint8_t buf[DCUTR_MAX_MSG_SIZE];
    ssize_t n = libp2p_lp_recv(s, buf, sizeof(buf));
    if (n <= 0)
    {
        fprintf(stderr, "[DCUTR] failed to read CONNECT response\n");
        libp2p_stream_close(s);
        libp2p_stream_free(s);
        return LIBP2P_ERR_INTERNAL;
    }

    dcutr_message_t resp;
    if (parse_dcutr_message(buf, (size_t)n, &resp) != 0 || !resp.type_set ||
        resp.type != LIBP2P_DCUTR_MSG_CONNECT)
    {
        fprintf(stderr, "[DCUTR] invalid CONNECT response\n");
        dcutr_message_free(&resp);
        libp2p_stream_close(s);
        libp2p_stream_free(s);
        return LIBP2P_ERR_INTERNAL;
    }

    /* Extract remote addresses */
    char **remote_addrs = NULL;
    size_t num_remote_addrs = 0;
    if (resp.num_obs_addrs > 0)
    {
        remote_addrs = (char **)calloc(resp.num_obs_addrs, sizeof(char *));
        if (remote_addrs)
        {
            for (size_t i = 0; i < resp.num_obs_addrs; i++)
            {
                int ma_err = 0;
                multiaddr_t *ma = multiaddr_new_from_bytes(resp.obs_addrs[i], resp.obs_addrs_lens[i], &ma_err);
                if (ma)
                {
                    remote_addrs[num_remote_addrs] = multiaddr_to_str(ma, &ma_err);
                    if (remote_addrs[num_remote_addrs])
                    {
                        fprintf(stderr, "[DCUTR] peer %s addr: %s\n", peer_str, remote_addrs[num_remote_addrs]);
                        num_remote_addrs++;
                    }
                    multiaddr_free(ma);
                }
            }
        }
    }
    dcutr_message_free(&resp);

    if (num_remote_addrs == 0)
    {
        fprintf(stderr, "[DCUTR] peer has no observed addresses\n");
        free_addr_array(remote_addrs, num_remote_addrs);
        libp2p_stream_close(s);
        libp2p_stream_free(s);
        return LIBP2P_ERR_INTERNAL;
    }

    /* Send SYNC to coordinate hole punch timing */
    pb_buf_t sync = {0};
    if (encode_dcutr_message(&sync, LIBP2P_DCUTR_MSG_SYNC, NULL, 0) != 0)
    {
        free(sync.buf);
        free_addr_array(remote_addrs, num_remote_addrs);
        libp2p_stream_close(s);
        libp2p_stream_free(s);
        return LIBP2P_ERR_INTERNAL;
    }

    if (libp2p_lp_send(s, sync.buf, sync.len) < 0)
    {
        fprintf(stderr, "[DCUTR] failed to send SYNC\n");
        free(sync.buf);
        free_addr_array(remote_addrs, num_remote_addrs);
        libp2p_stream_close(s);
        libp2p_stream_free(s);
        return LIBP2P_ERR_INTERNAL;
    }
    free(sync.buf);

    fprintf(stderr, "[DCUTR] sent SYNC, starting hole punch\n");

    /* Attempt hole punch */
    char *success_addr = NULL;
    int success_fd = -1;
    rc = attempt_hole_punch(svc, (const char *const *)remote_addrs, num_remote_addrs,
                             &success_addr, &success_fd);

    free_addr_array(remote_addrs, num_remote_addrs);
    libp2p_stream_close(s);
    libp2p_stream_free(s);

    if (rc == 0 && success_addr && success_fd >= 0)
    {
        fprintf(stderr, "[DCUTR] upgrade SUCCESS via %s (fd=%d)\n", success_addr, success_fd);
        notify_upgrade(svc, peer, success_addr, LIBP2P_DCUTR_RESULT_SUCCESS);

        /* Create a libp2p connection from the hole-punched socket and hand off to host */
        libp2p_conn_t *raw = make_tcp_conn(success_fd);
        if (raw && svc->host)
        {
            int accept_rc = libp2p__host_accept_inbound_raw(svc->host, raw);
            if (accept_rc == 0)
            {
                fprintf(stderr, "[DCUTR] successfully handed off hole-punched connection to host\n");
            }
            else
            {
                fprintf(stderr, "[DCUTR] failed to hand off connection (rc=%d)\n", accept_rc);
                libp2p_conn_free(raw);
            }
        }
        else
        {
            if (!raw)
                fprintf(stderr, "[DCUTR] failed to create connection from fd\n");
            close(success_fd);
        }

        free(success_addr);
        return 0;
    }

    fprintf(stderr, "[DCUTR] upgrade FAILED for peer=%s\n", peer_str);
    notify_upgrade(svc, peer, NULL, LIBP2P_DCUTR_RESULT_HOLE_PUNCH_FAILED);
    free(success_addr);
    if (success_fd >= 0)
        close(success_fd);
    return LIBP2P_ERR_INTERNAL;
}
