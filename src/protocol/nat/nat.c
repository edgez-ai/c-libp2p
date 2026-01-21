/**
 * NAT traversal implementation for libp2p using UPnP and NAT-PMP.
 *
 * This implementation provides:
 * - UPnP IGD (Internet Gateway Device) port mapping
 * - NAT-PMP (Port Mapping Protocol) support
 * - Automatic gateway discovery
 * - Mapping refresh and lifecycle management
 *
 * UPnP IGD uses SSDP (Simple Service Discovery Protocol) to discover
 * NAT gateways and SOAP to request port mappings.
 *
 * NAT-PMP uses a simpler UDP-based protocol on port 5351.
 */

#include "libp2p/nat.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "libp2p/errors.h"
#include "libp2p/log.h"
#include "multiformats/multiaddr/multiaddr.h"

/* ======================= Constants ======================= */

/* SSDP (UPnP Discovery) */
#define SSDP_MULTICAST_ADDR "239.255.255.250"
#define SSDP_PORT 1900
#define SSDP_MX 3 /* Max wait time in seconds */

/* NAT-PMP */
#define NATPMP_PORT 5351
#define NATPMP_VERSION 0
#define NATPMP_OP_EXTERNAL_ADDR 0
#define NATPMP_OP_MAP_UDP 1
#define NATPMP_OP_MAP_TCP 2
#define NATPMP_RESULT_SUCCESS 0
#define NATPMP_RECOMMENDED_LIFETIME 7200 /* 2 hours */

/* Timeouts and limits */
#define DEFAULT_DISCOVERY_TIMEOUT_MS 5000
#define DEFAULT_MAPPING_LIFETIME_SECS 3600
#define DEFAULT_RETRY_ATTEMPTS 3
#define DEFAULT_RETRY_DELAY_MS 1000
#define MAX_MAPPINGS 64
#define MAX_RESPONSE_SIZE 4096
#define HTTP_TIMEOUT_MS 5000

/* ======================= SSDP Messages ======================= */

static const char *SSDP_SEARCH_IGD =
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "MAN: \"ssdp:discover\"\r\n"
    "MX: 3\r\n"
    "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
    "\r\n";

static const char *SSDP_SEARCH_WANIP =
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "MAN: \"ssdp:discover\"\r\n"
    "MX: 3\r\n"
    "ST: urn:schemas-upnp-org:service:WANIPConnection:1\r\n"
    "\r\n";

/* ======================= Internal Structures ======================= */

typedef struct mapping_entry
{
    uint16_t internal_port;
    uint16_t external_port;
    int is_tcp;
    uint32_t lifetime_secs;
    time_t created_at;
    time_t last_refresh;
    struct mapping_entry *next;
} mapping_entry_t;

typedef struct upnp_gateway
{
    char *location_url;    /* UPnP device description URL */
    char *control_url;     /* WANIPConnection control URL */
    char *service_type;    /* Service type string */
    char *external_ip;     /* Cached external IP */
    struct sockaddr_in addr;
} upnp_gateway_t;

typedef struct natpmp_gateway
{
    struct sockaddr_in addr;
    char *external_ip;
    uint32_t epoch;
} natpmp_gateway_t;

struct libp2p_nat_service
{
    libp2p_host_t *host;
    libp2p_nat_opts_t opts;
    
    pthread_mutex_t mtx;
    pthread_t refresh_thread;
    int refresh_running;
    int stop_flag;
    
    libp2p_nat_status_t status;
    libp2p_nat_proto_t active_proto;
    
    /* Gateway info */
    upnp_gateway_t *upnp;
    natpmp_gateway_t *natpmp;
    
    /* Active mappings */
    mapping_entry_t *mappings;
    size_t mapping_count;
    
    /* Callbacks */
    libp2p_nat_mapping_cb cb;
    void *cb_user_data;
};

/* ======================= Helper Functions ======================= */

static void set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0)
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static char *find_header(const char *response, const char *header)
{
    char search[256];
    snprintf(search, sizeof(search), "\r\n%s:", header);
    
    char *pos = strcasestr(response, search);
    if (!pos)
    {
        /* Check at start of headers */
        snprintf(search, sizeof(search), "%s:", header);
        if (strncasecmp(response, search, strlen(search)) == 0)
            pos = (char *)response - 2; /* Adjust for the \r\n we added */
        else
            return NULL;
    }
    
    pos += strlen(search) + 2; /* Skip header name and colon */
    while (*pos == ' ' || *pos == '\t')
        pos++;
    
    char *end = strstr(pos, "\r\n");
    if (!end)
        end = pos + strlen(pos);
    
    size_t len = end - pos;
    char *result = malloc(len + 1);
    if (result)
    {
        memcpy(result, pos, len);
        result[len] = '\0';
    }
    return result;
}

static char *extract_xml_value(const char *xml, const char *tag)
{
    char open_tag[128], close_tag[128];
    snprintf(open_tag, sizeof(open_tag), "<%s>", tag);
    snprintf(close_tag, sizeof(close_tag), "</%s>", tag);
    
    char *start = strstr(xml, open_tag);
    if (!start)
        return NULL;
    start += strlen(open_tag);
    
    char *end = strstr(start, close_tag);
    if (!end)
        return NULL;
    
    size_t len = end - start;
    char *result = malloc(len + 1);
    if (result)
    {
        memcpy(result, start, len);
        result[len] = '\0';
    }
    return result;
}

static int get_default_route_iface(char *out_ifname, size_t out_len)
{
    if (!out_ifname || out_len == 0)
        return -1;

    FILE *fp = fopen("/proc/net/route", "r");
    if (!fp)
        return -1;

    char line[256];
    /* Skip header */
    if (!fgets(line, sizeof(line), fp))
    {
        fclose(fp);
        return -1;
    }

    while (fgets(line, sizeof(line), fp))
    {
        char iface[IFNAMSIZ] = {0};
        unsigned long dest = 0;
        unsigned long gw = 0;
        unsigned int flags = 0;

        /* Format: Iface Destination Gateway Flags ... */
        if (sscanf(line, "%15s %lx %lx %X", iface, &dest, &gw, &flags) == 4)
        {
            if (dest == 0 && (flags & 0x1)) /* RTF_UP */
            {
                snprintf(out_ifname, out_len, "%s", iface);
                fclose(fp);
                return 0;
            }
        }
    }

    fclose(fp);
    return -1;
}

static int get_iface_ipv4(const char *ifname, char *out_ip, size_t out_len)
{
    if (!ifname || !out_ip || out_len == 0)
        return -1;

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0)
        return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);

    if (ioctl(s, SIOCGIFADDR, &ifr) != 0)
    {
        close(s);
        return -1;
    }

    struct sockaddr_in *sa = (struct sockaddr_in *)&ifr.ifr_addr;
    const char *res = inet_ntop(AF_INET, &sa->sin_addr, out_ip, out_len);
    close(s);
    return res ? 0 : -1;
}

static void log_interfaces_ipv4(void)
{
    struct ifaddrs *ifaddr = NULL;
    if (getifaddrs(&ifaddr) != 0)
    {
        LP_LOGW("NAT", "getifaddrs failed: %s", strerror(errno));
        fprintf(stderr, "[NAT] getifaddrs failed: %s\n", strerror(errno));
        return;
    }

    for (struct ifaddrs *ifa = ifaddr; ifa; ifa = ifa->ifa_next)
    {
        if (!ifa->ifa_name || !ifa->ifa_addr)
            continue;
        if (ifa->ifa_addr->sa_family != AF_INET)
            continue;

        char ip[INET_ADDRSTRLEN] = {0};
        struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
        if (inet_ntop(AF_INET, &sa->sin_addr, ip, sizeof(ip)))
        {
            LP_LOGI("NAT", "iface %s IPv4 %s flags=0x%x", ifa->ifa_name, ip, (unsigned int)ifa->ifa_flags);
            fprintf(stderr, "[NAT] iface %s IPv4 %s flags=0x%x\n", ifa->ifa_name, ip, (unsigned int)ifa->ifa_flags);
        }
    }

    freeifaddrs(ifaddr);
}

/* ======================= UPnP Implementation ======================= */

static int upnp_discover_gateway(libp2p_nat_service_t *svc, int timeout_ms)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        return LIBP2P_NAT_ERR_INTERNAL;
    
    set_nonblocking(sock);
    
    /* Allow multicast */
    int ttl = 2;
    setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
    
    /* Enable broadcast */
    int bcast = 1;
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &bcast, sizeof(bcast));

    /* Log available interfaces for troubleshooting */
    log_interfaces_ipv4();

    /* Use hard-coded interface preference for SSDP source IP */
    const char *iface_ip = NULL;
    char iface_ip_buf[INET_ADDRSTRLEN] = {0};

    const char *preferred_ifaces[] = {
        "br-ahwlan",
        "phy0-sta0"
    };
    for (size_t i = 0; i < sizeof(preferred_ifaces) / sizeof(preferred_ifaces[0]); i++)
    {
        if (get_iface_ipv4(preferred_ifaces[i], iface_ip_buf, sizeof(iface_ip_buf)) == 0)
        {
            iface_ip = iface_ip_buf;
            LP_LOGI("NAT", "SSDP using interface %s (%s)", preferred_ifaces[i], iface_ip);
            break;
        }
    }

    if (iface_ip && iface_ip[0] != '\0')
    {
        struct in_addr iface_addr;
        if (inet_pton(AF_INET, iface_ip, &iface_addr) == 1)
        {
            /* Bind source IP for outbound SSDP */
            struct sockaddr_in src;
            memset(&src, 0, sizeof(src));
            src.sin_family = AF_INET;
            src.sin_port = 0;
            src.sin_addr = iface_addr;
            if (bind(sock, (struct sockaddr *)&src, sizeof(src)) != 0)
            {
                LP_LOGW("NAT", "SSDP bind to %s failed: %s", iface_ip, strerror(errno));
            }
            /* Ensure multicast uses the selected interface */
            if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF, &iface_addr, sizeof(iface_addr)) != 0)
            {
                LP_LOGW("NAT", "SSDP IP_MULTICAST_IF %s failed: %s", iface_ip, strerror(errno));
            }
            else
            {
                LP_LOGI("NAT", "SSDP using interface IP %s", iface_ip);
                fprintf(stderr, "[NAT] SSDP using interface IP %s\n", iface_ip);
            }
        }
        else
        {
            LP_LOGW("NAT", "SSDP interface IP invalid: %s", iface_ip);
            fprintf(stderr, "[NAT] SSDP interface IP invalid: %s\n", iface_ip);
        }
    }
    
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(SSDP_PORT);
    inet_pton(AF_INET, SSDP_MULTICAST_ADDR, &dest.sin_addr);
    
    /* Send SSDP search for WANIPConnection service */
    fprintf(stderr, "[NAT] SSDP sending WANIP M-SEARCH to %s:%d\n", SSDP_MULTICAST_ADDR, SSDP_PORT);
    if (sendto(sock, SSDP_SEARCH_WANIP, strlen(SSDP_SEARCH_WANIP), 0,
               (struct sockaddr *)&dest, sizeof(dest)) < 0)
    {
        LP_LOGW("NAT", "SSDP sendto failed: %s", strerror(errno));
        fprintf(stderr, "[NAT] SSDP sendto WANIP failed: %s\n", strerror(errno));
    }
    
    /* Also search for IGD device */
    fprintf(stderr, "[NAT] SSDP sending IGD M-SEARCH to %s:%d\n", SSDP_MULTICAST_ADDR, SSDP_PORT);
    if (sendto(sock, SSDP_SEARCH_IGD, strlen(SSDP_SEARCH_IGD), 0,
               (struct sockaddr *)&dest, sizeof(dest)) < 0)
    {
        LP_LOGW("NAT", "SSDP sendto failed: %s", strerror(errno));
        fprintf(stderr, "[NAT] SSDP sendto IGD failed: %s\n", strerror(errno));
    }
    
    /* Wait for responses */
    char response[MAX_RESPONSE_SIZE];
    struct pollfd pfd = {.fd = sock, .events = POLLIN};
    
    int64_t deadline_ms = (int64_t)time(NULL) * 1000 + timeout_ms;
    
    while (1)
    {
        int64_t now_ms = (int64_t)time(NULL) * 1000;
        int remaining = (int)(deadline_ms - now_ms);
        if (remaining <= 0)
            break;
        
        int ret = poll(&pfd, 1, remaining > 1000 ? 1000 : remaining);
        if (ret <= 0)
            continue;
        
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);
        ssize_t n = recvfrom(sock, response, sizeof(response) - 1, 0,
                             (struct sockaddr *)&from, &from_len);
        if (n <= 0)
            continue;
        
        response[n] = '\0';

        {
            char from_ip[INET_ADDRSTRLEN] = {0};
            inet_ntop(AF_INET, &from.sin_addr, from_ip, sizeof(from_ip));
            fprintf(stderr, "[NAT] SSDP response from %s:%u (%zd bytes)\n",
                    from_ip, ntohs(from.sin_port), n);
        }
        
        /* Check if this is a valid UPnP response */
        if (strstr(response, "200 OK") == NULL)
            continue;
        
        /* Look for WANIPConnection or WANPPPConnection */
        if (strstr(response, "WANIPConnection") == NULL &&
            strstr(response, "WANPPPConnection") == NULL)
            continue;
        
        /* Extract location URL */
        char *location = find_header(response, "LOCATION");
        if (!location)
            continue;
        
        LP_LOGI("NAT", "Found UPnP gateway at %s", location);
        
        /* Store gateway info */
        if (!svc->upnp)
        {
            svc->upnp = calloc(1, sizeof(upnp_gateway_t));
            if (!svc->upnp)
            {
                free(location);
                continue;
            }
        }
        
        free(svc->upnp->location_url);
        svc->upnp->location_url = location;
        svc->upnp->addr = from;
        
        close(sock);
        return LIBP2P_NAT_OK;
    }
    
    close(sock);
    return LIBP2P_NAT_ERR_NO_GATEWAY;
}

static int upnp_fetch_description(libp2p_nat_service_t *svc)
{
    if (!svc->upnp || !svc->upnp->location_url)
        return LIBP2P_NAT_ERR_INTERNAL;
    
    /* Parse URL to get host, port, path */
    char host[256] = {0};
    int port = 80;
    char path[512] = "/";
    
    const char *url = svc->upnp->location_url;
    if (strncmp(url, "http://", 7) == 0)
        url += 7;
    
    const char *path_start = strchr(url, '/');
    const char *port_start = strchr(url, ':');
    
    if (port_start && (!path_start || port_start < path_start))
    {
        size_t host_len = port_start - url;
        if (host_len >= sizeof(host))
            host_len = sizeof(host) - 1;
        memcpy(host, url, host_len);
        port = atoi(port_start + 1);
    }
    else if (path_start)
    {
        size_t host_len = path_start - url;
        if (host_len >= sizeof(host))
            host_len = sizeof(host) - 1;
        memcpy(host, url, host_len);
    }
    else
    {
        strncpy(host, url, sizeof(host) - 1);
    }
    
    if (path_start)
        strncpy(path, path_start, sizeof(path) - 1);
    
    /* Connect to the gateway */
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
        return LIBP2P_NAT_ERR_INTERNAL;
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    
    struct hostent *he = gethostbyname(host);
    if (!he)
    {
        close(sock);
        return LIBP2P_NAT_ERR_INTERNAL;
    }
    memcpy(&addr.sin_addr, he->h_addr, he->h_length);
    
    struct timeval tv = {.tv_sec = 5, .tv_usec = 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        close(sock);
        return LIBP2P_NAT_ERR_INTERNAL;
    }
    
    /* Send HTTP GET request */
    char request[1024];
    snprintf(request, sizeof(request),
             "GET %s HTTP/1.1\r\n"
             "Host: %s:%d\r\n"
             "Connection: close\r\n"
             "\r\n",
             path, host, port);
    
    if (send(sock, request, strlen(request), 0) < 0)
    {
        close(sock);
        return LIBP2P_NAT_ERR_INTERNAL;
    }
    
    /* Read response */
    char *response = malloc(MAX_RESPONSE_SIZE * 4);
    if (!response)
    {
        close(sock);
        return LIBP2P_NAT_ERR_INTERNAL;
    }
    
    size_t total = 0;
    ssize_t n;
    while ((n = recv(sock, response + total, MAX_RESPONSE_SIZE * 4 - total - 1, 0)) > 0)
    {
        total += n;
        if (total >= MAX_RESPONSE_SIZE * 4 - 1)
            break;
    }
    response[total] = '\0';
    close(sock);
    
    /* Parse XML to find control URL */
    /* Look for WANIPConnection or WANPPPConnection service */
    char *service_start = strstr(response, "WANIPConnection");
    if (!service_start)
        service_start = strstr(response, "WANPPPConnection");
    
    if (!service_start)
    {
        free(response);
        return LIBP2P_NAT_ERR_NO_GATEWAY;
    }
    
    /* Find controlURL within this service block */
    char *control_url = extract_xml_value(service_start, "controlURL");
    if (!control_url)
    {
        free(response);
        return LIBP2P_NAT_ERR_NO_GATEWAY;
    }
    
    /* Make absolute URL if relative */
    if (control_url[0] == '/')
    {
        char *abs_url = malloc(strlen(host) + 16 + strlen(control_url));
        if (abs_url)
        {
            sprintf(abs_url, "http://%s:%d%s", host, port, control_url);
            free(control_url);
            control_url = abs_url;
        }
    }
    
    free(svc->upnp->control_url);
    svc->upnp->control_url = control_url;
    
    /* Determine service type */
    if (strstr(response, "WANPPPConnection"))
        svc->upnp->service_type = strdup("urn:schemas-upnp-org:service:WANPPPConnection:1");
    else
        svc->upnp->service_type = strdup("urn:schemas-upnp-org:service:WANIPConnection:1");
    
    LP_LOGI("NAT", "UPnP control URL: %s", svc->upnp->control_url);
    
    free(response);
    return LIBP2P_NAT_OK;
}

static int upnp_soap_action(libp2p_nat_service_t *svc,
                            const char *action,
                            const char *args,
                            char **response_out)
{
    if (!svc->upnp || !svc->upnp->control_url)
        return LIBP2P_NAT_ERR_INTERNAL;
    
    /* Parse control URL */
    char host[256] = {0};
    int port = 80;
    char path[512] = "/";
    
    const char *url = svc->upnp->control_url;
    if (strncmp(url, "http://", 7) == 0)
        url += 7;
    
    const char *path_start = strchr(url, '/');
    const char *port_start = strchr(url, ':');
    
    if (port_start && (!path_start || port_start < path_start))
    {
        size_t host_len = port_start - url;
        if (host_len >= sizeof(host))
            host_len = sizeof(host) - 1;
        memcpy(host, url, host_len);
        port = atoi(port_start + 1);
    }
    else if (path_start)
    {
        size_t host_len = path_start - url;
        if (host_len >= sizeof(host))
            host_len = sizeof(host) - 1;
        memcpy(host, url, host_len);
    }
    else
    {
        strncpy(host, url, sizeof(host) - 1);
    }
    
    if (path_start)
        strncpy(path, path_start, sizeof(path) - 1);
    
    /* Build SOAP envelope */
    char body[2048];
    snprintf(body, sizeof(body),
             "<?xml version=\"1.0\"?>\r\n"
             "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
             "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\r\n"
             "<s:Body>\r\n"
             "<u:%s xmlns:u=\"%s\">\r\n"
             "%s"
             "</u:%s>\r\n"
             "</s:Body>\r\n"
             "</s:Envelope>\r\n",
             action, svc->upnp->service_type ? svc->upnp->service_type : "urn:schemas-upnp-org:service:WANIPConnection:1",
             args ? args : "",
             action);
    
    /* Connect */
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
        return LIBP2P_NAT_ERR_INTERNAL;
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    
    struct hostent *he = gethostbyname(host);
    if (!he)
    {
        close(sock);
        return LIBP2P_NAT_ERR_INTERNAL;
    }
    memcpy(&addr.sin_addr, he->h_addr, he->h_length);
    
    struct timeval tv = {.tv_sec = 5, .tv_usec = 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        close(sock);
        return LIBP2P_NAT_ERR_INTERNAL;
    }
    
    /* Build HTTP POST */
    char header[1024];
    snprintf(header, sizeof(header),
             "POST %s HTTP/1.1\r\n"
             "Host: %s:%d\r\n"
             "Content-Type: text/xml; charset=\"utf-8\"\r\n"
             "Content-Length: %zu\r\n"
             "SOAPAction: \"%s#%s\"\r\n"
             "Connection: close\r\n"
             "\r\n",
             path, host, port, strlen(body),
             svc->upnp->service_type ? svc->upnp->service_type : "urn:schemas-upnp-org:service:WANIPConnection:1",
             action);
    
    if (send(sock, header, strlen(header), 0) < 0 ||
        send(sock, body, strlen(body), 0) < 0)
    {
        close(sock);
        return LIBP2P_NAT_ERR_INTERNAL;
    }
    
    /* Read response */
    char *response = malloc(MAX_RESPONSE_SIZE);
    if (!response)
    {
        close(sock);
        return LIBP2P_NAT_ERR_INTERNAL;
    }
    
    size_t total = 0;
    ssize_t n;
    while ((n = recv(sock, response + total, MAX_RESPONSE_SIZE - total - 1, 0)) > 0)
    {
        total += n;
        if (total >= MAX_RESPONSE_SIZE - 1)
            break;
    }
    response[total] = '\0';
    close(sock);
    
    /* Check for success */
    if (strstr(response, "200 OK") == NULL)
    {
        LP_LOGW("NAT", "UPnP SOAP action %s failed: %.*s", action, 200, response);
        free(response);
        return LIBP2P_NAT_ERR_MAPPING_FAILED;
    }
    
    if (response_out)
        *response_out = response;
    else
        free(response);
    
    return LIBP2P_NAT_OK;
}

static int upnp_get_external_ip(libp2p_nat_service_t *svc)
{
    char *response = NULL;
    int ret = upnp_soap_action(svc, "GetExternalIPAddress", "", &response);
    if (ret != LIBP2P_NAT_OK)
        return ret;
    
    char *ip = extract_xml_value(response, "NewExternalIPAddress");
    free(response);
    
    if (!ip)
        return LIBP2P_NAT_ERR_INTERNAL;
    
    free(svc->upnp->external_ip);
    svc->upnp->external_ip = ip;
    
    LP_LOGI("NAT", "UPnP external IP: %s", ip);
    return LIBP2P_NAT_OK;
}

static int upnp_add_port_mapping(libp2p_nat_service_t *svc,
                                  uint16_t internal_port,
                                  uint16_t external_port,
                                  int is_tcp,
                                  uint32_t lifetime)
{
    /* Get local IP address */
    char local_ip[INET_ADDRSTRLEN] = "0.0.0.0";
    
    /* Try to get local IP by connecting to gateway */
    int probe_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (probe_sock >= 0)
    {
        if (connect(probe_sock, (struct sockaddr *)&svc->upnp->addr, sizeof(svc->upnp->addr)) == 0)
        {
            struct sockaddr_in local;
            socklen_t local_len = sizeof(local);
            if (getsockname(probe_sock, (struct sockaddr *)&local, &local_len) == 0)
            {
                inet_ntop(AF_INET, &local.sin_addr, local_ip, sizeof(local_ip));
            }
        }
        close(probe_sock);
    }
    
    char args[1024];
    snprintf(args, sizeof(args),
             "<NewRemoteHost></NewRemoteHost>\r\n"
             "<NewExternalPort>%u</NewExternalPort>\r\n"
             "<NewProtocol>%s</NewProtocol>\r\n"
             "<NewInternalPort>%u</NewInternalPort>\r\n"
             "<NewInternalClient>%s</NewInternalClient>\r\n"
             "<NewEnabled>1</NewEnabled>\r\n"
             "<NewPortMappingDescription>%s</NewPortMappingDescription>\r\n"
             "<NewLeaseDuration>%u</NewLeaseDuration>\r\n",
             external_port,
             is_tcp ? "TCP" : "UDP",
             internal_port,
             local_ip,
             svc->opts.description ? svc->opts.description : "libp2p",
             lifetime);
    
    int ret = upnp_soap_action(svc, "AddPortMapping", args, NULL);
    if (ret == LIBP2P_NAT_OK)
    {
        LP_LOGI("NAT", "UPnP port mapping added: %s %s:%u -> %u (lifetime=%u)",
                is_tcp ? "TCP" : "UDP", local_ip, internal_port, external_port, lifetime);
    }
    return ret;
}

static int upnp_delete_port_mapping(libp2p_nat_service_t *svc,
                                     uint16_t external_port,
                                     int is_tcp)
{
    char args[512];
    snprintf(args, sizeof(args),
             "<NewRemoteHost></NewRemoteHost>\r\n"
             "<NewExternalPort>%u</NewExternalPort>\r\n"
             "<NewProtocol>%s</NewProtocol>\r\n",
             external_port,
             is_tcp ? "TCP" : "UDP");
    
    return upnp_soap_action(svc, "DeletePortMapping", args, NULL);
}

/* ======================= NAT-PMP Implementation ======================= */

static int natpmp_discover_gateway(libp2p_nat_service_t *svc, int timeout_ms)
{
    /* NAT-PMP gateway is typically the default gateway */
    /* Try to find it by checking common gateway addresses */
    
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        return LIBP2P_NAT_ERR_INTERNAL;
    
    set_nonblocking(sock);
    
    /* Try common gateway addresses */
    const char *gateways[] = {"192.168.1.1", "192.168.0.1", "10.0.0.1", "172.16.0.1"};
    
    uint8_t request[2] = {NATPMP_VERSION, NATPMP_OP_EXTERNAL_ADDR};
    
    for (size_t i = 0; i < sizeof(gateways) / sizeof(gateways[0]); i++)
    {
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_port = htons(NATPMP_PORT);
        inet_pton(AF_INET, gateways[i], &dest.sin_addr);
        
        sendto(sock, request, sizeof(request), 0, (struct sockaddr *)&dest, sizeof(dest));
    }
    
    /* Wait for response */
    struct pollfd pfd = {.fd = sock, .events = POLLIN};
    int64_t deadline_ms = (int64_t)time(NULL) * 1000 + timeout_ms;
    
    while (1)
    {
        int64_t now_ms = (int64_t)time(NULL) * 1000;
        int remaining = (int)(deadline_ms - now_ms);
        if (remaining <= 0)
            break;
        
        int ret = poll(&pfd, 1, remaining > 500 ? 500 : remaining);
        if (ret <= 0)
            continue;
        
        uint8_t response[16];
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);
        ssize_t n = recvfrom(sock, response, sizeof(response), 0,
                             (struct sockaddr *)&from, &from_len);
        
        if (n >= 12 && response[0] == 0 && response[1] == 128)
        {
            /* Valid NAT-PMP response */
            uint16_t result = (response[2] << 8) | response[3];
            if (result == NATPMP_RESULT_SUCCESS)
            {
                if (!svc->natpmp)
                {
                    svc->natpmp = calloc(1, sizeof(natpmp_gateway_t));
                    if (!svc->natpmp)
                    {
                        close(sock);
                        return LIBP2P_NAT_ERR_INTERNAL;
                    }
                }
                
                svc->natpmp->addr = from;
                svc->natpmp->epoch = (response[4] << 24) | (response[5] << 16) |
                                     (response[6] << 8) | response[7];
                
                /* Extract external IP */
                char ip[INET_ADDRSTRLEN];
                snprintf(ip, sizeof(ip), "%u.%u.%u.%u",
                         response[8], response[9], response[10], response[11]);
                free(svc->natpmp->external_ip);
                svc->natpmp->external_ip = strdup(ip);
                
                LP_LOGI("NAT", "NAT-PMP gateway found, external IP: %s", ip);
                close(sock);
                return LIBP2P_NAT_OK;
            }
        }
    }
    
    close(sock);
    return LIBP2P_NAT_ERR_NO_GATEWAY;
}

static int natpmp_add_mapping(libp2p_nat_service_t *svc,
                               uint16_t internal_port,
                               uint16_t external_port,
                               int is_tcp,
                               uint32_t lifetime,
                               uint16_t *assigned_port)
{
    if (!svc->natpmp)
        return LIBP2P_NAT_ERR_INTERNAL;
    
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        return LIBP2P_NAT_ERR_INTERNAL;
    
    set_nonblocking(sock);
    
    uint8_t request[12];
    request[0] = NATPMP_VERSION;
    request[1] = is_tcp ? NATPMP_OP_MAP_TCP : NATPMP_OP_MAP_UDP;
    request[2] = 0; /* reserved */
    request[3] = 0;
    request[4] = (internal_port >> 8) & 0xFF;
    request[5] = internal_port & 0xFF;
    request[6] = (external_port >> 8) & 0xFF;
    request[7] = external_port & 0xFF;
    request[8] = (lifetime >> 24) & 0xFF;
    request[9] = (lifetime >> 16) & 0xFF;
    request[10] = (lifetime >> 8) & 0xFF;
    request[11] = lifetime & 0xFF;
    
    if (sendto(sock, request, sizeof(request), 0,
               (struct sockaddr *)&svc->natpmp->addr, sizeof(svc->natpmp->addr)) < 0)
    {
        close(sock);
        return LIBP2P_NAT_ERR_INTERNAL;
    }
    
    /* Wait for response */
    struct pollfd pfd = {.fd = sock, .events = POLLIN};
    if (poll(&pfd, 1, 5000) <= 0)
    {
        close(sock);
        return LIBP2P_NAT_ERR_TIMEOUT;
    }
    
    uint8_t response[16];
    ssize_t n = recv(sock, response, sizeof(response), 0);
    close(sock);
    
    if (n < 16)
        return LIBP2P_NAT_ERR_INTERNAL;
    
    uint16_t result = (response[2] << 8) | response[3];
    if (result != NATPMP_RESULT_SUCCESS)
        return LIBP2P_NAT_ERR_MAPPING_FAILED;
    
    if (assigned_port)
    {
        *assigned_port = (response[10] << 8) | response[11];
    }
    
    LP_LOGI("NAT", "NAT-PMP mapping added: %s internal=%u external=%u",
            is_tcp ? "TCP" : "UDP", internal_port,
            (response[10] << 8) | response[11]);
    
    return LIBP2P_NAT_OK;
}

static int natpmp_delete_mapping(libp2p_nat_service_t *svc,
                                  uint16_t internal_port,
                                  int is_tcp)
{
    /* Delete by requesting 0 lifetime */
    return natpmp_add_mapping(svc, internal_port, 0, is_tcp, 0, NULL);
}

/* ======================= Refresh Thread ======================= */

static void *nat_refresh_thread(void *arg)
{
    libp2p_nat_service_t *svc = (libp2p_nat_service_t *)arg;
    
    int refresh_interval = svc->opts.refresh_interval_secs;
    if (refresh_interval <= 0)
        refresh_interval = svc->opts.mapping_lifetime_secs / 2;
    if (refresh_interval < 60)
        refresh_interval = 60;
    
    while (!svc->stop_flag)
    {
        sleep(refresh_interval);
        
        if (svc->stop_flag)
            break;
        
        pthread_mutex_lock(&svc->mtx);
        
        for (mapping_entry_t *m = svc->mappings; m; m = m->next)
        {
            if (svc->active_proto == LIBP2P_NAT_PROTO_UPNP && svc->upnp)
            {
                upnp_add_port_mapping(svc, m->internal_port, m->external_port,
                                      m->is_tcp, svc->opts.mapping_lifetime_secs);
            }
            else if (svc->active_proto == LIBP2P_NAT_PROTO_NATPMP && svc->natpmp)
            {
                natpmp_add_mapping(svc, m->internal_port, m->external_port,
                                   m->is_tcp, svc->opts.mapping_lifetime_secs, NULL);
            }
            m->last_refresh = time(NULL);
        }
        
        pthread_mutex_unlock(&svc->mtx);
    }
    
    return NULL;
}

/* ======================= Public API ======================= */

void libp2p_nat_opts_default(libp2p_nat_opts_t *opts)
{
    if (!opts)
        return;
    
    memset(opts, 0, sizeof(*opts));
    opts->struct_size = sizeof(*opts);
    opts->protocol = LIBP2P_NAT_PROTO_AUTO;
    opts->discovery_timeout_ms = DEFAULT_DISCOVERY_TIMEOUT_MS;
    opts->mapping_lifetime_secs = DEFAULT_MAPPING_LIFETIME_SECS;
    opts->refresh_interval_secs = 0; /* Will use lifetime/2 */
    opts->retry_attempts = DEFAULT_RETRY_ATTEMPTS;
    opts->retry_delay_ms = DEFAULT_RETRY_DELAY_MS;
    opts->enable_auto_refresh = true;
    opts->description = "libp2p";
}

int libp2p_nat_new(libp2p_host_t *host, const libp2p_nat_opts_t *opts, libp2p_nat_service_t **out)
{
    if (!host || !out)
        return LIBP2P_NAT_ERR_NULL_PTR;
    
    libp2p_nat_service_t *svc = calloc(1, sizeof(*svc));
    if (!svc)
        return LIBP2P_NAT_ERR_INTERNAL;
    
    svc->host = host;
    
    if (opts)
    {
        svc->opts = *opts;
    }
    else
    {
        libp2p_nat_opts_default(&svc->opts);
    }
    
    pthread_mutex_init(&svc->mtx, NULL);
    svc->status = LIBP2P_NAT_STATUS_INACTIVE;
    
    *out = svc;
    return LIBP2P_NAT_OK;
}

void libp2p_nat_free(libp2p_nat_service_t *svc)
{
    if (!svc)
        return;
    
    libp2p_nat_stop(svc);
    
    /* Free UPnP resources */
    if (svc->upnp)
    {
        free(svc->upnp->location_url);
        free(svc->upnp->control_url);
        free(svc->upnp->service_type);
        free(svc->upnp->external_ip);
        free(svc->upnp);
    }
    
    /* Free NAT-PMP resources */
    if (svc->natpmp)
    {
        free(svc->natpmp->external_ip);
        free(svc->natpmp);
    }
    
    /* Free mappings */
    mapping_entry_t *m = svc->mappings;
    while (m)
    {
        mapping_entry_t *next = m->next;
        free(m);
        m = next;
    }
    
    pthread_mutex_destroy(&svc->mtx);
    free(svc);
}

int libp2p_nat_start(libp2p_nat_service_t *svc)
{
    if (!svc)
        return LIBP2P_NAT_ERR_NULL_PTR;
    
    fprintf(stderr, "[NAT] libp2p_nat_start called\n");
    pthread_mutex_lock(&svc->mtx);
    
    if (svc->status == LIBP2P_NAT_STATUS_ACTIVE)
    {
        pthread_mutex_unlock(&svc->mtx);
        return LIBP2P_NAT_OK;
    }
    
    svc->status = LIBP2P_NAT_STATUS_DISCOVERING;
    pthread_mutex_unlock(&svc->mtx);
    
    int ret = LIBP2P_NAT_ERR_NO_GATEWAY;
    LP_LOGI("NAT", "Starting NAT discovery (protocol=%d)", svc->opts.protocol);
    
    /* Try discovery based on protocol preference */
    if (svc->opts.protocol == LIBP2P_NAT_PROTO_AUTO ||
        svc->opts.protocol == LIBP2P_NAT_PROTO_UPNP)
    {
        ret = upnp_discover_gateway(svc, svc->opts.discovery_timeout_ms);
        if (ret == LIBP2P_NAT_OK)
        {
            ret = upnp_fetch_description(svc);
            if (ret == LIBP2P_NAT_OK)
            {
                upnp_get_external_ip(svc);
                svc->active_proto = LIBP2P_NAT_PROTO_UPNP;
            }
            else
            {
                LP_LOGW("NAT", "UPnP fetch description failed: %d", ret);
            }
        }
        else
        {
            LP_LOGW("NAT", "UPnP discovery failed: %d", ret);
        }
    }
    
    if (ret != LIBP2P_NAT_OK &&
        (svc->opts.protocol == LIBP2P_NAT_PROTO_AUTO ||
         svc->opts.protocol == LIBP2P_NAT_PROTO_NATPMP))
    {
        ret = natpmp_discover_gateway(svc, svc->opts.discovery_timeout_ms);
        if (ret == LIBP2P_NAT_OK)
        {
            svc->active_proto = LIBP2P_NAT_PROTO_NATPMP;
        }
        else
        {
            LP_LOGW("NAT", "NAT-PMP discovery failed: %d", ret);
        }
    }
    
    pthread_mutex_lock(&svc->mtx);
    if (ret == LIBP2P_NAT_OK)
    {
        svc->status = LIBP2P_NAT_STATUS_ACTIVE;
        LP_LOGI("NAT", "NAT discovery successful (active_proto=%d)", svc->active_proto);
        
        /* Start refresh thread if enabled */
        if (svc->opts.enable_auto_refresh)
        {
            svc->stop_flag = 0;
            if (pthread_create(&svc->refresh_thread, NULL, nat_refresh_thread, svc) == 0)
            {
                svc->refresh_running = 1;
            }
        }
    }
    else
    {
        svc->status = LIBP2P_NAT_STATUS_NOT_FOUND;
        LP_LOGW("NAT", "NAT discovery failed; no gateway found");
    }
    pthread_mutex_unlock(&svc->mtx);
    
    return ret;
}

void libp2p_nat_stop(libp2p_nat_service_t *svc)
{
    if (!svc)
        return;
    
    pthread_mutex_lock(&svc->mtx);
    svc->stop_flag = 1;
    
    /* Remove all mappings */
    for (mapping_entry_t *m = svc->mappings; m; m = m->next)
    {
        if (svc->active_proto == LIBP2P_NAT_PROTO_UPNP && svc->upnp)
        {
            upnp_delete_port_mapping(svc, m->external_port, m->is_tcp);
        }
        else if (svc->active_proto == LIBP2P_NAT_PROTO_NATPMP && svc->natpmp)
        {
            natpmp_delete_mapping(svc, m->internal_port, m->is_tcp);
        }
    }
    
    svc->status = LIBP2P_NAT_STATUS_INACTIVE;
    pthread_mutex_unlock(&svc->mtx);
    
    /* Wait for refresh thread */
    if (svc->refresh_running)
    {
        pthread_join(svc->refresh_thread, NULL);
        svc->refresh_running = 0;
    }
}

int libp2p_nat_add_mapping(libp2p_nat_service_t *svc,
                           uint16_t internal_port,
                           uint16_t external_port,
                           int is_tcp,
                           libp2p_nat_mapping_t **mapping)
{
    if (!svc)
        return LIBP2P_NAT_ERR_NULL_PTR;
    
    if (svc->status != LIBP2P_NAT_STATUS_ACTIVE)
        return LIBP2P_NAT_ERR_INTERNAL;
    
    pthread_mutex_lock(&svc->mtx);
    
    /* Check if already mapped */
    for (mapping_entry_t *m = svc->mappings; m; m = m->next)
    {
        if (m->internal_port == internal_port && m->is_tcp == is_tcp)
        {
            pthread_mutex_unlock(&svc->mtx);
            return LIBP2P_NAT_ERR_ALREADY_MAPPED;
        }
    }
    
    if (external_port == 0)
        external_port = internal_port;
    
    int ret;
    uint16_t assigned_port = external_port;
    
    if (svc->active_proto == LIBP2P_NAT_PROTO_UPNP && svc->upnp)
    {
        ret = upnp_add_port_mapping(svc, internal_port, external_port,
                                    is_tcp, svc->opts.mapping_lifetime_secs);
    }
    else if (svc->active_proto == LIBP2P_NAT_PROTO_NATPMP && svc->natpmp)
    {
        ret = natpmp_add_mapping(svc, internal_port, external_port,
                                 is_tcp, svc->opts.mapping_lifetime_secs, &assigned_port);
    }
    else
    {
        pthread_mutex_unlock(&svc->mtx);
        return LIBP2P_NAT_ERR_INTERNAL;
    }
    
    if (ret != LIBP2P_NAT_OK)
    {
        LP_LOGW("NAT", "Port mapping failed (proto=%d, %s internal=%u external=%u): %d",
                svc->active_proto, is_tcp ? "tcp" : "udp", internal_port, external_port, ret);
        pthread_mutex_unlock(&svc->mtx);
        return ret;
    }
    
    /* Store mapping */
    mapping_entry_t *entry = calloc(1, sizeof(*entry));
    if (!entry)
    {
        pthread_mutex_unlock(&svc->mtx);
        return LIBP2P_NAT_ERR_INTERNAL;
    }
    
    entry->internal_port = internal_port;
    entry->external_port = assigned_port;
    entry->is_tcp = is_tcp;
    entry->lifetime_secs = svc->opts.mapping_lifetime_secs;
    entry->created_at = time(NULL);
    entry->last_refresh = entry->created_at;
    entry->next = svc->mappings;
    svc->mappings = entry;
    svc->mapping_count++;
    
    pthread_mutex_unlock(&svc->mtx);
    
    /* Return mapping info if requested */
    if (mapping)
    {
        *mapping = calloc(1, sizeof(libp2p_nat_mapping_t));
        if (*mapping)
        {
            (*mapping)->internal_port = internal_port;
            (*mapping)->external_port = assigned_port;
            (*mapping)->is_tcp = is_tcp;
            (*mapping)->lifetime_secs = svc->opts.mapping_lifetime_secs;
            (*mapping)->proto = svc->active_proto;
            
            /* Set external address */
            if (svc->active_proto == LIBP2P_NAT_PROTO_UPNP && svc->upnp && svc->upnp->external_ip)
            {
                (*mapping)->external_addr = strdup(svc->upnp->external_ip);
            }
            else if (svc->active_proto == LIBP2P_NAT_PROTO_NATPMP && svc->natpmp && svc->natpmp->external_ip)
            {
                (*mapping)->external_addr = strdup(svc->natpmp->external_ip);
            }
        }
    }
    
    /* Notify callback */
    if (svc->cb && mapping && *mapping)
    {
        svc->cb(*mapping, LIBP2P_NAT_STATUS_ACTIVE, svc->cb_user_data);
    }
    
    return LIBP2P_NAT_OK;
}

int libp2p_nat_remove_mapping(libp2p_nat_service_t *svc,
                               uint16_t internal_port,
                               int is_tcp)
{
    if (!svc)
        return LIBP2P_NAT_ERR_NULL_PTR;
    
    pthread_mutex_lock(&svc->mtx);
    
    mapping_entry_t *prev = NULL;
    mapping_entry_t *m = svc->mappings;
    
    while (m)
    {
        if (m->internal_port == internal_port && m->is_tcp == is_tcp)
        {
            /* Remove from gateway */
            if (svc->active_proto == LIBP2P_NAT_PROTO_UPNP && svc->upnp)
            {
                upnp_delete_port_mapping(svc, m->external_port, is_tcp);
            }
            else if (svc->active_proto == LIBP2P_NAT_PROTO_NATPMP && svc->natpmp)
            {
                natpmp_delete_mapping(svc, internal_port, is_tcp);
            }
            
            /* Remove from list */
            if (prev)
                prev->next = m->next;
            else
                svc->mappings = m->next;
            
            free(m);
            svc->mapping_count--;
            
            pthread_mutex_unlock(&svc->mtx);
            return LIBP2P_NAT_OK;
        }
        prev = m;
        m = m->next;
    }
    
    pthread_mutex_unlock(&svc->mtx);
    return LIBP2P_NAT_ERR_INTERNAL;
}

int libp2p_nat_get_external_addr(libp2p_nat_service_t *svc, char **out)
{
    if (!svc || !out)
        return LIBP2P_NAT_ERR_NULL_PTR;
    
    pthread_mutex_lock(&svc->mtx);
    
    const char *ip = NULL;
    if (svc->active_proto == LIBP2P_NAT_PROTO_UPNP && svc->upnp)
    {
        ip = svc->upnp->external_ip;
    }
    else if (svc->active_proto == LIBP2P_NAT_PROTO_NATPMP && svc->natpmp)
    {
        ip = svc->natpmp->external_ip;
    }
    
    if (!ip)
    {
        pthread_mutex_unlock(&svc->mtx);
        return LIBP2P_NAT_ERR_INTERNAL;
    }
    
    *out = strdup(ip);
    pthread_mutex_unlock(&svc->mtx);
    
    return *out ? LIBP2P_NAT_OK : LIBP2P_NAT_ERR_INTERNAL;
}

int libp2p_nat_get_external_multiaddr(libp2p_nat_service_t *svc,
                                       const multiaddr_t *local_addr,
                                       multiaddr_t **out)
{
    if (!svc || !local_addr || !out)
        return LIBP2P_NAT_ERR_NULL_PTR;
    
    char *external_ip = NULL;
    int ret = libp2p_nat_get_external_addr(svc, &external_ip);
    if (ret != LIBP2P_NAT_OK)
        return ret;
    
    /* Get port from local addr */
    int ma_err = 0;
    char *local_str = multiaddr_to_str(local_addr, &ma_err);
    if (!local_str)
    {
        free(external_ip);
        return LIBP2P_NAT_ERR_INTERNAL;
    }
    
    /* Parse port from local address */
    char *tcp_pos = strstr(local_str, "/tcp/");
    if (!tcp_pos)
    {
        free(local_str);
        free(external_ip);
        return LIBP2P_NAT_ERR_UNSUPPORTED;
    }
    
    uint16_t port = (uint16_t)atoi(tcp_pos + 5);
    free(local_str);
    
    /* Look up mapped port */
    pthread_mutex_lock(&svc->mtx);
    for (mapping_entry_t *m = svc->mappings; m; m = m->next)
    {
        if (m->internal_port == port && m->is_tcp)
        {
            port = m->external_port;
            break;
        }
    }
    pthread_mutex_unlock(&svc->mtx);
    
    /* Build external multiaddr */
    char ma_str[128];
    snprintf(ma_str, sizeof(ma_str), "/ip4/%s/tcp/%u", external_ip, port);
    free(external_ip);
    
    *out = multiaddr_new_from_str(ma_str, &ma_err);
    return (*out && ma_err == 0) ? LIBP2P_NAT_OK : LIBP2P_NAT_ERR_INTERNAL;
}

int libp2p_nat_on_mapping_change(libp2p_nat_service_t *svc,
                                  libp2p_nat_mapping_cb cb,
                                  void *user_data)
{
    if (!svc)
        return LIBP2P_NAT_ERR_NULL_PTR;
    
    pthread_mutex_lock(&svc->mtx);
    svc->cb = cb;
    svc->cb_user_data = user_data;
    pthread_mutex_unlock(&svc->mtx);
    
    return LIBP2P_NAT_OK;
}

libp2p_nat_status_t libp2p_nat_status(libp2p_nat_service_t *svc)
{
    if (!svc)
        return LIBP2P_NAT_STATUS_INACTIVE;
    
    pthread_mutex_lock(&svc->mtx);
    libp2p_nat_status_t status = svc->status;
    pthread_mutex_unlock(&svc->mtx);
    
    return status;
}

int libp2p_nat_get_mappings(libp2p_nat_service_t *svc,
                             libp2p_nat_mapping_t ***mappings,
                             size_t *count)
{
    if (!svc || !mappings || !count)
        return LIBP2P_NAT_ERR_NULL_PTR;
    
    pthread_mutex_lock(&svc->mtx);
    
    *count = svc->mapping_count;
    if (*count == 0)
    {
        *mappings = NULL;
        pthread_mutex_unlock(&svc->mtx);
        return LIBP2P_NAT_OK;
    }
    
    *mappings = calloc(*count, sizeof(libp2p_nat_mapping_t *));
    if (!*mappings)
    {
        pthread_mutex_unlock(&svc->mtx);
        return LIBP2P_NAT_ERR_INTERNAL;
    }
    
    size_t i = 0;
    for (mapping_entry_t *m = svc->mappings; m && i < *count; m = m->next, i++)
    {
        (*mappings)[i] = calloc(1, sizeof(libp2p_nat_mapping_t));
        if ((*mappings)[i])
        {
            (*mappings)[i]->internal_port = m->internal_port;
            (*mappings)[i]->external_port = m->external_port;
            (*mappings)[i]->is_tcp = m->is_tcp;
            (*mappings)[i]->lifetime_secs = m->lifetime_secs;
            (*mappings)[i]->proto = svc->active_proto;
            
            if (svc->active_proto == LIBP2P_NAT_PROTO_UPNP && svc->upnp && svc->upnp->external_ip)
            {
                (*mappings)[i]->external_addr = strdup(svc->upnp->external_ip);
            }
            else if (svc->active_proto == LIBP2P_NAT_PROTO_NATPMP && svc->natpmp && svc->natpmp->external_ip)
            {
                (*mappings)[i]->external_addr = strdup(svc->natpmp->external_ip);
            }
        }
    }
    
    pthread_mutex_unlock(&svc->mtx);
    return LIBP2P_NAT_OK;
}

void libp2p_nat_mapping_free(libp2p_nat_mapping_t *mapping)
{
    if (!mapping)
        return;
    
    free(mapping->internal_addr);
    free(mapping->external_addr);
    free(mapping);
}

void libp2p_nat_free_mappings(libp2p_nat_mapping_t **mappings, size_t count)
{
    if (!mappings)
        return;
    
    for (size_t i = 0; i < count; i++)
    {
        libp2p_nat_mapping_free(mappings[i]);
    }
    free(mappings);
}

bool libp2p_nat_upnp_available(void)
{
    /* UPnP is always available as it only requires sockets */
    return true;
}

bool libp2p_nat_natpmp_available(void)
{
    /* NAT-PMP is always available as it only requires sockets */
    return true;
}
