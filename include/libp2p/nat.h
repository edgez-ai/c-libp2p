#ifndef LIBP2P_NAT_H
#define LIBP2P_NAT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "libp2p/host.h"
#include "multiformats/multiaddr/multiaddr.h"

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * NAT traversal service for libp2p.
 *
 * Provides UPnP/NAT-PMP port mapping functionality to make nodes behind NAT
 * reachable from the internet. This is essential for:
 * - Improving DCUtR success rate
 * - Enabling direct connections without relay
 * - AutoNAT reachability verification
 */

/**
 * NAT mapping protocol type.
 */
typedef enum
{
    LIBP2P_NAT_PROTO_UPNP = 0,    /* UPnP IGD (Internet Gateway Device) */
    LIBP2P_NAT_PROTO_NATPMP = 1,  /* NAT-PMP (Port Mapping Protocol) */
    LIBP2P_NAT_PROTO_PCP = 2,     /* PCP (Port Control Protocol) */
    LIBP2P_NAT_PROTO_AUTO = 3     /* Auto-detect (try all) */
} libp2p_nat_proto_t;

/**
 * NAT mapping status.
 */
typedef enum
{
    LIBP2P_NAT_STATUS_INACTIVE = 0,     /* Not yet started */
    LIBP2P_NAT_STATUS_DISCOVERING = 1,  /* Discovering NAT gateway */
    LIBP2P_NAT_STATUS_ACTIVE = 2,       /* Mapping active */
    LIBP2P_NAT_STATUS_FAILED = 3,       /* Mapping failed */
    LIBP2P_NAT_STATUS_NOT_FOUND = 4     /* No NAT gateway found */
} libp2p_nat_status_t;

/**
 * NAT mapping result codes.
 */
typedef enum
{
    LIBP2P_NAT_OK = 0,
    LIBP2P_NAT_ERR_NULL_PTR = -1,
    LIBP2P_NAT_ERR_INTERNAL = -2,
    LIBP2P_NAT_ERR_NO_GATEWAY = -3,
    LIBP2P_NAT_ERR_MAPPING_FAILED = -4,
    LIBP2P_NAT_ERR_TIMEOUT = -5,
    LIBP2P_NAT_ERR_UNSUPPORTED = -6,
    LIBP2P_NAT_ERR_ALREADY_MAPPED = -7
} libp2p_nat_err_t;

/**
 * NAT port mapping information.
 */
typedef struct
{
    char *internal_addr;      /* Internal (LAN) address */
    uint16_t internal_port;   /* Internal port */
    char *external_addr;      /* External (WAN) address */
    uint16_t external_port;   /* External port */
    uint32_t lifetime_secs;   /* Mapping lifetime in seconds */
    libp2p_nat_proto_t proto; /* Protocol used for mapping */
    int is_tcp;               /* 1 for TCP, 0 for UDP */
} libp2p_nat_mapping_t;

/**
 * Callback invoked when NAT mapping changes.
 *
 * @param mapping The mapping information (NULL if mapping removed)
 * @param status The current status
 * @param user_data User-provided context
 */
typedef void (*libp2p_nat_mapping_cb)(
    const libp2p_nat_mapping_t *mapping,
    libp2p_nat_status_t status,
    void *user_data
);

/**
 * NAT traversal service handle.
 */
typedef struct libp2p_nat_service libp2p_nat_service_t;

/**
 * NAT service options.
 */
typedef struct
{
    size_t struct_size;
    
    libp2p_nat_proto_t protocol;     /* Preferred protocol (default: AUTO) */
    int discovery_timeout_ms;         /* Gateway discovery timeout (default: 5000) */
    int mapping_lifetime_secs;        /* Requested mapping lifetime (default: 3600) */
    int refresh_interval_secs;        /* Refresh interval (default: mapping_lifetime/2) */
    int retry_attempts;               /* Max retry attempts (default: 3) */
    int retry_delay_ms;               /* Delay between retries (default: 1000) */
    bool enable_auto_refresh;         /* Auto-refresh mappings (default: true) */
    const char *description;          /* Mapping description (default: "libp2p") */
} libp2p_nat_opts_t;

/**
 * Initialize default NAT options.
 *
 * @param opts Pointer to options struct to initialize
 */
void libp2p_nat_opts_default(libp2p_nat_opts_t *opts);

/**
 * Create a new NAT traversal service bound to the host.
 *
 * @param host The libp2p host
 * @param opts Options (NULL for defaults)
 * @param out Output pointer for the service handle
 * @return 0 on success, negative error code on failure
 */
int libp2p_nat_new(libp2p_host_t *host, const libp2p_nat_opts_t *opts, libp2p_nat_service_t **out);

/**
 * Free the NAT service and remove all port mappings.
 *
 * @param svc The NAT service handle
 */
void libp2p_nat_free(libp2p_nat_service_t *svc);

/**
 * Start the NAT service (discover gateway and create mappings).
 *
 * @param svc The NAT service handle
 * @return 0 on success, negative error code on failure
 */
int libp2p_nat_start(libp2p_nat_service_t *svc);

/**
 * Stop the NAT service and remove all mappings.
 *
 * @param svc The NAT service handle
 */
void libp2p_nat_stop(libp2p_nat_service_t *svc);

/**
 * Request a port mapping for a specific local address.
 *
 * @param svc The NAT service handle
 * @param internal_port The internal port to map
 * @param external_port The requested external port (0 for any)
 * @param is_tcp 1 for TCP, 0 for UDP
 * @param mapping Output for the created mapping (caller must free with libp2p_nat_mapping_free)
 * @return 0 on success, negative error code on failure
 */
int libp2p_nat_add_mapping(libp2p_nat_service_t *svc,
                           uint16_t internal_port,
                           uint16_t external_port,
                           int is_tcp,
                           libp2p_nat_mapping_t **mapping);

/**
 * Remove a port mapping.
 *
 * @param svc The NAT service handle
 * @param internal_port The internal port to unmap
 * @param is_tcp 1 for TCP, 0 for UDP
 * @return 0 on success, negative error code on failure
 */
int libp2p_nat_remove_mapping(libp2p_nat_service_t *svc,
                               uint16_t internal_port,
                               int is_tcp);

/**
 * Get the current external address from NAT gateway.
 *
 * @param svc The NAT service handle
 * @param out Output string (caller must free)
 * @return 0 on success, negative error code on failure
 */
int libp2p_nat_get_external_addr(libp2p_nat_service_t *svc, char **out);

/**
 * Get the external multiaddr for a local listen address.
 *
 * @param svc The NAT service handle
 * @param local_addr The local listen multiaddr
 * @param out Output multiaddr (caller must free)
 * @return 0 on success, negative error code on failure
 */
int libp2p_nat_get_external_multiaddr(libp2p_nat_service_t *svc,
                                       const multiaddr_t *local_addr,
                                       multiaddr_t **out);

/**
 * Register a callback for mapping status changes.
 *
 * @param svc The NAT service handle
 * @param cb The callback function
 * @param user_data User-provided context
 * @return 0 on success, negative error code on failure
 */
int libp2p_nat_on_mapping_change(libp2p_nat_service_t *svc,
                                  libp2p_nat_mapping_cb cb,
                                  void *user_data);

/**
 * Get the current NAT status.
 *
 * @param svc The NAT service handle
 * @return Current status
 */
libp2p_nat_status_t libp2p_nat_status(libp2p_nat_service_t *svc);

/**
 * Get all current port mappings.
 *
 * @param svc The NAT service handle
 * @param mappings Output array (caller must free each element and array)
 * @param count Output count
 * @return 0 on success, negative error code on failure
 */
int libp2p_nat_get_mappings(libp2p_nat_service_t *svc,
                             libp2p_nat_mapping_t ***mappings,
                             size_t *count);

/**
 * Free a NAT mapping structure.
 *
 * @param mapping The mapping to free
 */
void libp2p_nat_mapping_free(libp2p_nat_mapping_t *mapping);

/**
 * Free an array of NAT mappings returned by libp2p_nat_get_mappings.
 *
 * @param mappings The mappings array to free
 * @param count Number of elements in the array
 */
void libp2p_nat_free_mappings(libp2p_nat_mapping_t **mappings, size_t count);

/**
 * Check if UPnP is available on this system.
 *
 * @return true if available, false otherwise
 */
bool libp2p_nat_upnp_available(void);

/**
 * Check if NAT-PMP is available on this system.
 *
 * @return true if available, false otherwise
 */
bool libp2p_nat_natpmp_available(void);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_NAT_H */
