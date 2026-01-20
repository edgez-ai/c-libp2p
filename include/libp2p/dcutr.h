#ifndef LIBP2P_DCUTR_H
#define LIBP2P_DCUTR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "libp2p/host.h"
#include "libp2p/stream.h"
#include "peer_id/peer_id.h"
#include "multiformats/multiaddr/multiaddr.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define LIBP2P_DCUTR_PROTO_ID "/libp2p/dcutr"

/**
 * DCUtR message types.
 */
typedef enum
{
    LIBP2P_DCUTR_MSG_CONNECT = 0,
    LIBP2P_DCUTR_MSG_SYNC = 1
} libp2p_dcutr_msg_type_t;

/**
 * DCUtR connection upgrade result.
 */
typedef enum
{
    LIBP2P_DCUTR_RESULT_SUCCESS = 0,
    LIBP2P_DCUTR_RESULT_NO_OBSERVED_ADDRS = 1,
    LIBP2P_DCUTR_RESULT_HOLE_PUNCH_FAILED = 2,
    LIBP2P_DCUTR_RESULT_TIMEOUT = 3,
    LIBP2P_DCUTR_RESULT_PROTOCOL_ERROR = 4,
    LIBP2P_DCUTR_RESULT_INTERNAL_ERROR = 5
} libp2p_dcutr_result_t;

/**
 * Callback invoked when a direct connection is established via DCUtR.
 * 
 * @param peer The remote peer ID
 * @param direct_addr The direct address that was successfully connected
 * @param user_data User-provided context
 */
typedef void (*libp2p_dcutr_upgrade_cb)(
    const peer_id_t *peer,
    const char *direct_addr,
    libp2p_dcutr_result_t result,
    void *user_data
);

/**
 * DCUtR service handle.
 */
typedef struct libp2p_dcutr_service libp2p_dcutr_service_t;

/**
 * DCUtR service options.
 */
typedef struct
{
    size_t struct_size;
    
    int hole_punch_timeout_ms;    /* Timeout for hole punch attempts (default: 5000) */
    int max_retry_attempts;       /* Max retry attempts per address (default: 3) */
    int retry_delay_ms;           /* Delay between retries (default: 500) */
    bool enable_tcp_simultaneous_open;  /* Enable TCP simultaneous open (default: true) */
} libp2p_dcutr_opts_t;

/**
 * Initialize default DCUtR options.
 */
void libp2p_dcutr_opts_default(libp2p_dcutr_opts_t *opts);

/**
 * Create a new DCUtR service bound to the host.
 * This registers the /libp2p/dcutr protocol handler.
 *
 * @param host The libp2p host
 * @param opts Options (NULL for defaults)
 * @param out Output pointer for the service handle
 * @return 0 on success, negative error code on failure
 */
int libp2p_dcutr_new(libp2p_host_t *host, const libp2p_dcutr_opts_t *opts, libp2p_dcutr_service_t **out);

/**
 * Free the DCUtR service and all associated resources.
 *
 * @param svc The DCUtR service handle
 */
void libp2p_dcutr_free(libp2p_dcutr_service_t *svc);

/**
 * Register a callback for successful direct connection upgrades.
 *
 * @param svc The DCUtR service handle
 * @param cb Callback function
 * @param user_data User data passed to callback
 * @return 0 on success, negative error code on failure
 */
int libp2p_dcutr_on_upgrade(
    libp2p_dcutr_service_t *svc,
    libp2p_dcutr_upgrade_cb cb,
    void *user_data
);

/**
 * Attempt to upgrade a relayed connection to a direct connection.
 * This initiates the DCUtR protocol exchange with the remote peer.
 *
 * The function will:
 * 1. Open a DCUtR stream over the relayed connection
 * 2. Exchange observed addresses with the remote peer
 * 3. Perform coordinated hole punching
 * 4. Return success if direct connection is established
 *
 * @param svc The DCUtR service handle
 * @param peer The remote peer to upgrade connection with
 * @param timeout_ms Timeout for the upgrade attempt
 * @return 0 on success (direct connection established), negative on failure
 */
int libp2p_dcutr_upgrade(
    libp2p_dcutr_service_t *svc,
    const peer_id_t *peer,
    int timeout_ms
);

/**
 * Add an observed address for the local node.
 * Call this when you learn your external address (e.g., from identify or AutoNAT).
 *
 * @param svc The DCUtR service handle
 * @param addr The observed address string
 * @return 0 on success, negative error code on failure
 */
int libp2p_dcutr_add_observed_addr(libp2p_dcutr_service_t *svc, const char *addr);

/**
 * Get the list of observed addresses for the local node.
 *
 * @param svc The DCUtR service handle
 * @param out_addrs Output array of address strings (caller must free each and the array)
 * @param out_count Output count of addresses
 * @return 0 on success, negative error code on failure
 */
int libp2p_dcutr_get_observed_addrs(
    libp2p_dcutr_service_t *svc,
    char ***out_addrs,
    size_t *out_count
);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_DCUTR_H */
