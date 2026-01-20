#ifndef LIBP2P_AUTONAT_H
#define LIBP2P_AUTONAT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "libp2p/host.h"
#include "peer_id/peer_id.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define LIBP2P_AUTONAT_PROTO_ID "/libp2p/autonat/1.0.0"

/**
 * AutoNAT reachability status.
 */
typedef enum
{
    LIBP2P_AUTONAT_REACHABILITY_UNKNOWN = 0,
    LIBP2P_AUTONAT_REACHABILITY_PUBLIC = 1,
    LIBP2P_AUTONAT_REACHABILITY_PRIVATE = 2
} libp2p_autonat_reachability_t;

/**
 * AutoNAT response status codes (from autonat.proto).
 */
typedef enum
{
    LIBP2P_AUTONAT_STATUS_OK = 0,
    LIBP2P_AUTONAT_STATUS_E_DIAL_ERROR = 100,
    LIBP2P_AUTONAT_STATUS_E_DIAL_REFUSED = 101,
    LIBP2P_AUTONAT_STATUS_E_BAD_REQUEST = 200,
    LIBP2P_AUTONAT_STATUS_E_INTERNAL_ERROR = 300
} libp2p_autonat_status_t;

/**
 * AutoNAT dial result returned by a peer.
 */
typedef struct
{
    libp2p_autonat_status_t status;
    char *status_text;        /* Optional status text (caller must free) */
    char *addr;               /* Address that was successfully dialed, if any (caller must free) */
} libp2p_autonat_dial_result_t;

/**
 * AutoNAT service handle.
 */
typedef struct libp2p_autonat_service libp2p_autonat_service_t;

/**
 * AutoNAT service options.
 */
typedef struct
{
    size_t struct_size;
    
    /* Server-side options */
    bool enable_service;              /* Enable responding to AutoNAT requests (default: true) */
    int dial_timeout_ms;              /* Timeout for dial-back attempts (default: 15000) */
    int throttle_global_max;          /* Max concurrent dial-backs globally (default: 30) */
    int throttle_peer_max;            /* Max dial-backs per peer per interval (default: 3) */
    int throttle_interval_ms;         /* Throttle reset interval (default: 60000) */
    
    /* Client-side options */
    int refresh_interval_ms;          /* How often to probe reachability (default: 60000) */
    int boot_delay_ms;                /* Delay before first probe (default: 15000) */
    int min_peers_required;           /* Min peers needed for determination (default: 3) */
    int min_confirmations;            /* Min confirmations for reachability (default: 3) */
} libp2p_autonat_opts_t;

/**
 * Callback for reachability changes.
 */
typedef void (*libp2p_autonat_reachability_cb)(
    libp2p_autonat_reachability_t old_status,
    libp2p_autonat_reachability_t new_status,
    const char *public_addr,
    void *user_data
);

/**
 * Initialize default AutoNAT options.
 */
void libp2p_autonat_opts_default(libp2p_autonat_opts_t *opts);

/**
 * Create a new AutoNAT service bound to the host.
 * This registers protocol handlers for incoming AutoNAT requests.
 *
 * @param host The libp2p host
 * @param opts Options (NULL for defaults)
 * @param out Output pointer for the service handle
 * @return 0 on success, negative error code on failure
 */
int libp2p_autonat_new(libp2p_host_t *host, const libp2p_autonat_opts_t *opts, libp2p_autonat_service_t **out);

/**
 * Start the AutoNAT service (begins periodic reachability probing).
 *
 * @param svc The AutoNAT service handle
 * @return 0 on success, negative error code on failure
 */
int libp2p_autonat_start(libp2p_autonat_service_t *svc);

/**
 * Stop the AutoNAT service.
 *
 * @param svc The AutoNAT service handle
 * @return 0 on success, negative error code on failure
 */
int libp2p_autonat_stop(libp2p_autonat_service_t *svc);

/**
 * Free the AutoNAT service and all associated resources.
 *
 * @param svc The AutoNAT service handle
 */
void libp2p_autonat_free(libp2p_autonat_service_t *svc);

/**
 * Get the current reachability status.
 *
 * @param svc The AutoNAT service handle
 * @return Current reachability status
 */
libp2p_autonat_reachability_t libp2p_autonat_get_reachability(libp2p_autonat_service_t *svc);

/**
 * Get the confirmed public address (if reachability is PUBLIC).
 *
 * @param svc The AutoNAT service handle
 * @param out_addr Output buffer for the address string
 * @param out_len Size of output buffer
 * @return 0 on success, negative error code if not public or error
 */
int libp2p_autonat_get_public_addr(libp2p_autonat_service_t *svc, char *out_addr, size_t out_len);

/**
 * Register a callback for reachability status changes.
 *
 * @param svc The AutoNAT service handle
 * @param cb Callback function
 * @param user_data User data passed to callback
 * @return 0 on success, negative error code on failure
 */
int libp2p_autonat_on_reachability_changed(
    libp2p_autonat_service_t *svc,
    libp2p_autonat_reachability_cb cb,
    void *user_data
);

/**
 * Manually request a dial-back from a specific peer.
 * This is useful for testing or forcing a reachability check.
 *
 * @param svc The AutoNAT service handle
 * @param peer The peer to request dial-back from
 * @param addrs Array of addresses to request dial-back to
 * @param num_addrs Number of addresses
 * @param timeout_ms Timeout for the request
 * @param result Output for the dial result (caller must free status_text and addr)
 * @return 0 on success, negative error code on failure
 */
int libp2p_autonat_probe_peer(
    libp2p_autonat_service_t *svc,
    const peer_id_t *peer,
    const char *const *addrs,
    size_t num_addrs,
    int timeout_ms,
    libp2p_autonat_dial_result_t *result
);

/**
 * Force an immediate reachability probe cycle.
 *
 * @param svc The AutoNAT service handle
 * @return 0 on success, negative error code on failure
 */
int libp2p_autonat_force_probe(libp2p_autonat_service_t *svc);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_AUTONAT_H */
