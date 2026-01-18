#ifndef LIBP2P_RELAY_V2_H
#define LIBP2P_RELAY_V2_H

#include <stdint.h>
#include <stddef.h>

#include "libp2p/host.h"
#include "peer_id/peer_id.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define LIBP2P_RELAY_V2_PROTO_HOP  "/libp2p/circuit/relay/0.2.0/hop"
#define LIBP2P_RELAY_V2_PROTO_STOP "/libp2p/circuit/relay/0.2.0/stop"

/* Relay v2 status codes (from circuit.proto). */
typedef enum
{
    LIBP2P_RELAY_V2_STATUS_UNUSED = 0,
    LIBP2P_RELAY_V2_STATUS_OK = 100,
    LIBP2P_RELAY_V2_STATUS_RESERVATION_REFUSED = 200,
    LIBP2P_RELAY_V2_STATUS_RESOURCE_LIMIT_EXCEEDED = 201,
    LIBP2P_RELAY_V2_STATUS_PERMISSION_DENIED = 202,
    LIBP2P_RELAY_V2_STATUS_CONNECTION_FAILED = 203,
    LIBP2P_RELAY_V2_STATUS_NO_RESERVATION = 204,
    LIBP2P_RELAY_V2_STATUS_MALFORMED_MESSAGE = 400,
    LIBP2P_RELAY_V2_STATUS_UNEXPECTED_MESSAGE = 401
} libp2p_relay_v2_status_t;

typedef struct
{
    libp2p_relay_v2_status_t status;
    uint64_t expire_unix;       /* Reservation expiration (unix seconds). */
    uint32_t limit_duration_s;  /* Relay limit duration (seconds). */
    uint64_t limit_data_bytes;  /* Relay limit data (bytes). */
} libp2p_relay_v2_reservation_t;

/* Register the relay v2 STOP handler for inbound relay connections. */
int libp2p_relay_v2_client_start(libp2p_host_t *host);

/* Unregister the relay v2 STOP handler. */
int libp2p_relay_v2_client_stop(libp2p_host_t *host);

/* Reserve a slot on a relay. Returns 0 on success. */
int libp2p_relay_v2_reserve(libp2p_host_t *host, const char *relay_multiaddr, int timeout_ms, libp2p_relay_v2_reservation_t *out);

/* Build a relay circuit multiaddr of the form:
 *   <relay_multiaddr>/p2p-circuit/p2p/<self_peer_id>
 * Caller must free *out_addr with free().
 */
int libp2p_relay_v2_build_circuit_addr(const char *relay_multiaddr, const peer_id_t *self, char **out_addr);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_RELAY_V2_H */
