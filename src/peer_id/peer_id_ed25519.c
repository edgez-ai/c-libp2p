#include <stdlib.h>
#include <string.h>

#include "../../../external/libeddsa/lib/eddsa.h"
#include "peer_id/peer_id.h"
#include "peer_id/peer_id_ed25519.h"
#include "peer_id/peer_id_proto.h"

#ifdef _WIN32
#include <windows.h>
#define secure_zero(ptr, len) SecureZeroMemory((PVOID)(ptr), (SIZE_T)(len))
#else

/**
 * @brief Securely zero out a memory region.
 *
 * @param ptr Pointer to the memory region to zero out.
 * @param len Length of the memory region in bytes.
 */
static void secure_zero(void *ptr, size_t len)
{
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--)
    {
        *p++ = 0;
    }
}
#endif

/**
 * @brief Create a peer ID from an Ed25519 private key.
 *
 * @param key_data Pointer to the private key data.
 * @param key_data_len Length of the private key data.
 * @param pubkey_buf Pointer to store the generated public key buffer.
 * @param pubkey_len Pointer to store the length of the generated public key buffer.
 * @return peer_id_error_t Error code indicating success or type of failure.
 */
peer_id_error_t peer_id_create_from_private_key_ed25519(const uint8_t *key_data, size_t key_data_len, uint8_t **pubkey_buf, size_t *pubkey_len)
{
    if (!key_data || !pubkey_buf || !pubkey_len)
    {
        return PEER_ID_E_NULL_PTR;
    }

    if (key_data_len < 32)
    {
        return PEER_ID_E_INVALID_PROTOBUF;
    }

    uint8_t pub[32];
    ed25519_genpub(pub, key_data);
    peer_id_error_t ret = peer_id_build_public_key_protobuf(PEER_ID_ED25519_KEY_TYPE, pub, sizeof(pub), pubkey_buf, pubkey_len);
    secure_zero(pub, sizeof(pub));
    return ret;
}
