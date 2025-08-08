#include <openssl/bio.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include "haetae_local.h"

/* Encode kunci privat ke format DER */
int haetae_encode_privkey(const HAETAE_KEY *key, unsigned char **out) {
    size_t needed = key->priv_key_len + key->pub_key_len + 16; // Header dll
    unsigned char *buf = OPENSSL_malloc(needed);
    
    if (buf == NULL)
        return 0;
    
    // Format biner sederhana (bisa diganti dengan ASN.1 untuk bonus)
    unsigned char *p = buf;
    *p++ = (key->version >> 8) & 0xFF;  // Versi MSB
    *p++ = key->version & 0xFF;         // Versi LSB
    
    // Copy kunci privat
    memcpy(p, key->priv_key, key->priv_key_len);
    p += key->priv_key_len;
    
    // Copy kunci publik
    memcpy(p, key->pub_key, key->pub_key_len);
    
    *out = buf;
    return 1;
}

/* Decode kunci privat dari format DER */
int haetae_decode_privkey(HAETAE_KEY *key, const unsigned char *in, size_t inlen) {
    if (inlen < 2)
        return 0;
    
    const unsigned char *p = in;
    key->version = (*p++ << 8);
    key->version |= *p++;
    
    // Sesuaikan dengan format encoding
    size_t priv_len = (key->version == 180) ? HAETAE180_PRIVKEY_LEN : HAETAE260_PRIVKEY_LEN;
    size_t pub_len = (key->version == 180) ? HAETAE180_PUBKEY_LEN : HAETAE260_PUBKEY_LEN;
    
    if (inlen != 2 + priv_len + pub_len)
        return 0;
    
    key->priv_key = OPENSSL_memdup(p, priv_len);
    key->priv_key_len = priv_len;
    p += priv_len;
    
    key->pub_key = OPENSSL_memdup(p, pub_len);
    key->pub_key_len = pub_len;
    
    return 1;
}

/* Encode kunci publik */
int haetae_encode_pubkey(const HAETAE_KEY *key, unsigned char **out) {
    size_t needed = key->pub_key_len + 2;
    unsigned char *buf = OPENSSL_malloc(needed);
    
    if (buf == NULL)
        return 0;
    
    unsigned char *p = buf;
    *p++ = (key->version >> 8) & 0xFF;
    *p++ = key->version & 0xFF;
    
    memcpy(p, key->pub_key, key->pub_key_len);
    
    *out = buf;
    return 1;
}

/* Decode kunci publik */
int haetae_decode_pubkey(HAETAE_KEY *key, const unsigned char *in, size_t inlen) {
    if (inlen < 2)
        return 0;
    
    const unsigned char *p = in;
    key->version = (*p++ << 8);
    key->version |= *p++;
    
    size_t pub_len = (key->version == 180) ? HAETAE180_PUBKEY_LEN : HAETAE260_PUBKEY_LEN;
    
    if (inlen != 2 + pub_len)
        return 0;
    
    key->pub_key = OPENSSL_memdup(p, pub_len);
    key->pub_key_len = pub_len;
    
    return 1;
}