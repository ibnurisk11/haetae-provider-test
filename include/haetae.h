#ifndef HAETAE_H
#define HAETAE_H

#include <openssl/opensslv.h>

/* Deklarasi versi provider */
#define HAETAE_VERSION "0.1.0"
#define HAETAE_DEFAULT_VERSION 260  // Versi default

/* Fungsi-fungsi wrapper untuk referensi HAETAE */
int haetae_keygen(unsigned char **pub_key, size_t *pub_key_len,
                 unsigned char **priv_key, size_t *priv_key_len,
                 int version);

int haetae_sign(unsigned char *sig, size_t *siglen,
               const unsigned char *msg, size_t msglen,
               const unsigned char *priv_key, size_t priv_keylen,
               int version);

int haetae_verify(const unsigned char *sig, size_t siglen,
                 const unsigned char *msg, size_t msglen,
                 const unsigned char *pub_key, size_t pub_keylen,
                 int version);

/* Fungsi encoder/decoder */
int haetae_encode_privkey(const HAETAE_KEY *key, unsigned char **out);
int haetae_decode_privkey(HAETAE_KEY *key, const unsigned char *in, size_t inlen);
int haetae_encode_pubkey(const HAETAE_KEY *key, unsigned char **out);
int haetae_decode_pubkey(HAETAE_KEY *key, const unsigned char *in, size_t inlen);

#endif