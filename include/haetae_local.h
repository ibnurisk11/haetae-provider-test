#ifndef HAETAE_LOCAL_H
#define HAETAE_LOCAL_H

#include <openssl/ossl_typ.h>
#include <openssl/core.h>
#include <openssl/evp.h>
#include <openssl/params.h>    // Untuk OSSL_PARAM
#include <openssl/err.h>
#include "haetae.h"

* Tambahkan definisi jika masih ada error */
#ifndef NULL
#define NULL ((void *)0)
#endif

/* Konstanta untuk berbagai versi HAETAE */
#define HAETAE180_SIG_LEN    1234  // Sesuaikan dengan spesifikasi
#define HAETAE260_SIG_LEN    5678  // Sesuaikan dengan spesifikasi
#define HAETAE180_PUBKEY_LEN 9012  // Sesuaikan
#define HAETAE260_PUBKEY_LEN 3456  // Sesuaikan

/* Struktur kunci HAETAE */
typedef struct {
    CRYPTO_RWLOCK *lock;          // Kunci untuk thread safety
    unsigned char *pub_key;       // Kunci publik
    size_t pub_key_len;           // Panjang kunci publik
    unsigned char *priv_key;      // Kunci privat
    size_t priv_key_len;          // Panjang kunci privat
    int version;                  // Versi HAETAE (180/260)
} HAETAE_KEY;

/* Struktur konteks tanda tangan */
typedef struct {
    void *provctx;               // Konteks provider
    HAETAE_KEY *key;             // Kunci yang digunakan
    unsigned int flag_allow_md:1; // Flag untuk allowed digest
} HAETAE_SIG_CTX;

/* Struktur konteks generate kunci */
typedef struct {
    void *provctx;               // Konteks provider
    int version;                 // Versi HAETAE yang dipilih
} HAETAE_GEN_CTX;

#endif