/* Membuat kunci baru */
static void *haetae_newkey(void *provctx, const OSSL_PARAM params[])
{
    HAETAE_KEY *key = OPENSSL_zalloc(sizeof(*key));
    if (key == NULL)
        return NULL;
    
    key->lock = CRYPTO_THREAD_lock_new();  // Kunci untuk thread safety
    if (key->lock == NULL) {
        OPENSSL_free(key);
        return NULL;
    }
    
    return key;
}

/* Membersihkan memori kunci */
static void haetae_freepkey(void *keydata)
{
    HAETAE_KEY *key = keydata;
    if (key == NULL)
        return;
    
    // Bersihkan kunci privat dengan aman
    OPENSSL_secure_clear_free(key->priv_key, key->priv_key_len);
    OPENSSL_free(key->pub_key);
    CRYPTO_THREAD_lock_free(key->lock);
    OPENSSL_free(key);
}

/* Generate kunci HAETAE */
static int haetae_gen(void *keygenctx, OSSL_CALLBACK *cb, void *cbarg)
{
    HAETAE_GEN_CTX *gctx = keygenctx;
    HAETAE_KEY *key = haetae_newkey(gctx->provctx, NULL);
    
    // Panggil implementasi referensi HAETAE
    if (haetae_keygen(&key->pub_key, &key->pub_key_len,
                     &key->priv_key, &key->priv_key_len) != 0) {
        haetae_freepkey(key);
        return 0;
    }
    
    return 1;
}