/* Inisialisasi proses tanda tangan */
static int haetae_sign_init(void *provctx, void *sigctx,
                           const OSSL_PARAM params[])
{
    HAETAE_SIG_CTX *sctx = OPENSSL_zalloc(sizeof(*sctx));
    if (sctx == NULL)
        return 0;
    
    sctx->provctx = provctx;
    *(HAETAE_SIG_CTX **)sigctx = sctx;
    return 1;
}

/* Buat tanda tangan */
static int haetae_sign(void *sigctx, unsigned char *sig, size_t *siglen,
                      size_t sigsize, const unsigned char *tbs, size_t tbslen)
{
    HAETAE_SIG_CTX *sctx = sigctx;
    size_t needed = HAETAE_SIG_LEN;
    
    if (sig == NULL) {
        *siglen = needed;  // Kembalikan ukuran tanda tangan yang dibutuhkan
        return 1;
    }
    
    if (sigsize < needed)
        return 0;
    
    // Panggil implementasi referensi HAETAE
    if (haetae_sign(sig, siglen, tbs, tbslen, sctx->key->priv_key,
                   sctx->key->priv_key_len) != 0)
        return 0;
    
    return 1;
}

/* Verifikasi tanda tangan */
static int haetae_verify(void *sigctx, const unsigned char *sig, size_t siglen,
                        const unsigned char *tbs, size_t tbslen)
{
    HAETAE_SIG_CTX *vctx = sigctx;
    
    // Panggil implementasi referensi HAETAE
    return haetae_verify(sig, siglen, tbs, tbslen, vctx->key->pub_key,
                        vctx->key->pub_key_len);
}