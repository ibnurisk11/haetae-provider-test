/* Daftar algoritma yang disupport */
static const OSSL_ALGORITHM haetae_signature[] = {
    { "haetae", "provider=haetae", haetae_signature_functions },
    { "haetae-180", "provider=haetae", haetae_signature_functions },
    { "haetae-260", "provider=haetae", haetae_signature_functions },
    { NULL, NULL, NULL }
};

/* Fungsi query untuk operasi yang didukung */
static const OSSL_ALGORITHM *haetae_query(void *provctx, int operation_id,
                                         int *no_cache)
{
    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_SIGNATURE:  // Operasi tanda tangan
        return haetae_signature;
    case OSSL_OP_KEYMGMT:    // Operasi manajemen kunci
        return haetae_keymgmt;
    }
    return NULL;
}

/* Fungsi inisialisasi provider */
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                      const OSSL_DISPATCH *in,
                      const OSSL_DISPATCH **out,
                      void **provctx)
{
    *out = haetae_dispatch_table;
    *provctx = (void *)handle;
    return 1;
}