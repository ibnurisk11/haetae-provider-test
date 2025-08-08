#include <stdio.h>
#include <string.h>
#include "haetae.h"

/* Vektor uji untuk HAETAE-180 */
static const unsigned char haetae180_pubkey[] = { /* isi kunci publik */ };
static const unsigned char haetae180_privkey[] = { /* isi kunci privat */ };
static const unsigned char haetae180_msg[] = "Pesan uji HAETAE-180";
static const unsigned char haetae180_sig[] = { /* isi tanda tangan */ };

/* Vektor uji untuk HAETAE-260 */
static const unsigned char haetae260_pubkey[] = { /* isi kunci publik */ };
static const unsigned char haetae260_privkey[] = { /* isi kunci privat */ };
static const unsigned char haetae260_msg[] = "Pesan uji HAETAE-260";
static const unsigned char haetae260_sig[] = { /* isi tanda tangan */ };

/* Fungsi test untuk satu vektor uji */
static int test_vector(const unsigned char *pubkey, size_t pubkey_len,
                      const unsigned char *privkey, size_t privkey_len,
                      const unsigned char *msg, size_t msglen,
                      const unsigned char *sig, size_t siglen,
                      int version) {
    printf("Testing HAETAE-%d... ", version);
    
    // Test tanda tangan
    unsigned char test_sig[1024];
    size_t test_siglen;
    
    if (!haetae_sign(test_sig, &test_siglen, msg, msglen, privkey, privkey_len, version)) {
        printf("Gagal membuat tanda tangan\n");
        return 0;
    }
    
    // Test verifikasi
    if (!haetae_verify(sig, siglen, msg, msglen, pubkey, pubkey_len, version)) {
        printf("Gagal verifikasi tanda tangan asli\n");
        return 0;
    }
    
    // Test verifikasi salah
    unsigned char tampered_msg[] = "Pesan salah";
    if (haetae_verify(sig, siglen, tampered_msg, strlen((char *)tampered_msg), 
                     pubkey, pubkey_len, version)) {
        printf("Verifikasi sukses untuk pesan salah\n");
        return 0;
    }
    
    printf("Sukses\n");
    return 1;
}

/* Fungsi utama testing */
int main() {
    int success = 1;
    
    // Test HAETAE-180
    success &= test_vector(haetae180_pubkey, sizeof(haetae180_pubkey),
               haetae180_privkey, sizeof(haetae180_privkey),
               haetae180_msg, strlen((char *)haetae180_msg),
               haetae180_sig, sizeof(haetae180_sig),
               180);
    
    // Test HAETAE-260
    success &= test_vector(haetae260_pubkey, sizeof(haetae260_pubkey),
               haetae260_privkey, sizeof(haetae260_privkey),
               haetae260_msg, strlen((char *)haetae260_msg),
               haetae260_sig, sizeof(haetae260_sig),
               260);
    
    return success ? 0 : 1;
}