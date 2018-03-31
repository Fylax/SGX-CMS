#include "ESigner_t.h"
#include <openssl/pem.h>
#include <openssl/cms.h>

X509* certificate;
EVP_PKEY* private_key;
EVP_MD* digest_algorithm;

int set_secret(const char* certificate_data, size_t certificate_data_size,
    const char* private_key_data, size_t private_key_size) {
    const auto cert = BIO_new_mem_buf(certificate_data, certificate_data_size);
    certificate = PEM_read_bio_X509(cert, nullptr, nullptr, nullptr);
    BIO_free(cert);

    const auto key = BIO_new_mem_buf(private_key_data, private_key_size);
    private_key = PEM_read_bio_PrivateKey(key, nullptr, nullptr, nullptr);
    BIO_free(key);

    digest_algorithm = const_cast<EVP_MD*>(EVP_sha256());
    if (!certificate || !private_key) return 0;
    return i2d_X509(certificate, nullptr) * 2;
}

size_t enc_sign(const char* message, size_t message_length, size_t salt_length,
    char* signed_data, size_t estimated_envelope_data) {
    const int flags = CMS_BINARY | CMS_PARTIAL | CMS_KEY_PARAM
        | CMS_DETACHED | CMS_NOSMIMECAP;
    const auto mem = BIO_new(BIO_s_mem());
    BIO_write(mem, message, message_length);

    CMS_ContentInfo* data = CMS_sign(nullptr, nullptr, nullptr, mem, flags);
    CMS_SignerInfo* sinfo = CMS_add1_signer(data, certificate, private_key,
        digest_algorithm, flags);
    EVP_PKEY_CTX* pkey_ctx = CMS_SignerInfo_get0_pkey_ctx(sinfo);
    EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING);
    EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, salt_length);
    CMS_final(data, mem, nullptr, flags);

    const auto ret = BIO_new(BIO_s_mem());
    i2d_CMS_bio(ret, data);
    BIO_flush(ret);

    CMS_ContentInfo_free(data);
    BIO_free(mem);

    const size_t signed_data_length = BIO_get_mem_data(ret, nullptr);
    BIO_read(ret, signed_data, signed_data_length);
    signed_data[signed_data_length] = '\0';
    return signed_data_length;
}

void enc_clear() {
    X509_free(certificate);
    EVP_PKEY_free(private_key);
}
