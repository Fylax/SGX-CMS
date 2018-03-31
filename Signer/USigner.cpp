#include <openssl/pem.h>
#include <string>
#include "USigner.hpp"

USigner::USigner(const char * certificate_path, const char * private_key_path) {
    const auto certificate_data = Signer::ReadFile(certificate_path);
    const auto cert = BIO_new_mem_buf(certificate_data.c_str(),
        certificate_data.length());
    this->certificate = PEM_read_bio_X509(cert, nullptr, nullptr, nullptr);
    BIO_free(cert);

    const auto&& private_key_data = Signer::ReadFile(private_key_path);
    const auto&& key = BIO_new_mem_buf(private_key_data.c_str(),
        private_key_data.length());
    this->private_key = PEM_read_bio_PrivateKey(key, nullptr, nullptr, nullptr);
    BIO_free(key);

    this->digest_algorithm = const_cast<EVP_MD*>(EVP_sha256());
}

std::string USigner::Sign(const char * message_path,
    std::size_t salt_length) const {
    const auto&& message = Signer::ReadFile(message_path);

    const int flags = CMS_BINARY | CMS_PARTIAL | CMS_KEY_PARAM
        | CMS_DETACHED | CMS_NOSMIMECAP;
    const auto mem = BIO_new(BIO_s_mem());
    BIO_write(mem, message.c_str(), message.length());

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
    char* signed_data = new char[signed_data_length + 1];
    BIO_read(ret, signed_data, signed_data_length);
    signed_data[signed_data_length] = '\0';

    std::string finalized_signed_data(signed_data, signed_data_length);
    delete[] signed_data;
    return finalized_signed_data;
}

USigner::~USigner() {
    X509_free(this->certificate);
    EVP_PKEY_free(this->private_key);
}
