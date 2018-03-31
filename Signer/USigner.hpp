#pragma once
#ifndef POLITO_CSS_USIGNER_HPP_
#define POLITO_CSS_USIGNER_HPP_

#include <openssl/cms.h>
#include <string>
#include "Signer.hpp"

class USigner: public Signer {
 private:
  X509* certificate;
  EVP_PKEY* private_key;
  EVP_MD* digest_algorithm;
 public:
  USigner(const char* certificate_path, const char* private_key_path);
  std::string Sign(const char * message_path,
    std::size_t salt_length) const override;
  ~USigner();
};

#endif  // POLITO_CSS_USIGNER_HPP_
