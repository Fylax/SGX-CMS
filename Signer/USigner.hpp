#pragma once
#ifndef POLITO_CSS_USIGNER_HPP_
#define POLITO_CSS_USIGNER_HPP_

#include <openssl/cms.h>
#include <string>
#include "Signer.hpp"

class USigner: public Signer {
 private:
  X509* certificate_;
  EVP_PKEY* private_key_;
  EVP_MD* digest_algorithm_;
 public:
  USigner(const char* certificate_path, const char* private_key_path);
  std::string Sign(const char * message_path,
    const std::size_t salt_length) const override;
  ~USigner();
};

#endif  // POLITO_CSS_USIGNER_HPP_
