#pragma once
#ifndef POLITO_CSS_ESIGNER_HPP_
#define POLITO_CSS_ESIGNER_HPP_

#include <sgx_urts.h>
#include <string>
#include "Signer.hpp"

class ESigner: public Signer {
 private:
#ifdef _WIN32
  const char* kEnclaveFile = "ESigner.signed.dll";
#else
  const char* kEnclaveFile = "ESigner.signed.so";
#endif
  const char* kTokenFile = "token";
  int estimated_envelope_size_;
  sgx_enclave_id_t enclave_id_;

 public:
  ESigner(const char* certificate_path, const char* private_key_path);
  std::string Sign(const char * message_path,
    const std::size_t salt_length) const override;
  ~ESigner();
};

#endif  // POLITO_CSS_ESIGNER_HPP_
