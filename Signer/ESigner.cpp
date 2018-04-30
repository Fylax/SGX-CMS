#include <openssl/bio.h>
#include <stdexcept>
#include <string>
#include "ESigner.hpp"
#include "ESigner_u.h"

ESigner::ESigner(const char* certificate_path, const char* private_key_path) {
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  sgx_launch_token_t launch_token = { 0 };
  int updated = 0;

  // Step 1: try to retrieve the launch token saved by last transaction
  //         if there is no token, then create a new one.
  auto fp = fopen(this->kTokenFile, "rb");
  if (fp == nullptr) {
      if ((fp = fopen(this->kTokenFile, "wb")) == nullptr) {
          throw std::runtime_error("Failed to create the launch token file.");
      }
  } else {
    // read the token from saved file
    const size_t read_num = fread(launch_token, 1,
      sizeof(sgx_launch_token_t), fp);
    if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
      // if token is invalid, clear the buffer
      memset(&launch_token, 0, sizeof(sgx_launch_token_t));
    }
  }

  // Step 2: call sgx_create_enclave to initialize an enclave instance
  ret = sgx_create_enclave(this->kEnclaveFile, SGX_DEBUG_FLAG, &launch_token,
    &updated, &this->enclave_id_, nullptr);
  if (ret != SGX_SUCCESS) {
    throw std::runtime_error("Failed to create enclave.");
  }

  // Step 3: save the launch token if it is updated
  if (updated) {
    fp = freopen(this->kTokenFile, "wb", fp);
    if (fp == nullptr) {
      throw std::runtime_error("Failed to save launch token.");
    }
    const std::size_t write_num = fwrite(launch_token, 1,
      sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t)) {
      throw std::runtime_error("Failed to save launch token.");
    }
  }
  fclose(fp);

  int success;
  const auto&& certificate = Signer::ReadFile(certificate_path);
  const auto&& private_key = Signer::ReadFile(private_key_path);
  set_secret(this->enclave_id_, &success,
    certificate.c_str(), certificate.length(),
    private_key.c_str(), private_key.length());
  if (!success) {
    throw std::runtime_error("Failed to initialise enclave");
  }
  this->estimated_envelope_size_ = success;
}

std::string ESigner::Sign(const char * message_path,
  const std::size_t salt_length) const {
  BIO* envelope = nullptr;
  const auto&& message = Signer::ReadFile(message_path);

  size_t signed_data_length;
  char* signed_data = new char[this->estimated_envelope_size_];
  enc_sign(this->enclave_id_, &signed_data_length, message.c_str(),
    message.length(), salt_length, signed_data, this->estimated_envelope_size_);

  std::string finalized_signed_data(signed_data, signed_data_length);
  
  delete[] signed_data;
  return finalized_signed_data;
}


ESigner::~ESigner() {
  enc_clear(this->enclave_id_);
  sgx_destroy_enclave(this->enclave_id_);
}
