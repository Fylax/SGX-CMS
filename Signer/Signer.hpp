#pragma once
#ifndef POLITO_CSS_SIGNER_HPP_
#define POLITO_CSS_SIGNER_HPP_

#include <string>

class Signer {
 protected:
  static std::string ReadFile(const char* path);
  virtual std::string Sign(const char* message_path,
    const std::size_t salt_length) const = 0;
 public:
  virtual ~Signer() = default;
};

#endif  // POLITO_CSS_SIGNER_HPP_
