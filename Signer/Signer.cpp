#include <fstream>
#include <stdexcept>
#include <string>
#include "Signer.hpp"

std::string Signer::ReadFile(const char * path) {
  std::ifstream file(path, std::ios::in | std::ios::binary);
  if (!file) {
    throw std::runtime_error("Cannot open file.");
  }

  std::string str;

  file.seekg(0, std::ios::end);
  const std::size_t file_length = file.tellg();
  str.reserve(file_length);
  file.seekg(0, std::ios::beg);

  str.assign((std::istreambuf_iterator<char>(file)),
    std::istreambuf_iterator<char>());

  file.close();
  return str;
}
