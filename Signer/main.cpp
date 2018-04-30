#include "USigner.hpp"
#include <fstream>
#include <filesystem>


namespace fs = std::experimental::filesystem;
int main(int argc, char** argv) {
  if(argc < 4)
  {
    printf("Usage: %s certificate key sign_files_dir", argv[0]);
  }
  
  USigner esigner(argv[1], argv[2]);
  for (auto& p : fs::directory_iterator(argv[3]))
  {
    std::string&& sign = esigner.Sign(p.path().generic_string().c_str(), 8);
  }

  //std::ofstream out(signed_path, std::ios::out | std::ios::binary);
  //out << sign;
  //out.close();
  return 0;
}
