#include "ESigner.hpp"
#include <fstream>

int main(int argc, char** argv) {
  if(argc < 5)
  {
    printf("Usage: %s certificate key input_file output_file\n", argv[0]);
	exit(EXIT_FAILURE);
  }
  
  
  // salt length as argv?
  ESigner esigner(argv[1], argv[2]);
  std::string&& sign = esigner.Sign(argv[3], 8);

  std::ofstream out(argv[4], std::ios::out | std::ios::binary);
  out << sign;
  out.close();
  exit(EXIT_SUCCESS);
}
