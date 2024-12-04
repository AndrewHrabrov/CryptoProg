#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>
#include <string>
#include <iostream>
#include <fstream>
#include <sstream>

int main() {
    std::string file_path = "test.txt";
    std::ifstream infile (file_path, std::ios::binary);
    std::stringstream ss;
    while (infile >> ss.rdbuf());
    std::string text = ss.str();
    
    namespace CPP = CryptoPP;
    CPP::SHA256 sha; 
    std::string hash; 
    CPP::StringSource(text, true,
                      new CPP::HashFilter(sha,
                                          new CPP::HexEncoder(
                                            new CPP::StringSink(hash))));
    
    std::cout << text << std::endl;
    std::cout << hash << std::endl;
    infile.close();
    return 0;
}
