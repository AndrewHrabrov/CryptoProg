#include <iostream>
#include <fstream>
#include <string>
#include <cryptopp/cryptlib.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pwdbased.h>
#include <boost/program_options.hpp>

using namespace CryptoPP;

CryptoPP::SecByteBlock genPass(const std::string& pass)
{
    CryptoPP::SecByteBlock key(CryptoPP::AES::MAX_KEYLENGTH);
    CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf2;
    pbkdf2.DeriveKey(key, key.size(), 0, (byte*)pass.data(), pass.size(), (byte*)pass.data(), pass.size(), 1000);
    return key;
}

using namespace std;

void encrypt(const string& src, const string& rst, const string& pass)
{
    SecByteBlock key = genPass(pass);
    SecByteBlock iv(AES::BLOCKSIZE);

    AutoSeededRandomPool prng;
    prng.GenerateBlock(iv, iv.size());

    try {
        ofstream encrypted(rst, ios::binary);
        encrypted.write(reinterpret_cast<const char*>(iv.data()), iv.size());
        
        CBC_Mode<AES>::Encryption encryptor;
        encryptor.SetKeyWithIV(key, key.size(), iv);

        FileSource(src.c_str(), true, new StreamTransformationFilter(encryptor, new FileSink(encrypted)));
        
    } catch(const CryptoPP::Exception& e) {
        std::cerr << "Encryption error: " << e.what() << std::endl;
        exit(1);
    }
}

void decrypt(const string& src, const string& rst, const string& pass)
{
    SecByteBlock key = genPass(pass);
    SecByteBlock iv(AES::BLOCKSIZE);

    try {
        ifstream encrypted(src, ios::binary);
        encrypted.read(reinterpret_cast<char*>(iv.data()), iv.size());

        CBC_Mode<AES>::Decryption decryptor;
        decryptor.SetKeyWithIV(key, key.size(), iv);

        FileSource(encrypted, true, new StreamTransformationFilter(decryptor, new FileSink(rst.c_str())));
        
    } catch(const CryptoPP::Exception& e) {
        std::cerr << "Decryption error: " << e.what() << std::endl;
        exit(1);
    }
}

namespace po = boost::program_options;

int main(int argc, char* argv[]) {
    po::options_description desc("Блочный шифратор");
    desc.add_options()
        ("help,h" , "Выдать справку\n")
        ("mode,m" , po::value<unsigned int>()->default_value(1), "Шифрование-1\nрасшифрование-2\n")
        ("source,s" , po::value<std::string>()->required(), "Файл с исходными данными\n")
        ("result_cip,c", po::value<std::string>()->default_value("cip.txt"), "Файл для записи результата шифрования\n")
        ("result_dec,d", po::value<std::string>()->default_value("dec.txt"), "Файл для записи результата \nрасшифрования\n")
        ("pass,p", po::value<std::string>()->required(), "Пароль для \nформирования ключа шифрования");

    po::variables_map vm;
    try {
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);
    }
    catch(po::error& e) {
        std::cout<< e.what()<<std::endl;
        std::cout<<desc<<std::endl;
        return 1;
    }
    if (vm.count("help")) {
        std::cout << desc << std::endl;
        return 0;
    }
    
    unsigned int mode = vm["mode"].as<unsigned int>();
    std::string src = vm["source"].as<std::string>();
    std::string cip = vm["result_cip"].as<std::string>();
    std::string dec = vm["result_dec"].as<std::string>();
    std::string pass = vm["pass"].as<std::string>();
    
    if (mode == 1) {
        encrypt(src, cip, pass);
        std::cout << "File encrypted successfully." << std::endl;
    }
    
    else if (mode == 2) {
        decrypt(cip, dec, pass);
        std::cout << "File decrypted successfully." << std::endl;
    }
    
    else {
        std::cerr << "Invalid mode. Please enter '1 or '2." << std::endl;
        return 1;
    }
    return 0;
}