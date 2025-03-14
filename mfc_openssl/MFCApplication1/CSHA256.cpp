#include "pch.h"
#include "CSHA256.h"
#pragma warning(disable : 4996)  // 사용되지 않는 함수 경고 비활성화
#include <openssl/sha.h>
#include <fstream>
#include <sstream>
#include <iomanip>

std::string CSHA256::GetSHA256FromText(const std::string& text)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256Context;
    SHA256_Init(&sha256Context);
    SHA256_Update(&sha256Context, reinterpret_cast<const unsigned char*>(text.c_str()), text.length());
    SHA256_Final(hash, &sha256Context);

    std::ostringstream hexStream;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        hexStream << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];

    return hexStream.str();
}

std::string CSHA256::GetSHA256FromFile(const std::string& filepath)
{
    std::ifstream file(filepath, std::ios::binary);
    if (!file)
        return "";

    SHA256_CTX sha256Context;
    SHA256_Init(&sha256Context);

    char buffer[8192];
    while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0)
    {
        SHA256_Update(&sha256Context, reinterpret_cast<const unsigned char*>(buffer), file.gcount());
    }
    file.close();

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &sha256Context);

    std::ostringstream hexStream;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        hexStream << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];

    return hexStream.str();
}