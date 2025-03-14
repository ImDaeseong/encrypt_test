#include "pch.h"
#include "CMD5.h"
#pragma warning(disable : 4996) // 사용되지 않는 함수 경고 비활성화
#include <openssl/md5.h>
#include <fstream>
#include <sstream>
#include <iomanip>

std::string CMD5::GetMD5FromText(const std::string& text)
{
    unsigned char hash[MD5_DIGEST_LENGTH];

    // OpenSSL 3.0에서는 MD5 함수 호출 방식이 달라지지 않았습니다.
    MD5_CTX md5Context;
    MD5_Init(&md5Context);
    MD5_Update(&md5Context, reinterpret_cast<const unsigned char*>(text.c_str()), text.length());
    MD5_Final(hash, &md5Context);

    std::ostringstream hexStream;
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++)
        hexStream << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];

    return hexStream.str();
}

// 파일 MD5 해시 반환
std::string CMD5::GetMD5FromFile(const std::string& filepath)
{
    std::ifstream file(filepath, std::ios::binary);
    if (!file)
        return "";

    MD5_CTX md5Context;
    MD5_Init(&md5Context);

    char buffer[8192];
    while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0)
    {
        MD5_Update(&md5Context, reinterpret_cast<const unsigned char*>(buffer), file.gcount());
    }
    file.close();

    unsigned char hash[MD5_DIGEST_LENGTH];
    MD5_Final(hash, &md5Context);

    std::ostringstream hexStream;
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++)
        hexStream << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];

    return hexStream.str();
}