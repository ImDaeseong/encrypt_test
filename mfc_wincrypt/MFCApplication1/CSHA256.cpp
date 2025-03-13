#include "pch.h"
#include "CSHA256.h"

std::string CSHA256::GetSHA256FromText(const std::string& text)
{
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE hash[32];  // SHA-256은 32바이트(256비트)
    DWORD hashSize = 32;
    char hexHash[65] = { 0 };  // 32바이트 * 2 + null 문자

    // CryptoAPI 컨텍스트 생성
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return "";

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
    {
        CryptReleaseContext(hProv, 0);
        return "";
    }

    // 입력 문자열을 해시 데이터로 변환
    if (!CryptHashData(hHash, (BYTE*)text.c_str(), text.length(), 0))
    {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    // 해시 값 추출
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashSize, 0))
    {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    // 32바이트(256비트) 해시 값을 64자리 HEX 문자열로 변환
    for (int i = 0; i < 32; i++)
        sprintf_s(hexHash + i * 2, 3, "%02x", hash[i]);

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    return std::string(hexHash);
}

std::string CSHA256::GetSHA256FromFile(const std::string& filepath)
{
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE hash[32];  // SHA-256은 32바이트(256비트)
    DWORD hashSize = 32;
    char hexHash[65] = { 0 };
    BYTE buffer[8192];
    std::ifstream file(filepath, std::ios::binary);

    if (!file)
        return "";

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return "";

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
    {
        CryptReleaseContext(hProv, 0);
        return "";
    }

    // 파일을 읽어서 해시 계산
    while (file.read(reinterpret_cast<char*>(buffer), sizeof(buffer)) || file.gcount() > 0)
    {
        if (!CryptHashData(hHash, buffer, static_cast<DWORD>(file.gcount()), 0))
        {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return "";
        }
    }

    file.close();

    // 최종 해시 값 가져오기
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashSize, 0))
    {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    // 32바이트(256비트) 해시 값을 64자리 HEX 문자열로 변환
    for (int i = 0; i < 32; i++)
        sprintf_s(hexHash + i * 2, 3, "%02x", hash[i]);

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    return std::string(hexHash);
}