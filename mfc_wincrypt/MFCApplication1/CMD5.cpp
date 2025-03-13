#include "pch.h"
#include "CMD5.h"

std::string CMD5::GetMD5FromText(const std::string& text)
{
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE hash[16];
    DWORD hashSize = 16;
    char hexHash[33] = { 0 };

    // CryptoAPI 컨텍스트 생성
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        return "";

    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
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

    // 16바이트(128비트) 해시 값을 32자리 HEX 문자열로 변환
    for (int i = 0; i < 16; i++)
        sprintf_s(hexHash + i * 2, 3, "%02x", hash[i]);

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    return std::string(hexHash);
}

// 파일 MD5 해시 반환
std::string CMD5::GetMD5FromFile(const std::string& filepath)
{
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE hash[16];
    DWORD hashSize = 16;
    char hexHash[33] = { 0 };
    BYTE buffer[8192];
    std::ifstream file(filepath, std::ios::binary);

    if (!file)
        return "";

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        return "";

    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
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

    // 16바이트(128비트) 해시 값을 32자리 HEX 문자열로 변환
    for (int i = 0; i < 16; i++)
        sprintf_s(hexHash + i * 2, 3, "%02x", hash[i]);

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    return std::string(hexHash);
}