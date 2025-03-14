#include "pch.h"
#include "CMD5.h"

std::string CMD5::GetMD5FromText(const std::string& text)
{
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    DWORD hashSize = 0, dataSize = 0;
    UCHAR hash[16];
    char hexHash[33] = { 0 };

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_MD5_ALGORITHM, NULL, 0) != 0)
        return "";

    if (BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0) != 0)
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return "";
    }

    if (BCryptHashData(hHash, (PUCHAR)text.c_str(), (ULONG)text.length(), 0) != 0)
    {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return "";
    }

    if (BCryptFinishHash(hHash, hash, sizeof(hash), 0) != 0)
    {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return "";
    }

    for (int i = 0; i < 16; i++)
        sprintf_s(hexHash + i * 2, 3, "%02x", hash[i]);

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return std::string(hexHash);
}

// 파일 MD5 해시 반환
std::string CMD5::GetMD5FromFile(const std::string& filepath)
{
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    UCHAR hash[16];
    char hexHash[33] = { 0 };
    BYTE buffer[8192];
    std::ifstream file(filepath, std::ios::binary);

    if (!file)
        return "";

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_MD5_ALGORITHM, NULL, 0) != 0)
        return "";

    if (BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0) != 0)
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return "";
    }

    while (file.read(reinterpret_cast<char*>(buffer), sizeof(buffer)) || file.gcount() > 0)
    {
        if (BCryptHashData(hHash, buffer, (ULONG)file.gcount(), 0) != 0)
        {
            BCryptDestroyHash(hHash);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return "";
        }
    }

    file.close();

    if (BCryptFinishHash(hHash, hash, sizeof(hash), 0) != 0)
    {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return "";
    }

    for (int i = 0; i < 16; i++)
        sprintf_s(hexHash + i * 2, 3, "%02x", hash[i]);

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return std::string(hexHash);
}