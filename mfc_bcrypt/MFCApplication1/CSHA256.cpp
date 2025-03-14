#include "pch.h"
#include "CSHA256.h"

std::string CSHA256::GetSHA256FromText(const std::string& text)
{
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD hashSize = 0, dataSize = 0;
    std::vector<BYTE> hash(32); // SHA-256은 32바이트(256비트)
    char hexHash[65] = { 0 };

    if (BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0)
        return "";

    if (BCryptCreateHash(hAlgorithm, &hHash, NULL, 0, NULL, 0, 0) != 0)
    {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return "";
    }

    if (BCryptHashData(hHash, (BYTE*)text.c_str(), (ULONG)text.size(), 0) != 0)
    {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return "";
    }

    if (BCryptFinishHash(hHash, hash.data(), (ULONG)hash.size(), 0) != 0)
    {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return "";
    }

    for (int i = 0; i < 32; i++)
        sprintf_s(hexHash + i * 2, 3, "%02x", hash[i]);

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlgorithm, 0);

    return std::string(hexHash);
}

std::string CSHA256::GetSHA256FromFile(const std::string& filepath)
{
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD hashSize = 0, dataSize = 0;
    std::vector<BYTE> hash(32);
    char hexHash[65] = { 0 };
    BYTE buffer[8192];
    std::ifstream file(filepath, std::ios::binary);

    if (!file)
        return "";

    if (BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0)
        return "";

    if (BCryptCreateHash(hAlgorithm, &hHash, NULL, 0, NULL, 0, 0) != 0)
    {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return "";
    }

    while (file.read(reinterpret_cast<char*>(buffer), sizeof(buffer)) || file.gcount() > 0)
    {
        if (BCryptHashData(hHash, buffer, static_cast<ULONG>(file.gcount()), 0) != 0)
        {
            BCryptDestroyHash(hHash);
            BCryptCloseAlgorithmProvider(hAlgorithm, 0);
            return "";
        }
    }

    file.close();

    if (BCryptFinishHash(hHash, hash.data(), (ULONG)hash.size(), 0) != 0)
    {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return "";
    }

    for (int i = 0; i < 32; i++)
        sprintf_s(hexHash + i * 2, 3, "%02x", hash[i]);

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlgorithm, 0);

    return std::string(hexHash);
}