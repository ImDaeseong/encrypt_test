#include "pch.h"
#include "CSHA256.h"

std::string CSHA256::GetSHA256FromText(const std::string& text)
{
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE hash[32];  // SHA-256�� 32����Ʈ(256��Ʈ)
    DWORD hashSize = 32;
    char hexHash[65] = { 0 };  // 32����Ʈ * 2 + null ����

    // CryptoAPI ���ؽ�Ʈ ����
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return "";

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
    {
        CryptReleaseContext(hProv, 0);
        return "";
    }

    // �Է� ���ڿ��� �ؽ� �����ͷ� ��ȯ
    if (!CryptHashData(hHash, (BYTE*)text.c_str(), text.length(), 0))
    {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    // �ؽ� �� ����
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashSize, 0))
    {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    // 32����Ʈ(256��Ʈ) �ؽ� ���� 64�ڸ� HEX ���ڿ��� ��ȯ
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
    BYTE hash[32];  // SHA-256�� 32����Ʈ(256��Ʈ)
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

    // ������ �о �ؽ� ���
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

    // ���� �ؽ� �� ��������
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashSize, 0))
    {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    // 32����Ʈ(256��Ʈ) �ؽ� ���� 64�ڸ� HEX ���ڿ��� ��ȯ
    for (int i = 0; i < 32; i++)
        sprintf_s(hexHash + i * 2, 3, "%02x", hash[i]);

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    return std::string(hexHash);
}