#include "pch.h"
#include "CMD5.h"

std::string CMD5::GetMD5FromText(const std::string& text)
{
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE hash[16];
    DWORD hashSize = 16;
    char hexHash[33] = { 0 };

    // CryptoAPI ���ؽ�Ʈ ����
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        return "";

    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
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

    // 16����Ʈ(128��Ʈ) �ؽ� ���� 32�ڸ� HEX ���ڿ��� ��ȯ
    for (int i = 0; i < 16; i++)
        sprintf_s(hexHash + i * 2, 3, "%02x", hash[i]);

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    return std::string(hexHash);
}

// ���� MD5 �ؽ� ��ȯ
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

    // 16����Ʈ(128��Ʈ) �ؽ� ���� 32�ڸ� HEX ���ڿ��� ��ȯ
    for (int i = 0; i < 16; i++)
        sprintf_s(hexHash + i * 2, 3, "%02x", hash[i]);

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    return std::string(hexHash);
}