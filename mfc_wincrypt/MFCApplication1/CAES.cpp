#include "pch.h"
#include "CAES.h"

CAES::CAES(const std::string& key)
{
    if (key.length() != 32)
    {
        throw std::invalid_argument("Key must be 32 bytes");
    }

    m_key = key;
    m_blockSize = 16; // AES block size is 16 bytes
}

std::string CAES::EncryptText(const std::string& text)
{
    // Acquire a cryptographic provider context
    HCRYPTPROV hProv = NULL;
    if (!CryptAcquireContext(&hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
    {
        DWORD dwError = GetLastError();
        throw std::runtime_error("CryptAcquireContext failed: " + std::to_string(dwError));
    }

    // Create a hash object for the key
    HCRYPTHASH hHash = NULL;
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
    {
        DWORD dwError = GetLastError();
        CryptReleaseContext(hProv, 0);
        throw std::runtime_error("CryptCreateHash failed: " + std::to_string(dwError));
    }

    // Hash the key
    if (!CryptHashData(hHash, (BYTE*)m_key.c_str(), m_key.length(), 0))
    {
        DWORD dwError = GetLastError();
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        throw std::runtime_error("CryptHashData failed: " + std::to_string(dwError));
    }

    // Create a key object from the hash
    HCRYPTKEY hKey = NULL;
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey))
    {
        DWORD dwError = GetLastError();
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        throw std::runtime_error("CryptDeriveKey failed: " + std::to_string(dwError));
    }

    // Create IV (Initialization Vector)
    std::vector<BYTE> iv(m_blockSize);
    DWORD dwMode = CRYPT_MODE_CBC;

    // Generate random IV
    if (!CryptGenRandom(hProv, m_blockSize, iv.data()))
    {
        DWORD dwError = GetLastError();
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        throw std::runtime_error("CryptGenRandom failed: " + std::to_string(dwError));
    }

    // Set the cipher mode to CBC
    if (!CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&dwMode, 0))
    {
        DWORD dwError = GetLastError();
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        throw std::runtime_error("CryptSetKeyParam (KP_MODE) failed: " + std::to_string(dwError));
    }

    // Set the IV
    if (!CryptSetKeyParam(hKey, KP_IV, iv.data(), 0))
    {
        DWORD dwError = GetLastError();
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        throw std::runtime_error("CryptSetKeyParam (KP_IV) failed: " + std::to_string(dwError));
    }

    // Prepare buffer for encryption
    std::vector<BYTE> buffer(text.begin(), text.end());
    DWORD dwDataLen = buffer.size();

    // Determine the size needed for encryption
    if (!CryptEncrypt(hKey, 0, TRUE, 0, NULL, &dwDataLen, 0))
    {
        DWORD dwError = GetLastError();
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        throw std::runtime_error("CryptEncrypt (size check) failed: " + std::to_string(dwError));
    }

    // Resize buffer to include padding
    buffer.resize(dwDataLen);
    dwDataLen = text.size();

    // Encrypt the data
    if (!CryptEncrypt(hKey, 0, TRUE, 0, buffer.data(), &dwDataLen, buffer.size()))
    {
        DWORD dwError = GetLastError();
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        throw std::runtime_error("CryptEncrypt failed: " + std::to_string(dwError));
    }

    // Combine IV and ciphertext
    std::vector<BYTE> combined;
    combined.insert(combined.end(), iv.begin(), iv.end());
    combined.insert(combined.end(), buffer.begin(), buffer.begin() + dwDataLen);

    // Base64 encode the result
    std::string result = Base64Encode(combined);
    //std::string result = Base64::Encode(combined);

    // Clean up
    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    return result;
}

std::string CAES::DecryptText(const std::string& text)
{
    try
    {
        // Base64 decode
        std::vector<BYTE> combined = Base64Decode(text);
        //std::vector<BYTE> combined = Base64::Decode(text);

        // Extract IV and ciphertext
        if (combined.size() <= m_blockSize)
        {
            throw std::runtime_error("Invalid ciphertext format");
        }

        std::vector<BYTE> iv(combined.begin(), combined.begin() + m_blockSize);
        std::vector<BYTE> ciphertext(combined.begin() + m_blockSize, combined.end());

        // Acquire cryptographic provider
        HCRYPTPROV hProv = NULL;
        if (!CryptAcquireContext(&hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        {
            DWORD dwError = GetLastError();
            throw std::runtime_error("CryptAcquireContext failed: " + std::to_string(dwError));
        }

        // Create hash object for the key
        HCRYPTHASH hHash = NULL;
        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
        {
            DWORD dwError = GetLastError();
            CryptReleaseContext(hProv, 0);
            throw std::runtime_error("CryptCreateHash failed: " + std::to_string(dwError));
        }

        // Hash the key
        if (!CryptHashData(hHash, (BYTE*)m_key.c_str(), m_key.length(), 0))
        {
            DWORD dwError = GetLastError();
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            throw std::runtime_error("CryptHashData failed: " + std::to_string(dwError));
        }

        // Derive key from hash
        HCRYPTKEY hKey = NULL;
        if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey))
        {
            DWORD dwError = GetLastError();
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            throw std::runtime_error("CryptDeriveKey failed: " + std::to_string(dwError));
        }

        // Set cipher mode to CBC
        DWORD dwMode = CRYPT_MODE_CBC;
        if (!CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&dwMode, 0))
        {
            DWORD dwError = GetLastError();
            CryptDestroyKey(hKey);
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            throw std::runtime_error("CryptSetKeyParam (KP_MODE) failed: " + std::to_string(dwError));
        }

        // Set IV
        if (!CryptSetKeyParam(hKey, KP_IV, iv.data(), 0))
        {
            DWORD dwError = GetLastError();
            CryptDestroyKey(hKey);
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            throw std::runtime_error("CryptSetKeyParam (KP_IV) failed: " + std::to_string(dwError));
        }

        // Prepare buffer for decryption
        std::vector<BYTE> buffer = ciphertext;
        DWORD dwDataLen = buffer.size();

        // Decrypt the data
        if (!CryptDecrypt(hKey, 0, TRUE, 0, buffer.data(), &dwDataLen))
        {
            DWORD dwError = GetLastError();
            CryptDestroyKey(hKey);
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            throw std::runtime_error("CryptDecrypt failed: " + std::to_string(dwError));
        }

        // Convert decrypted data to string
        std::string plaintext(buffer.begin(), buffer.begin() + dwDataLen);

        // Clean up
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);

        return plaintext;
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(std::string("Decryption error: ") + e.what());
    }
}