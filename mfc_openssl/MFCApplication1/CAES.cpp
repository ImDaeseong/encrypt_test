#include "pch.h"
#include "CAES.h"
#pragma warning(disable : 4996) // ������ �ʴ� �Լ� ��� ��Ȱ��ȭ
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <stdexcept>
#include <string>
#include <vector>
#include <iostream>
#include <memory>

// CAES Ŭ���� ������: ��ȣȭ/��ȣȭ�� ���� Ű�� �Է¹���
CAES::CAES(const std::string& key)
{
    if (key.length() != 32)  // AES 256�� 32����Ʈ Ű�� �ʿ���
    {
        throw std::invalid_argument("Key must be 32 bytes");
    }
    m_key = key;
    m_blockSize = AES_BLOCK_SIZE; // AES ��� ũ��� 16����Ʈ
}

std::string CAES::EncryptText(const std::string& text)
{
    if (text.empty())
    {
        throw std::invalid_argument("Input text cannot be empty");
    }

    // OpenSSL�� �ʱ�ȭ���� �ʾҴٸ� �ʱ�ȭ
    static bool opensslInitialized = false;
    if (!opensslInitialized)
    {
        OpenSSL_add_all_algorithms();
        opensslInitialized = true;
    }

    // SHA-256�� ����Ͽ� Ű �غ�
    unsigned char key[32]; // AES-256�� ���� 32����Ʈ ���
    SHA256_CTX sha256_ctx;
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, m_key.c_str(), m_key.length());
    SHA256_Final(key, &sha256_ctx);

    // ���� IV(�ʱ�ȭ ����) ���� (16����Ʈ)
    unsigned char iv[AES_BLOCK_SIZE];
    if (RAND_bytes(iv, AES_BLOCK_SIZE) != 1)
    {
        throw std::runtime_error("Error generating random IV");
    }

    // �� ���� ���Ȱ� �������� API�� ���� EVP ���
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        throw std::runtime_error("Failed to create EVP cipher context");
    }

    // ��ȣȭ �۾� �ʱ�ȭ
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize encryption operation");
    }

    // �ʿ��� ���� ũ�� ���� (�� ���� + �е��� ���� ��� ũ��)
    int maxCiphertextLength = text.length() + AES_BLOCK_SIZE;
    std::vector<unsigned char> ciphertext(maxCiphertextLength);
    int ciphertextLength = 0;
    int len = 0;

    // ������ ��ȣȭ
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, reinterpret_cast<const unsigned char*>(text.data()), static_cast<int>(text.length())) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encryption failed during update");
    }
    ciphertextLength = len;

    // ��ȣȭ ������ (�е� ó��)
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encryption failed during finalization");
    }
    ciphertextLength += len;

    // �ڿ� ����
    EVP_CIPHER_CTX_free(ctx);

    // ���� ũ��� ��ȣ�� ����
    ciphertext.resize(ciphertextLength);

    // IV�� ��ȣ�� ����
    std::vector<unsigned char> combined(iv, iv + AES_BLOCK_SIZE);
    combined.insert(combined.end(), ciphertext.begin(), ciphertext.end());

    // ����� Base64�� ���ڵ� (�е� ����)
    return Base64::Encode(combined);
}

std::string CAES::DecryptText(const std::string& text)
{
    try
    {
        // �Է� �ؽ�Ʈ�� Base64 ���ڵ�
        std::vector<unsigned char> combined = Base64::Decode(text);

        if (combined.size() <= AES_BLOCK_SIZE)
        {
            throw std::runtime_error("Invalid ciphertext format: too short");
        }

        // IV�� ��ȣ�� ����
        std::vector<unsigned char> iv(combined.begin(), combined.begin() + AES_BLOCK_SIZE);
        std::vector<unsigned char> ciphertext(combined.begin() + AES_BLOCK_SIZE, combined.end());

        // SHA-256�� ����Ͽ� Ű �غ�
        unsigned char key[32]; // AES-256�� ���� 32����Ʈ ���
        SHA256_CTX sha256_ctx;
        SHA256_Init(&sha256_ctx);
        SHA256_Update(&sha256_ctx, m_key.c_str(), m_key.length());
        SHA256_Final(key, &sha256_ctx);

        // OpenSSL�� �ʱ�ȭ���� �ʾҴٸ� �ʱ�ȭ
        static bool opensslInitialized = false;
        if (!opensslInitialized)
        {
            OpenSSL_add_all_algorithms();
            opensslInitialized = true;
        }

        // �� ���� ���Ȱ� �������� API�� ���� EVP ���
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
        {
            throw std::runtime_error("Failed to create EVP cipher context");
        }

        // ��ȣȭ �۾� �ʱ�ȭ
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv.data()) != 1)
        {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize decryption operation");
        }

        // ��� ���� �غ� (��ȣ���� ������ ũ��� ���)
        std::vector<unsigned char> plaintext(ciphertext.size());
        int plaintextLength = 0;
        int len = 0;

        // ������ ��ȣȭ
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &len,
            ciphertext.data(), static_cast<int>(ciphertext.size())) != 1)
        {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Decryption failed during update");
        }
        plaintextLength = len;

        // ��ȣȭ ������ (�е� ó��)
        if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1)
        {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Decryption failed during finalization: padding error");
        }
        plaintextLength += len;

        // �ڿ� ����
        EVP_CIPHER_CTX_free(ctx);

        // ���� ũ��� �� ����
        plaintext.resize(plaintextLength);

        // ��ȣȭ�� �����͸� ���ڿ��� ��ȯ
        return std::string(plaintext.begin(), plaintext.end());
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(std::string("Decryption error: ") + e.what());
    }
}