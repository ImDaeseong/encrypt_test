#include "pch.h"
#include "CAES.h"
#pragma warning(disable : 4996) // 사용되지 않는 함수 경고 비활성화
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <stdexcept>
#include <string>
#include <vector>
#include <iostream>
#include <memory>

// CAES 클래스 생성자: 암호화/복호화를 위한 키를 입력받음
CAES::CAES(const std::string& key)
{
    if (key.length() != 32)  // AES 256은 32바이트 키가 필요함
    {
        throw std::invalid_argument("Key must be 32 bytes");
    }
    m_key = key;
    m_blockSize = AES_BLOCK_SIZE; // AES 블록 크기는 16바이트
}

std::string CAES::EncryptText(const std::string& text)
{
    if (text.empty())
    {
        throw std::invalid_argument("Input text cannot be empty");
    }

    // OpenSSL이 초기화되지 않았다면 초기화
    static bool opensslInitialized = false;
    if (!opensslInitialized)
    {
        OpenSSL_add_all_algorithms();
        opensslInitialized = true;
    }

    // SHA-256을 사용하여 키 준비
    unsigned char key[32]; // AES-256을 위해 32바이트 사용
    SHA256_CTX sha256_ctx;
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, m_key.c_str(), m_key.length());
    SHA256_Final(key, &sha256_ctx);

    // 랜덤 IV(초기화 벡터) 생성 (16바이트)
    unsigned char iv[AES_BLOCK_SIZE];
    if (RAND_bytes(iv, AES_BLOCK_SIZE) != 1)
    {
        throw std::runtime_error("Error generating random IV");
    }

    // 더 나은 보안과 현대적인 API를 위해 EVP 사용
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        throw std::runtime_error("Failed to create EVP cipher context");
    }

    // 암호화 작업 초기화
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize encryption operation");
    }

    // 필요한 버퍼 크기 결정 (평문 길이 + 패딩을 위한 블록 크기)
    int maxCiphertextLength = text.length() + AES_BLOCK_SIZE;
    std::vector<unsigned char> ciphertext(maxCiphertextLength);
    int ciphertextLength = 0;
    int len = 0;

    // 데이터 암호화
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, reinterpret_cast<const unsigned char*>(text.data()), static_cast<int>(text.length())) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encryption failed during update");
    }
    ciphertextLength = len;

    // 암호화 마무리 (패딩 처리)
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encryption failed during finalization");
    }
    ciphertextLength += len;

    // 자원 정리
    EVP_CIPHER_CTX_free(ctx);

    // 실제 크기로 암호문 조정
    ciphertext.resize(ciphertextLength);

    // IV와 암호문 결합
    std::vector<unsigned char> combined(iv, iv + AES_BLOCK_SIZE);
    combined.insert(combined.end(), ciphertext.begin(), ciphertext.end());

    // 결과를 Base64로 인코딩 (패딩 없이)
    return Base64::Encode(combined);
}

std::string CAES::DecryptText(const std::string& text)
{
    try
    {
        // 입력 텍스트를 Base64 디코딩
        std::vector<unsigned char> combined = Base64::Decode(text);

        if (combined.size() <= AES_BLOCK_SIZE)
        {
            throw std::runtime_error("Invalid ciphertext format: too short");
        }

        // IV와 암호문 추출
        std::vector<unsigned char> iv(combined.begin(), combined.begin() + AES_BLOCK_SIZE);
        std::vector<unsigned char> ciphertext(combined.begin() + AES_BLOCK_SIZE, combined.end());

        // SHA-256을 사용하여 키 준비
        unsigned char key[32]; // AES-256을 위해 32바이트 사용
        SHA256_CTX sha256_ctx;
        SHA256_Init(&sha256_ctx);
        SHA256_Update(&sha256_ctx, m_key.c_str(), m_key.length());
        SHA256_Final(key, &sha256_ctx);

        // OpenSSL이 초기화되지 않았다면 초기화
        static bool opensslInitialized = false;
        if (!opensslInitialized)
        {
            OpenSSL_add_all_algorithms();
            opensslInitialized = true;
        }

        // 더 나은 보안과 현대적인 API를 위해 EVP 사용
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
        {
            throw std::runtime_error("Failed to create EVP cipher context");
        }

        // 복호화 작업 초기화
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv.data()) != 1)
        {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize decryption operation");
        }

        // 출력 버퍼 준비 (암호문과 동일한 크기면 충분)
        std::vector<unsigned char> plaintext(ciphertext.size());
        int plaintextLength = 0;
        int len = 0;

        // 데이터 복호화
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &len,
            ciphertext.data(), static_cast<int>(ciphertext.size())) != 1)
        {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Decryption failed during update");
        }
        plaintextLength = len;

        // 복호화 마무리 (패딩 처리)
        if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1)
        {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Decryption failed during finalization: padding error");
        }
        plaintextLength += len;

        // 자원 정리
        EVP_CIPHER_CTX_free(ctx);

        // 실제 크기로 평문 조정
        plaintext.resize(plaintextLength);

        // 복호화된 데이터를 문자열로 변환
        return std::string(plaintext.begin(), plaintext.end());
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(std::string("Decryption error: ") + e.what());
    }
}