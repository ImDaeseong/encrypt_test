#pragma once
class CAES
{
public:
    CAES(const std::string& key);
    std::string EncryptText(const std::string& text);
    std::string DecryptText(const std::string& text);

private:
    std::string m_key;
    int m_blockSize;

    // Base64 encoding helper
    std::string Base64Encode(const std::vector<BYTE>& data)
    {
        if (data.empty())
            return std::string();

        // Calculate the length of the Base64 string
        DWORD dwBase64Length = 0;
        CryptBinaryToStringA(data.data(), data.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &dwBase64Length);

        // Allocate buffer for the Base64 string
        std::vector<char> base64Buffer(dwBase64Length);

        // Convert binary data to Base64 string
        if (!CryptBinaryToStringA(data.data(), data.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, base64Buffer.data(), &dwBase64Length))
        {
            throw std::runtime_error("Base64 encoding failed");
        }

        return std::string(base64Buffer.data(), dwBase64Length - 1); // -1 to remove null terminator
    }

    // Base64 decoding helper
    std::vector<BYTE> Base64Decode(const std::string& base64)
    {
        if (base64.empty())
            return std::vector<BYTE>();

        // Calculate the length of the binary data
        DWORD dwDataLength = 0;
        CryptStringToBinaryA(base64.c_str(), base64.length(), CRYPT_STRING_BASE64, NULL, &dwDataLength, NULL, NULL);

        // Allocate buffer for binary data
        std::vector<BYTE> dataBuffer(dwDataLength);

        // Convert Base64 string to binary data
        if (!CryptStringToBinaryA(base64.c_str(), base64.length(), CRYPT_STRING_BASE64, dataBuffer.data(), &dwDataLength, NULL, NULL))
        {
            throw std::runtime_error("Base64 decoding failed");
        }

        return dataBuffer;
    }
};

