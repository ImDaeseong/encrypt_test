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
};

