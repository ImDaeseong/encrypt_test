#include "pch.h"
#include "Base64.h"

// ���� ��� �ʱ�ȭ
const char Base64::base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::vector<int> Base64::InitDecodeTable() 
{
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) 
    {
        T[static_cast<int>(base64_chars[i])] = i;
    }
    return T;
}

const std::vector<int> Base64::decodeTable = Base64::InitDecodeTable();

std::string Base64::Encode(const std::vector<BYTE>& data)
{
    if (data.empty()) 
    {
        return std::string();
    }

    return Encode(data.data(), data.size());
}

std::string Base64::Encode(const BYTE* data, size_t length) 
{
    if (data == nullptr || length == 0) 
    {
        return std::string();
    }

    std::string result;
    // �뷫���� ��� ũ�� ���� (�е��� �����Ƿ� ��Ȯ�� ũ�� ����� �����)
    result.reserve((length * 4) / 3 + 1);

    size_t i = 0;

    // 3����Ʈ�� ó��
    for (; i + 2 < length; i += 3) 
    {
        // 3����Ʈ�� 4���� 6��Ʈ �׷����� ��ȯ
        result.push_back(base64_chars[(data[i] >> 2) & 0x3F]);
        result.push_back(base64_chars[((data[i] & 0x3) << 4) | ((data[i + 1] >> 4) & 0xF)]);
        result.push_back(base64_chars[((data[i + 1] & 0xF) << 2) | ((data[i + 2] >> 6) & 0x3)]);
        result.push_back(base64_chars[data[i + 2] & 0x3F]);
    }

    // ���� ����Ʈ ó�� (1 �Ǵ� 2����Ʈ) - �е�('=') ���� ó��
    if (i < length) 
    {
        // ù ��° ����Ʈ ó��
        result.push_back(base64_chars[(data[i] >> 2) & 0x3F]);

        if (i + 1 < length) 
        {
            // �� ��° ����Ʈ�� �ִ� ���
            result.push_back(base64_chars[((data[i] & 0x3) << 4) | ((data[i + 1] >> 4) & 0xF)]);
            result.push_back(base64_chars[(data[i + 1] & 0xF) << 2]);
        }
        else 
        {
            // �� ��° ����Ʈ�� ���� ���
            result.push_back(base64_chars[(data[i] & 0x3) << 4]);
        }
        // �е� ���ڴ� �߰����� ����
    }
    return result;

    //�е�('=') ���� ��ó�� 
    /*
    if (data == nullptr || length == 0)
    {
        return std::string();
    }

    std::string result;
    // �� 4/3�� ������ ��� ���ڿ� ����
    result.reserve((length * 4) / 3 + 4);

    int val = 0;
    int valb = -6;

    for (size_t i = 0; i < length; i++) 
    {
        val = (val << 8) + data[i];
        valb += 8;
        while (valb >= 0) 
        {
            result.push_back(base64_chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }

    if (valb > -6) 
    {
        result.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    }

    // �е� ���� '=' �߰�
    while (result.size() % 4) 
    {
        result.push_back('=');
    }

    return result;
    */
}

std::vector<BYTE> Base64::Decode(const std::string& base64)
{
    if (base64.empty()) 
    {
        return std::vector<BYTE>();
    }

    const size_t inputLength = base64.length();

    // ��� ũ�� ��� (�е� ���� ����)
    size_t outputLength = (inputLength * 3) / 4;
    std::vector<BYTE> result;
    result.reserve(outputLength);

    size_t i = 0;
    uint32_t temp = 0;
    int bits = 0;

    for (char c : base64) 
    {
        if (c == '=') 
        {
            // �е� ���ڴ� ���� (ȣȯ���� ���� ���)
            continue;
        }

        int value = decodeTable[static_cast<unsigned char>(c)];
        if (value == -1) 
        {
            throw std::runtime_error("��ȿ���� ���� Base64 ���ڰ� ���ԵǾ� �ֽ��ϴ�");
        }

        // 6��Ʈ�� �߰�
        temp = (temp << 6) | value;
        bits += 6;

        // 8��Ʈ�� ���̸� 1����Ʈ ����
        if (bits >= 8) 
        {
            bits -= 8;
            result.push_back((temp >> bits) & 0xFF);
        }
    }
    return result;

    //�е�('=') ���� ��ó�� 
    /*
    if (base64.empty()) 
    {
        return std::vector<BYTE>();
    }

    std::vector<BYTE> result;
    // �� 3/4�� ������ ��� ���� ����
    result.reserve((base64.size() * 3) / 4);

    int val = 0;
    int valb = -8;

    for (char c : base64)
    {
        if (c == '=') 
        {
            break;
        }

        int decodedChar = decodeTable[static_cast<unsigned char>(c)];
        if (decodedChar == -1) 
        {
            throw std::runtime_error("��ȿ���� ���� Base64 ���ڰ� ���ԵǾ� �ֽ��ϴ�");
        }

        val = (val << 6) + decodedChar;
        valb += 6;

        if (valb >= 0) 
        {
            result.push_back((val >> valb) & 0xFF);
            valb -= 8;
        }
    }

    return result;
    */
}

std::string Base64::EncodeString(const std::string& str)
{
    return Encode(reinterpret_cast<const BYTE*>(str.data()), str.length());
}

std::string Base64::DecodeToString(const std::string& base64)
{
    std::vector<BYTE> bytes = Decode(base64);
    return std::string(bytes.begin(), bytes.end());
}