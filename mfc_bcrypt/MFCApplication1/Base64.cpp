#include "pch.h"
#include "Base64.h"

// 정적 멤버 초기화
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
    // 대략적인 결과 크기 예약 (패딩이 없으므로 정확한 크기 계산이 어려움)
    result.reserve((length * 4) / 3 + 1);

    size_t i = 0;

    // 3바이트씩 처리
    for (; i + 2 < length; i += 3) 
    {
        // 3바이트를 4개의 6비트 그룹으로 변환
        result.push_back(base64_chars[(data[i] >> 2) & 0x3F]);
        result.push_back(base64_chars[((data[i] & 0x3) << 4) | ((data[i + 1] >> 4) & 0xF)]);
        result.push_back(base64_chars[((data[i + 1] & 0xF) << 2) | ((data[i + 2] >> 6) & 0x3)]);
        result.push_back(base64_chars[data[i + 2] & 0x3F]);
    }

    // 남은 바이트 처리 (1 또는 2바이트) - 패딩('=') 없이 처리
    if (i < length) 
    {
        // 첫 번째 바이트 처리
        result.push_back(base64_chars[(data[i] >> 2) & 0x3F]);

        if (i + 1 < length) 
        {
            // 두 번째 바이트가 있는 경우
            result.push_back(base64_chars[((data[i] & 0x3) << 4) | ((data[i + 1] >> 4) & 0xF)]);
            result.push_back(base64_chars[(data[i + 1] & 0xF) << 2]);
        }
        else 
        {
            // 두 번째 바이트가 없는 경우
            result.push_back(base64_chars[(data[i] & 0x3) << 4]);
        }
        // 패딩 문자는 추가하지 않음
    }
    return result;

    //패딩('=') 문자 미처리 
    /*
    if (data == nullptr || length == 0)
    {
        return std::string();
    }

    std::string result;
    // 약 4/3의 비율로 결과 문자열 예약
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

    // 패딩 문자 '=' 추가
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

    // 결과 크기 계산 (패딩 없음 가정)
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
            // 패딩 문자는 무시 (호환성을 위해 허용)
            continue;
        }

        int value = decodeTable[static_cast<unsigned char>(c)];
        if (value == -1) 
        {
            throw std::runtime_error("유효하지 않은 Base64 문자가 포함되어 있습니다");
        }

        // 6비트씩 추가
        temp = (temp << 6) | value;
        bits += 6;

        // 8비트가 모이면 1바이트 추출
        if (bits >= 8) 
        {
            bits -= 8;
            result.push_back((temp >> bits) & 0xFF);
        }
    }
    return result;

    //패딩('=') 문자 미처리 
    /*
    if (base64.empty()) 
    {
        return std::vector<BYTE>();
    }

    std::vector<BYTE> result;
    // 약 3/4의 비율로 결과 벡터 예약
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
            throw std::runtime_error("유효하지 않은 Base64 문자가 포함되어 있습니다");
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