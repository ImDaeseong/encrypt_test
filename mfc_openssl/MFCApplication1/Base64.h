#pragma once
#include <string>
#include <vector>
#include <stdexcept>

using BYTE = unsigned char;

class Base64
{
private:
    // 표준 Base64 인코딩 테이블
    static const char base64_chars[];
    // 디코딩을 위한 룩업 테이블
    static std::vector<int> InitDecodeTable();
    static const std::vector<int> decodeTable;

public:
    // 바이너리 데이터를 Base64 문자열로 인코딩 (패딩 없음)
    static std::string Encode(const std::vector<BYTE>& data);

    // Base64 문자열을 바이너리 데이터로 디코딩
    static std::vector<BYTE> Decode(const std::string& base64);

    // 벡터가 아닌 일반 바이트 배열을 인코딩하는 오버로드 함수
    static std::string Encode(const BYTE* data, size_t length);

    // std::string을 바이너리 데이터로 인코딩하는 편의 함수
    static std::string EncodeString(const std::string& str);

    // 바이너리 데이터를 std::string으로 디코딩하는 편의 함수
    static std::string DecodeToString(const std::string& base64);
};