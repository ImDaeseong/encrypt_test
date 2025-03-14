#pragma once
#include <string>
#include <vector>
#include <stdexcept>

using BYTE = unsigned char;

class Base64
{
private:
    // ǥ�� Base64 ���ڵ� ���̺�
    static const char base64_chars[];
    // ���ڵ��� ���� ��� ���̺�
    static std::vector<int> InitDecodeTable();
    static const std::vector<int> decodeTable;

public:
    // ���̳ʸ� �����͸� Base64 ���ڿ��� ���ڵ� (�е� ����)
    static std::string Encode(const std::vector<BYTE>& data);

    // Base64 ���ڿ��� ���̳ʸ� �����ͷ� ���ڵ�
    static std::vector<BYTE> Decode(const std::string& base64);

    // ���Ͱ� �ƴ� �Ϲ� ����Ʈ �迭�� ���ڵ��ϴ� �����ε� �Լ�
    static std::string Encode(const BYTE* data, size_t length);

    // std::string�� ���̳ʸ� �����ͷ� ���ڵ��ϴ� ���� �Լ�
    static std::string EncodeString(const std::string& str);

    // ���̳ʸ� �����͸� std::string���� ���ڵ��ϴ� ���� �Լ�
    static std::string DecodeToString(const std::string& base64);
};