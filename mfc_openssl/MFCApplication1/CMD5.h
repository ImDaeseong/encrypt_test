#pragma once
class CMD5
{
public:
	static std::string GetMD5FromText(const std::string& text);
	static std::string GetMD5FromFile(const std::string& filepath);
};

