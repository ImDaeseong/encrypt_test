#pragma once
class CSHA256
{
public:
	static std::string GetSHA256FromText(const std::string& text);
	static std::string GetSHA256FromFile(const std::string& filepath);
};

