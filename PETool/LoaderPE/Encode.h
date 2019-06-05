
#ifndef _ENCODE_CHARSET_H_
#define _ENCODE_CHARSET_H_

#include <Windows.h>
#include <tchar.h>
#include <string>
#include <vector>

class Encode
{
public:
	static std::string unicode_to_gbk(const std::wstring & wstr);
	static std::string unicode_to_utf8(const std::wstring & wstr);

	static std::wstring gbk_to_unicode(const std::string & gbk);
	static std::string gbk_to_utf8(const std::string & gbk);

	static std::wstring utf8_to_unicode(const std::string & utf8);
	static std::string utf8_to_gbk(const std::string & utf8);

	static LPCSTR wctoc(LPCWSTR wpBuff);
	static LPCWSTR ctowc(LPCSTR pBuff);
	
	static std::string bytes_to_format_string(const char * bytes, int nlen);
	static std::string format_string_to_bytes(const char * str, int slen);

	static std::string base64_encode(const unsigned char * str,int bytes);//±àÂë
	static std::string base64_decode(const char *str,int length);//½âÂë

private:
	
};

#endif