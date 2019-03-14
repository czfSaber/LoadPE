#pragma once
#include <windows.h>
#include <strsafe.h>
#include <vector>

class CLoaderPE
{
public:
	CLoaderPE();
	CLoaderPE(LPCSTR lpFileName);
	~CLoaderPE();
	//获得dos头
	PIMAGE_DOS_HEADER GetDosHeader();
	//是否是PE头或者PE文件是否损坏
	BOOL IsPeFile();
	//获得NT头
	PIMAGE_NT_HEADERS GetNtHeader();
	//获得PE头
	PIMAGE_FILE_HEADER GetPeHeader();
	//获得可选PE头
	PIMAGE_OPTIONAL_HEADER GetOperHeader();
	//获得数据目录
	PIMAGE_DATA_DIRECTORY GetDataDir();
	//获取单个节表;nIndex : 第几个节表
	PIMAGE_SECTION_HEADER GetSectionHeader(int nIndex = 0);
private:
	HFILE			hFile;
	OFSTRUCT		OpenBuff;
	LARGE_INTEGER	FileSize;
	LPVOID			lpBuffer;
	DWORD			dLen;
	DWORD			dFileLen;
	PCHAR			pImgBuffer;
};