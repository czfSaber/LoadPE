#pragma once
#include <windows.h>
#include <strsafe.h>

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
	//硬盘拷贝到内存
	BOOL FileBuffCopyInImageBuff();
	//内存拷贝到硬盘
	BOOL ImageBuffToFileBuff();
	//获得节剩余空间的大小
	INT GetRemainingSize(int nIndex = 0);
	//添加节;In:节的名字
	BOOL AddSection(LPCSTR szName,int nSize = 0x1000);
	//重定向头
	void RedirectHelder();
	//保存文件
	BOOL SaveFile(LPCSTR szBuff, LPCWSTR szName);
	//获得硬盘中拉伸后的文件
	LPVOID GetHardDiskFile() {
		return lpImageBuffer;
	}
	//获得最新内存文件
	LPVOID GetNewFile() {
		return lpNewFileBuff;
	}
private:
	HFILE			hFile;
	OFSTRUCT		OpenBuff;
	LARGE_INTEGER	FileSize;
	LPVOID			lpBuffer;		//硬盘中的文件
	LPVOID			lpImageBuffer;	//内存中的文件
	LPVOID			lpNewFileBuff;	//内存中的文件
	DWORD			dLen;
	DWORD			dFileLen;
	PCHAR			pImgBuffer;

public:
	PIMAGE_DOS_HEADER		pImageDosHeader;
	PIMAGE_NT_HEADERS		pImageNTHeader;
	PIMAGE_SECTION_HEADER	pImageSectionHeader;
	PIMAGE_FILE_HEADER		pImageFileHeader;
	PIMAGE_OPTIONAL_HEADER	pImageOperFileHeader;
};