#pragma once
#include <windows.h>
#include <strsafe.h>
#include <map>
using namespace std;

/************************************************************************/
/*添加节：先看看文件头中有没有添加节表的空间，
	如果没有把PE头以及以下的头全部头上移到dos头之后
	要保证节表后面有两个节表的空间也就是80个字节。	
*/
/************************************************************************/

class CLoaderPE
{
private:
	void SaveSectionName();
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
	//获取单个节表;nIndex : 第几个节表
	PIMAGE_SECTION_HEADER GetSectionHeader(int nIndex = 0);
	//硬盘拷贝到内存
	BOOL FileBuffCopyInImageBuff();
	//内存拷贝到硬盘
	BOOL ImageBuffToFileBuff();
	//获得节剩余空间的大小
	INT GetRemainingSize(int nIndex = 0);
	//添加节;In:节的名字
	BOOL AddSection(LPCSTR szName, SIZE_T nSize = 0x1000);
	BOOL AddSectionForStretch(LPCSTR szName, SIZE_T nSize = 0x1000);
	//重定向头
	void RedirectHeader();
	//保存文件
	BOOL SaveFile(LPCSTR szBuff,INT nBufSize, LPCSTR szName);
	// 要申请内存的指针，申请大小，需要扩展的申请大小
	LPVOID rMalloc(LPVOID ptr, INT nOldSize,INT nNewSize);
	//判断节表名是否重复
	BOOL IsSectionName(BYTE* bName);
	//获得文件头空白大小
	INT GetFileHeaderBlankSize();
	//把文件头移到DOS头后边
	VOID MoveHeaderForDOS();
	//扩大最后一个节
	VOID ExpandFinalSection(INT nSize = 0x1000);
/*
	功能:虚拟内存相对地址和文件偏移的转换
	参数：stRVA：    虚拟内存相对偏移地址
		  lpFileBuf: 文件起始地址
	返回：转换后的文件偏移地址
*/
	DWORD RVAToOffset(DWORD stRVA, PVOID lpFileBuf);
/*
	功能：文件偏移地址和虚拟地址的转换
	参数：stOffset：文件偏移地址
		  lpFileBuf:虚拟内存起始地址
	返回：转换后的虚拟地址
*/
	DWORD OffsetToRVA(DWORD stOffset, PVOID lpFileBuf);
public:
	LPVOID				lpBuffer;		//硬盘中的文件
	LPVOID				lpImageBuffer;	//内存中的文件
	LPVOID				lpNewFileBuff;	//内存中的文件
	INT					nNewFileSize;
private:
	HFILE				hFile;
	OFSTRUCT			OpenBuff;
	LARGE_INTEGER		FileSize;
	DWORD				dLen;
	DWORD				dFileLen;
	map<BYTE*, BOOL>	mSectionName;
public:
	PIMAGE_DOS_HEADER		pImageDosHeader;
	PIMAGE_NT_HEADERS		pImageNTHeader;
	PIMAGE_SECTION_HEADER	pImageSectionHeader;
	PIMAGE_FILE_HEADER		pImageFileHeader;
	PIMAGE_OPTIONAL_HEADER	pImageOperFileHeader;
};

enum ETable
{
	ExportTable			= 0,	//导出表
	ImportTable			= 1,	//导入表
	Resource			= 2,	//资源
	Abnormal			= 3,	//异常
	Certificate			= 4,	//安全证书
	ResetTable			= 5,	//重定位表
	DebugInformation	= 6,	//调试信息
	Copyright			= 7,	//版权所有
	GlobalPointer		= 8,	//全局指针
	TLSTable			= 9,	//TLS表
	LoadConfig			= 10,	//加载配置
	BindImport			= 11,	//绑定导入
	IATTable			= 12,	//IAT表
	DelayedImport		= 13,	//延迟导入
	COM					= 14,
	Reserved			= 15	//保留。
};