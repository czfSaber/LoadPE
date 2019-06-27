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
	//获得输出表结构
	PIMAGE_EXPORT_DIRECTORY GetExportDir();
	//获得重定位表
	PIMAGE_BASE_RELOCATION GetBaseReloc(INT nIndex = 0);

	DWORD RVAToOffset(DWORD dwRva, PVOID pMapping);
	DWORD OffsetToRVA(DWORD dwRva, PVOID pMapping);
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
	PIMAGE_SECTION_HEADER GetSectionHeader(int nIndex = 1);
	//硬盘拷贝到内存
	BOOL FileBuffCopyInImageBuff();
	//内存拷贝到硬盘
	BOOL ImageBuffToFileBuff();
	//获得节剩余空间的大小
	INT GetSectionNullSize(int nIndex = 0);
	//添加节;In:节的名字
	BOOL AddSection(LPCSTR szName, SIZE_T nSize = 0x1000);
	//扩展最后一个节
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
	//打印输出表
	VOID PrintExportDir();
	//根据函数名找到函数地址
	DWORD GetFuncAddresForName(LPCSTR szFuncName);
	//根据序号找到函数地址
	DWORD GetFuncAddresForNumber(INT nNum);
	//输出重定位表
	VOID PrintBaseRrloc();
	//获得重定位表的个数
	WORD GetBaseRelocNum();
	//修复重定位表
	VOID RepairBaseRrloc(DWORD addr);
	//获得导入表
	PIMAGE_IMPORT_DESCRIPTOR GetImportTable(INT nIndex = 0);
	//输出导入表
	VOID PrintImportTable();
	//输出绑定导入表
	VOID PrintBoundImport();
	//获得导入表的个数
	INT GetImportTableNum();
	//移动导入表到节; nIndex:第几个节
	BOOL MoveImpotrTableForSection(INT nIndex = 0);
	
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
	//重定向表
	typedef struct BaseRelocAddress
	{
		WORD Addr	: 12;
		WORD Flag  : 4;
	}BaseAddr,*PBaseAddr;

public:
	PIMAGE_DOS_HEADER		pImageDosHeader;
	PIMAGE_NT_HEADERS		pImageNTHeader;
	PIMAGE_SECTION_HEADER	pImageSectionHeader;
	PIMAGE_FILE_HEADER		pImageFileHeader;
	PIMAGE_OPTIONAL_HEADER	pImageOperFileHeader;
};