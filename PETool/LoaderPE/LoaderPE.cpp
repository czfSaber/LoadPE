#include "LoaderPE.h"
#include "Encode.h"

CLoaderPE::CLoaderPE()
{
	lpBuffer	= NULL;
	hFile		= NULL;
	dLen		= 0;
	lpImageBuffer = NULL;
	lpNewFileBuff = NULL;

	pImageDosHeader			= NULL;
	pImageNTHeader			= NULL;
	pImageSectionHeader		= NULL;
	pImageFileHeader		= NULL;
	pImageOperFileHeader	= NULL;
	mSectionName.clear();
}

CLoaderPE::CLoaderPE(LPCSTR lpFileName)
{
	CLoaderPE();
	if ((hFile = OpenFile(lpFileName, &OpenBuff, OF_READWRITE)) == HFILE_ERROR)
	{
		TCHAR szError[MAX_PATH] = { 0 };
		StringCchPrintf(szError, MAX_PATH, TEXT("OpenFile is Error,Error Id: %d"), GetLastError());
		MessageBox(NULL, szError, TEXT("Error"), MB_OK);
		return;
	}
	SetFilePointer((HANDLE)hFile, NULL, NULL, FILE_BEGIN);

	dFileLen = GetFileSize((HANDLE)hFile, &dLen);

	lpBuffer = malloc(dFileLen);
	if (!ReadFile((HANDLE)hFile, lpBuffer, dFileLen, &dLen, NULL))
	{
		TCHAR szError[MAX_PATH] = { 0 };
		StringCchPrintf(szError, MAX_PATH, TEXT("ReadFile is Error,Error Id: %d"), GetLastError());
		MessageBox(NULL, szError, TEXT("Error"), MB_OK);
		return;
	}
	if (dFileLen != dLen)
	{
		TCHAR szError[MAX_PATH] = { 0 };
		StringCchPrintf(szError, MAX_PATH, TEXT("ReadFile is Error,Error Id: %d"), GetLastError());
		MessageBox(NULL, szError, TEXT("Error"), MB_OK);
		return;
	}
	nNewFileSize = dFileLen;
	CloseHandle((HANDLE)hFile);
}

void CLoaderPE::SaveSectionName()
{
	for (int i = 0; i < GetPeHeader()->NumberOfSections; ++i)
	{
		mSectionName.insert(pair<BYTE*, BOOL>(GetSectionHeader(i)->Name,TRUE));
	}
}

CLoaderPE::~CLoaderPE()
{
	hFile = NULL;
	if (lpBuffer != NULL)
	{
		free(lpBuffer);
		lpBuffer = NULL;
	}

	pImageDosHeader = NULL;
	pImageNTHeader = NULL;
	pImageSectionHeader = NULL;
	pImageFileHeader = NULL;
	pImageOperFileHeader = NULL;
}

PIMAGE_DOS_HEADER CLoaderPE::GetDosHeader()
{
	return (PIMAGE_DOS_HEADER)lpBuffer;
}

BOOL CLoaderPE::IsPeFile()
{
	if (GetNtHeader()->Signature != 0x4550)
	{
		return FALSE;
	}
	return TRUE;
}

PIMAGE_NT_HEADERS CLoaderPE::GetNtHeader()
{
	return (PIMAGE_NT_HEADERS)((CHAR*)lpBuffer + GetDosHeader()->e_lfanew);
}

PIMAGE_FILE_HEADER CLoaderPE::GetPeHeader()
{
	
	return &GetNtHeader()->FileHeader;
}

PIMAGE_OPTIONAL_HEADER CLoaderPE::GetOperHeader()
{
	return &GetNtHeader()->OptionalHeader;
}

PIMAGE_SECTION_HEADER CLoaderPE::GetSectionHeader(int nIndex)
{
	return (PIMAGE_SECTION_HEADER)((CHAR*)&GetOperHeader()->Magic + GetPeHeader()->SizeOfOptionalHeader) + nIndex;
}

PIMAGE_EXPORT_DIRECTORY CLoaderPE::GetExportDir()
{
	DWORD dVirAddrs = GetOperHeader()->DataDirectory[ExportTable].VirtualAddress;
	DWORD bak = RVAToOffset(dVirAddrs, lpBuffer);
	return (PIMAGE_EXPORT_DIRECTORY)((DWORD)lpBuffer + RVAToOffset(GetOperHeader()->DataDirectory[ExportTable].VirtualAddress, lpBuffer));
}

INT CLoaderPE::GetRemainingSize(int nIndex)
{
	int nNum = 0;
	//因为指针是从0开始计算的，所以这里要减一个
	for (int i = GetSectionHeader(nIndex)->PointerToRawData + GetSectionHeader(nIndex)->SizeOfRawData - 1; i > GetSectionHeader(nIndex)->PointerToRawData; --i)
	{
		if (*((CHAR*)lpBuffer + i) == 0)
		{
			nNum++;
		}
		else
		{
			return nNum;
		}
	}
	return nNum;
}

BOOL CLoaderPE::AddSection(LPCSTR szName, SIZE_T nSize)
{
	//先把节名字保存下来。
	SaveSectionName();
	//然后判断有没有重复的节名
	if (IsSectionName((BYTE*)szName))
	{
		MessageBox(NULL, TEXT("Error"), TEXT("SectionName is Repetition"), MB_OK);
		return FALSE;
	}
	lpBuffer = rMalloc(lpBuffer, dFileLen,nSize);
	//节的总数。
	int NumberSection = GetPeHeader()->NumberOfSections;
	//将最后一个节表复制到它下一个位置
	memcpy(GetSectionHeader(NumberSection), GetSectionHeader(NumberSection - 1), sizeof(IMAGE_SECTION_HEADER));
	//修改节表的总数
	GetPeHeader()->NumberOfSections += 1;
	//修改拉伸后的大小
	GetOperHeader()->SizeOfImage += nSize;
	//修改节名字
	strcpy_s((CHAR*)GetSectionHeader(NumberSection)->Name, IMAGE_SIZEOF_SHORT_NAME, szName);
	GetSectionHeader(NumberSection)->Misc.VirtualSize = nSize;
	GetSectionHeader(NumberSection)->SizeOfRawData = nSize;
	//取整
	int nVirSize = GetSectionHeader(NumberSection - 1)->Misc.VirtualSize / 0x1000;
	GetSectionHeader(NumberSection)->VirtualAddress += ((nVirSize + 1) * 0x1000);
	GetSectionHeader(NumberSection)->PointerToRawData += GetSectionHeader(NumberSection - 1)->SizeOfRawData;
	return TRUE;
}

BOOL CLoaderPE::AddSectionForStretch(LPCSTR szName, SIZE_T nSize /*= 0x1000*/)
{
	//先把节名字保存下来。
	SaveSectionName();
	//然后判断有没有重复的节名
	if (IsSectionName((BYTE*)szName))
	{
		MessageBox(NULL, TEXT("Error"), TEXT("SectionName is Repetition"), MB_OK);
		return FALSE;
	}
	lpImageBuffer = rMalloc(lpImageBuffer, dFileLen, nSize);
	RedirectHeader();
	//节的总数。
	int NumberSection = pImageFileHeader->NumberOfSections;
	//将最后一个节表复制到它下一个位置
	memcpy(pImageSectionHeader + NumberSection, pImageSectionHeader + NumberSection - 1, sizeof(IMAGE_SECTION_HEADER));
	//修改节表的总数
	pImageFileHeader->NumberOfSections += 1;
	//修改拉伸后的大小
	pImageOperFileHeader->SizeOfImage += nSize;
	//修改节名字
	strcpy_s((CHAR*)(pImageSectionHeader + NumberSection)->Name, IMAGE_SIZEOF_SHORT_NAME, szName);
	(pImageSectionHeader + NumberSection)->Misc.VirtualSize = nSize;
	(pImageSectionHeader + NumberSection)->SizeOfRawData = nSize;
	//取整
	int nVirSize = (pImageSectionHeader + NumberSection - 1)->Misc.VirtualSize / 0x1000;
	(pImageSectionHeader + NumberSection)->VirtualAddress += ((nVirSize + 1) * 0x1000);
	(pImageSectionHeader + NumberSection)->PointerToRawData += (pImageSectionHeader + NumberSection - 1)->SizeOfRawData;
	return TRUE;
}

void CLoaderPE::RedirectHeader()
{
	pImageDosHeader = (PIMAGE_DOS_HEADER)lpImageBuffer;
	pImageNTHeader = (PIMAGE_NT_HEADERS)((CHAR*)lpImageBuffer + pImageDosHeader->e_lfanew);
	pImageFileHeader = &pImageNTHeader->FileHeader;
	pImageOperFileHeader = &pImageNTHeader->OptionalHeader;
	pImageSectionHeader = (PIMAGE_SECTION_HEADER)((CHAR*)&pImageOperFileHeader->Magic + pImageFileHeader->SizeOfOptionalHeader);
}

BOOL CLoaderPE::SaveFile(LPCSTR szBuff,INT nBufSize, LPCSTR szName)
{
#ifdef UNICODE
	hFile = (HFILE)CreateFile(Encode::ctowc(szName), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
#else
	hFile = (HFILE)CreateFile(szName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
#endif // !UNICODE

	if ((HANDLE)hFile == INVALID_HANDLE_VALUE)
	{
		LPTSTR buf;
		FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_MAX_WIDTH_MASK, NULL, GetLastError(),
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&buf, 0, NULL);
		MessageBox(NULL, buf, TEXT("FileError"), MB_OK);
		return FALSE;
	}
	if (FALSE == WriteFile((HANDLE)hFile, szBuff, nBufSize, NULL, NULL))
	{
		TCHAR szError[MAX_PATH] = { 0 };
		StringCchPrintf(szError, MAX_PATH, TEXT("WriteFile is Error,Error Id: %d"), GetLastError());
		MessageBox(NULL, szError, TEXT("Error"), MB_OK);
	}
	if (FALSE == FlushFileBuffers((HANDLE)hFile))
	{
		TCHAR szError[MAX_PATH] = { 0 };
		StringCchPrintf(szError, MAX_PATH, TEXT("FlushFileBuffers is Error,Error Id: %d"), GetLastError());
		MessageBox(NULL, szError, TEXT("Error"), MB_OK);
	}
	CloseHandle((HANDLE)hFile);
	return TRUE;
}

LPVOID CLoaderPE::rMalloc(LPVOID ptr, INT nOldSize,INT nAddSize)
{
	nNewFileSize = (nAddSize += nOldSize);
	//如果ptr等于空，说明是分配内存
	if (ptr == NULL)
	{
		ptr = malloc(nOldSize);
		return ptr;
	}
	//否则是要修改原有内存的大小
	LPVOID lpNewBuff = malloc(nAddSize);
	memset(lpNewBuff, 0, nAddSize);
	memcpy(lpNewBuff, ptr, nOldSize);
	free(ptr);
	ptr = NULL;
	return lpNewBuff;
}
//查看map中是否有这个key
BOOL CLoaderPE::IsSectionName(BYTE* bName)
{
	return mSectionName.count(bName);
}

INT CLoaderPE::GetFileHeaderBlankSize()
{
	return (CHAR*)lpBuffer + GetOperHeader()->SizeOfHeaders - (CHAR*)GetSectionHeader(GetPeHeader()->NumberOfSections);
}

VOID CLoaderPE::MoveHeaderForDOS()
{
	memmove((CHAR*)lpBuffer + sizeof(IMAGE_DOS_HEADER), (CHAR*)lpBuffer + GetDosHeader()->e_lfanew, sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_SECTION_HEADER)*GetPeHeader()->NumberOfSections);
	GetDosHeader()->e_lfanew = sizeof(IMAGE_DOS_HEADER);
}

VOID CLoaderPE::ExpandFinalSection(INT nSize)
{
	lpBuffer = rMalloc(lpBuffer, nNewFileSize, nSize);
	int NumberSection = GetPeHeader()->NumberOfSections - 1;
	GetSectionHeader(NumberSection)->Misc.VirtualSize += nSize;
	GetSectionHeader(NumberSection)->SizeOfRawData += nSize;
	GetOperHeader()->SizeOfImage += nSize;
}

VOID CLoaderPE::PringExportDir()
{
	CHAR* FunctionName;

	printf("%s\n", (DWORD)lpBuffer + RVAToOffset(GetExportDir()->Name,lpBuffer));

	DWORD dNames = RVAToOffset(GetExportDir()->AddressOfNames, lpBuffer);
	DWORD dFuncs = RVAToOffset(GetExportDir()->AddressOfFunctions, lpBuffer);
	DWORD dNumbs = RVAToOffset(GetExportDir()->AddressOfNameOrdinals, lpBuffer);

	PULONG RVANames = (PULONG)((DWORD)lpBuffer + dNames);

	DWORD  FOANames = RVAToOffset(*(DWORD*)(RVANames), lpBuffer);
	FunctionName = (CHAR*)lpBuffer + FOANames;
	printf("%s\n", FunctionName);
	/*for (int i = 0; i < GetExportDir()->NumberOfNames; ++i)
	{
	}*/
}

DWORD CLoaderPE::RVAToOffset(DWORD dwRva, PVOID pMapping)
{
	WORD nSections = GetNtHeader()->FileHeader.NumberOfSections;
	for (int i = 0; i < nSections; ++i)
	{
		if ((dwRva >= GetSectionHeader(i)->VirtualAddress) && (dwRva <= GetSectionHeader(i)->VirtualAddress + GetSectionHeader(i)->SizeOfRawData))
		{
			return GetSectionHeader(i)->PointerToRawData + (dwRva - GetSectionHeader(i)->VirtualAddress);
		}
	}
	return -1;
}