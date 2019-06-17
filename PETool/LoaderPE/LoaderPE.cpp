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
	return (PIMAGE_EXPORT_DIRECTORY)((CHAR*)lpBuffer + RVAToOffset(GetOperHeader()->DataDirectory[ExportTable].VirtualAddress, lpBuffer));
}

BOOL CLoaderPE::FileBuffCopyInImageBuff()
{
	lpImageBuffer = malloc(GetOperHeader()->SizeOfImage);
	memset(lpImageBuffer, 0, GetOperHeader()->SizeOfImage);
	//lpImageBuffer = malloc(GetOperHeader()->SizeOfImage*2);
	if (lpImageBuffer == NULL)
	{
		printf("VirtualAlloc failed.\n");
		return FALSE;
	}
	//把文件头拷过去
	memcpy(lpImageBuffer, lpBuffer, GetOperHeader()->SizeOfHeaders);

	for (int i = 0; i < GetPeHeader()->NumberOfSections; ++i)
	{
		if (GetSectionHeader(i)->SizeOfRawData == 0 || GetSectionHeader(i)->PointerToRawData == 0)
		{
			continue;
		}
		//把节的内容拷过去
		memcpy((LPVOID)((CHAR*)lpImageBuffer + GetSectionHeader(i)->VirtualAddress), (LPVOID)((CHAR*)lpBuffer+GetSectionHeader(i)->PointerToRawData),
			GetSectionHeader(i)->SizeOfRawData);
	}

	RedirectHeader();
	
	return TRUE;
}

BOOL CLoaderPE::ImageBuffToFileBuff()
{
	//如果内存中没内容，直接退出
	if (lpImageBuffer == NULL)
	{
		printf("lpImageBuffer is null");
		return FALSE;
	}

	lpNewFileBuff = malloc(nNewFileSize);
	memset(lpNewFileBuff, 0, nNewFileSize);
	if (lpNewFileBuff == NULL)
	{
		printf("malloc failed.\n");
		return FALSE;
	}

	memcpy(lpNewFileBuff, lpImageBuffer, pImageOperFileHeader->SizeOfHeaders);

	for (int i = 0; i < pImageFileHeader->NumberOfSections; ++i)
	{
		memcpy((LPVOID)((CHAR*)lpNewFileBuff + (pImageSectionHeader + i)->PointerToRawData), (LPVOID)((CHAR*)lpImageBuffer + (pImageSectionHeader + i)->VirtualAddress),
			(pImageSectionHeader + i)->Misc.VirtualSize);
	}

	return TRUE; 
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
	DWORD dNames = RVAToOffset(GetExportDir()->AddressOfNames, lpBuffer);
	DWORD dFuncs = RVAToOffset(GetExportDir()->AddressOfFunctions, lpBuffer);
	DWORD dNumbs = RVAToOffset(GetExportDir()->AddressOfNameOrdinals, lpBuffer);
	int nNum = 0;
	while (nNum < GetExportDir()->NumberOfNames)
	{
		if (((CHAR*)lpBuffer + dNames) == 0)
		{
			nNum += 1;
		}
	}
}

DWORD CLoaderPE::RVAToOffset(DWORD stRVA, PVOID lpFileBuf)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)lpFileBuf;
	size_t stPEHeadAddr = (size_t)lpFileBuf + pDos->e_lfanew;
	PIMAGE_NT_HEADERS32 pNT = (PIMAGE_NT_HEADERS32)stPEHeadAddr;
	//区段数  
	DWORD dwSectionCount = pNT->FileHeader.NumberOfSections;
	//内存对齐大小  
	DWORD dwMemoruAil = pNT->OptionalHeader.SectionAlignment;
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNT);
	//距离命中节的起始虚拟地址的偏移值。  
	DWORD  dwDiffer = 0;
	for (DWORD i = 0; i < dwSectionCount; i++)
	{
		//模拟内存对齐机制  
		DWORD dwBlockCount = pSection[i].SizeOfRawData / dwMemoruAil;
		dwBlockCount += pSection[i].SizeOfRawData % dwMemoruAil ? 1 : 0;

		DWORD dwBeginVA = pSection[i].VirtualAddress;
		DWORD dwEndVA = pSection[i].VirtualAddress + dwBlockCount * dwMemoruAil;
		//如果stRVA在某个区段中  
		if (stRVA >= dwBeginVA && stRVA < dwEndVA)
		{
			dwDiffer = stRVA - dwBeginVA;
			return pSection[i].PointerToRawData + dwDiffer;
		}
		else if (stRVA < dwBeginVA)//在文件头中直接返回  
		{
			return stRVA;
		}
	}
	return 0;
}

DWORD CLoaderPE::OffsetToRVA(DWORD stOffset, PVOID lpFileBuf)
{
	//获取DOS头  
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)lpFileBuf;
	//获取PE头  
	//e_lfanew:PE头相对于文件的偏移地址  
	size_t stPEHeadAddr = (size_t)lpFileBuf + pDos->e_lfanew;
	PIMAGE_NT_HEADERS32 pNT = (PIMAGE_NT_HEADERS32)stPEHeadAddr;
	//区段数  
	DWORD dwSectionCount = pNT->FileHeader.NumberOfSections;
	//映像地址  
	DWORD dwImageBase = pNT->OptionalHeader.ImageBase;
	//区段头  
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNT);

	//相对大小  
	DWORD  dwDiffer = 0;
	for (DWORD i = 0; i < dwSectionCount; i++)
	{
		//区段的起始地址和结束地址  
		DWORD dwBeginVA = pSection[i].PointerToRawData;
		DWORD dwEndVA = pSection[i].PointerToRawData + pSection[i].SizeOfRawData;
		//如果文件偏移地址在dwBeginVA和dwEndVA之间  
		if (stOffset >= dwBeginVA && stOffset < dwEndVA)
		{
			//相对大小  
			dwDiffer = stOffset - dwBeginVA;
			//进程的起始地址 + 区段的相对地址 + 相对区段的大小  
			//return dwImageBase + pSection[i].VirtualAddress + dwDiffer;  
			return  pSection[i].VirtualAddress + dwDiffer;
		}
		else if (stOffset < dwBeginVA)    //如果文件偏移地址不在区段中  
		{
			return dwImageBase + stOffset;
		}
	}
	return 0;
}
