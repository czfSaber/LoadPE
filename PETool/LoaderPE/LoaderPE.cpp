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
	if (nIndex < 0)
	{
		nIndex = 0;
	}else if (nIndex >= GetPeHeader()->NumberOfSections)
	{
		nIndex = GetPeHeader()->NumberOfSections;
	}
	return (PIMAGE_SECTION_HEADER)((CHAR*)&GetOperHeader()->Magic + GetPeHeader()->SizeOfOptionalHeader) + nIndex;
}

PIMAGE_EXPORT_DIRECTORY CLoaderPE::GetExportDir()
{
	if (GetOperHeader()->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
	{
		MessageBox(NULL, TEXT("没用导出函数"), TEXT("warning"), MB_OK);
		exit(0);
	}
	return (PIMAGE_EXPORT_DIRECTORY)((DWORD)lpBuffer + RVAToOffset(GetOperHeader()->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, lpBuffer));
}

PIMAGE_BASE_RELOCATION CLoaderPE::GetBaseReloc(INT nIndex)
{
	DWORD bak = RVAToOffset(GetOperHeader()->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, lpBuffer);
	PDWORD pIndex = (PDWORD)((DWORD)lpBuffer +  RVAToOffset(GetOperHeader()->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, lpBuffer));
	if (*pIndex == 0 && *(pIndex + 1) == 0)
	{
		return NULL;
	}
	nIndex = (nIndex < 0 ? 0 : nIndex);
	for (int i = 0; i < nIndex; ++i)
	{
		pIndex = (PDWORD)(((DWORD)pIndex) + *(pIndex + 1));
		if (*pIndex == 0 && *(pIndex + 1) == 0)
		{
			break;
		}
	}

	return (PIMAGE_BASE_RELOCATION)pIndex;
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

INT CLoaderPE::GetSectionNullSize(int nIndex)
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

VOID CLoaderPE::PrintExportDir()
{
	CHAR* FunctionName;

	printf("%s\n", (DWORD)lpBuffer + RVAToOffset(GetExportDir()->Name,lpBuffer));

	DWORD dNameOrdinal = RVAToOffset(GetExportDir()->AddressOfNameOrdinals, lpBuffer);
	WORD* pNameOrdinal = (WORD*)((DWORD)lpBuffer + dNameOrdinal);
	DWORD dFuncs = RVAToOffset(GetExportDir()->AddressOfFunctions, lpBuffer);
	DWORD* pFuncs = (DWORD*)((DWORD)lpBuffer + dFuncs);

	INT Num = GetExportDir()->NumberOfFunctions;
	for (int i = 0; i < Num; ++i)
	{
		int j = 0;
		//循环地址id在序号表中的位置
		for (j; j < Num; ++j)
		{
			if (*(pNameOrdinal+j) == i)
			{
				break;
			}
		}

		DWORD dName = RVAToOffset(GetExportDir()->AddressOfNames + (j * 4), lpBuffer);
		DWORD* RVANames = (DWORD*)((DWORD)lpBuffer + dName);
		DWORD  FOANames = RVAToOffset(*(DWORD*)RVANames, lpBuffer);
		FunctionName = (CHAR*)lpBuffer + FOANames;

		INT nNameOrdinal = *pNameOrdinal + i;
		printf("%d\t0x%08x\t%s\n", nNameOrdinal, *(pFuncs + (nNameOrdinal - GetExportDir()->Base)), FunctionName);
	}
}

DWORD CLoaderPE::GetFuncAddresForName(LPCSTR szFuncName)
{
	for (int i = 0; i < GetExportDir()->NumberOfNames; ++i)
	{
		DWORD dName = RVAToOffset(GetExportDir()->AddressOfNames + (i * 4), lpBuffer);
		DWORD* RVANames = (DWORD*)((DWORD)lpBuffer + dName);
		DWORD  FOANames = RVAToOffset(*(DWORD*)RVANames, lpBuffer);
		CHAR* FunctionName = (CHAR*)lpBuffer + FOANames;
		if (strcmp(FunctionName,szFuncName) == 0)
		{
			DWORD dNameOrdinal = RVAToOffset(GetExportDir()->AddressOfNameOrdinals, lpBuffer);
			WORD* pNameOrdinal = (WORD*)((DWORD)lpBuffer + dNameOrdinal);
			DWORD dFuncs = RVAToOffset(GetExportDir()->AddressOfFunctions, lpBuffer);
			DWORD* pFuncs = (DWORD*)((DWORD)lpBuffer + dFuncs);
			return *(pFuncs + (*pNameOrdinal + i));
		}
	}
	return -1;
}

DWORD CLoaderPE::GetFuncAddresForNumber(INT nNum)
{
	DWORD dNameOrdinal = RVAToOffset(GetExportDir()->AddressOfNameOrdinals, lpBuffer);
	WORD* pNameOrdinal = (WORD*)((DWORD)lpBuffer + dNameOrdinal);
	DWORD dFuncs = RVAToOffset(GetExportDir()->AddressOfFunctions, lpBuffer);
	DWORD* pFuncs = (DWORD*)((DWORD)lpBuffer + dFuncs);
	INT nNameOrdinal = *pNameOrdinal + nNum - 1;	//数组是从0下标开始的，所以这里减一
	return *(pFuncs + (nNameOrdinal - GetExportDir()->Base));
}

VOID CLoaderPE::PrintBaseRrloc()
{
	INT nIndexTab = 0;	//记录表的个数
	PBaseAddr pBase = (PBaseAddr)((DWORD)GetBaseReloc() + 8);
	while (GetBaseReloc(nIndexTab)->VirtualAddress)
	{
		printf("RVA基址：%X\n", GetBaseReloc(nIndexTab)->VirtualAddress);
		printf("需要修改的地址：\n");
		PBaseAddr pBase = (PBaseAddr)((DWORD)GetBaseReloc(nIndexTab) + 8);
		DWORD Bak = (GetBaseReloc(nIndexTab)->SizeOfBlock - 8) / 2;
		INT nIndex = 0;
		for (nIndex; nIndex < Bak; ++nIndex)
		{
			if (pBase[nIndex].Flag == 3)
			{
				if (nIndex % 4 == 0 && nIndex != 0)
				{
					printf("\n");
				}
				printf("%X\t", pBase[nIndex].Addr + GetBaseReloc(nIndexTab)->VirtualAddress);
			}
		}
		printf("\n");
		printf("\n");
		nIndexTab += 1;
	}
}

WORD CLoaderPE::GetBaseRelocNum()
{
	INT nNum = 0;
	while (GetBaseReloc(nNum)->VirtualAddress && GetBaseReloc(nNum)->SizeOfBlock)
	{
		nNum += 1;
	}
	return nNum ;
}

VOID CLoaderPE::RepairBaseRrloc(DWORD addr)
{
	INT nIndexTab = 0;	//记录表的个数
	while (GetBaseReloc(nIndexTab)->VirtualAddress)
	{
		PBaseAddr pBase = (PBaseAddr)((DWORD)GetBaseReloc(nIndexTab) + 8);
		DWORD Bak = (GetBaseReloc(nIndexTab)->SizeOfBlock - 8) / 2;
		INT nIndex = 0;
		for (nIndex; nIndex < Bak; ++nIndex)
		{
			if (pBase[nIndex].Flag == 3)
			{
				LPVOID OffsetAddr = (PCHAR)lpBuffer + RVAToOffset(pBase[nIndex].Addr + GetBaseReloc(nIndexTab)->VirtualAddress, lpBuffer);
				DWORD bak = *(DWORD*)OffsetAddr;
				*(DWORD*)OffsetAddr += addr;
			}
		}
		nIndexTab += 1;
	}
}

PIMAGE_IMPORT_DESCRIPTOR CLoaderPE::GetImportTable(INT nIndex /*= 0*/)
{
	return (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)lpBuffer + RVAToOffset(GetOperHeader()->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, lpBuffer));
}

VOID CLoaderPE::PrintImportTable()
{
	PIMAGE_IMPORT_DESCRIPTOR pImport = GetImportTable();
	INT nIndex = 0;//导入表的个数
	while ((pImport + nIndex)->Name)
	{
		printf("%s\n", (DWORD)lpBuffer + RVAToOffset((pImport + nIndex)->Name, lpBuffer));
		//名称
		PDWORD pIAT = (PDWORD)(DWORD(lpBuffer) + RVAToOffset((pImport + nIndex)->FirstThunk, lpBuffer));
		//地址
		PDWORD pINT = (PDWORD)(DWORD(lpBuffer) + RVAToOffset((pImport + nIndex)->OriginalFirstThunk, lpBuffer));
		while (*pIAT)
		{
			//判断最高位
			if (IMAGE_SNAP_BY_ORDINAL(*pINT))
			{
				printf("序号：0x%x \t地址：0x%x \n", *pINT & 0xFFFF, *pINT);
			}
			else
			{
				PCHAR pName = (PCHAR)lpBuffer + RVAToOffset(*pINT, lpBuffer) + sizeof(WORD);
				printf("名称：%s \t 地址：0x%x\n", pName,*pINT);
			}
			pIAT += 1;
			pINT += 1;
		}
		nIndex += 1;
	}
}

VOID CLoaderPE::PrintBoundImport()
{
	DWORD BoundBase = (DWORD)lpBuffer + RVAToOffset(GetOperHeader()->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress,lpBuffer);
	PIMAGE_BOUND_IMPORT_DESCRIPTOR pBoundImport = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)BoundBase;
	printf("%s\n", BoundBase + pBoundImport->OffsetModuleName);
}

INT CLoaderPE::GetImportTableNum()
{
	PIMAGE_IMPORT_DESCRIPTOR pImport = GetImportTable();
	INT nIndex = 0;//导入表的个数
	while ((pImport + nIndex)->Name)
	{
		nIndex += 1;
	}
	return nIndex;
}

BOOL CLoaderPE::MoveImpotrTableForSection()
{
	//随机一个节
	INT nIndex = rand() % GetPeHeader()->NumberOfSections;
	INT nSecSize = GetSectionNullSize(nIndex);
	INT nImportSize = GetImportTableNum() * sizeof(IMAGE_IMPORT_DESCRIPTOR);
	//如果该节的空白处小于所有导入表的大小
	if (nSecSize < nImportSize + sizeof(IMAGE_IMPORT_DESCRIPTOR))
	{
		return FALSE;
	}
	//记录下导入表的偏移
	DWORD dImportFOA = GetSectionHeader(nIndex)->PointerToRawData + GetSectionHeader(nIndex)->SizeOfRawData - nSecSize;
	//计入下导入表新的首地址
	DWORD dImportAddr = (DWORD)lpBuffer + dImportFOA;
	//旧导入表的地址
	DWORD dOldImportAddr = DWORD(lpBuffer) + RVAToOffset(GetOperHeader()->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, lpBuffer);
	memmove((PDWORD)dImportAddr, (PDWORD)dOldImportAddr, nImportSize);
	//修改新导出表的RVA
	GetOperHeader()->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = OffsetToRVA(dImportFOA, lpBuffer);
	return TRUE;
}

BOOL CLoaderPE::AddImportTable()
{
	MoveImpotrTableForSection();
	PIMAGE_IMPORT_DESCRIPTOR pImport = GetImportTable();
	INT nImportNum = GetImportTableNum();
	memmove(pImport + nImportNum, pImport + nImportNum - 1, sizeof(IMAGE_IMPORT_DESCRIPTOR));
	return TRUE;
}

BOOL CLoaderPE::InImportTable(LPCSTR szDllName, LPCSTR szFuncName)
{
	if (NULL == szDllName || szFuncName == NULL)
	{
		return FALSE;
	}
	AddImportTable();
	PIMAGE_IMPORT_DESCRIPTOR updateImport = GetImportTable(GetImportTableNum() - 1);
	//随机一个节，把需要修改的信息加进去
	WORD nIndex = rand() % GetPeHeader()->NumberOfSections;
	//或者这个节空白处的大小
	INT nSecSize = GetSectionNullSize(nIndex);
	//记录下空白处开始的偏移
	DWORD dImportFOA = GetSectionHeader(nIndex)->PointerToRawData + GetSectionHeader(nIndex)->SizeOfRawData - nSecSize;

	//计入下要修改的首地址
	PDWORD dImportAddr = (PDWORD)((DWORD)lpBuffer + dImportFOA);
	//修改导入表的名字
	memmove(dImportAddr, szDllName, strlen(szDllName));
	updateImport->Name = OffsetToRVA(dImportFOA, lpBuffer);

	//修改下偏移，记录函数名偏移，函数名在IMAGE_IMPORT_BY_NAME的第二个值，第一个值是WORD类型，所以加它的长度
	dImportFOA += (strlen(szDllName) + sizeof(WORD) + 1);
	dImportAddr = (PDWORD)((DWORD)lpBuffer + dImportFOA);
	memmove(dImportAddr, szFuncName, strlen(szFuncName));

	//记录下名字表的地址
	DWORD NameAddr = (DWORD)dImportAddr;
	//记录下存储指向名称表的地址
	dImportFOA += (strlen(szFuncName) + 1);
	dImportAddr = (PDWORD)((DWORD)lpBuffer + dImportFOA);
	*dImportAddr = NameAddr;
	//让IAT表和INT表都指向函数名的RVA首地址
	updateImport->OriginalFirstThunk = OffsetToRVA(dImportFOA, lpBuffer);
	updateImport->FirstThunk = OffsetToRVA(dImportFOA, lpBuffer);
	return TRUE;
}

DWORD CLoaderPE::RVAToOffset(DWORD dwRva, PVOID pMapping)
{
	WORD nSections = GetNtHeader()->FileHeader.NumberOfSections;
	if (dwRva < GetSectionHeader()->VirtualAddress)
	{
		return dwRva;
	}
	for (int i = 0; i <= nSections; ++i)
	{
		if ((dwRva >= GetSectionHeader(i)->VirtualAddress) && (dwRva <= GetSectionHeader(i)->VirtualAddress + GetSectionHeader(i)->SizeOfRawData))
		{
			return GetSectionHeader(i)->PointerToRawData + (dwRva - GetSectionHeader(i)->VirtualAddress);
		}
	}
	return -1;
}

DWORD CLoaderPE::OffsetToRVA(DWORD dwRva, PVOID pMapping)
{
	WORD nSections = GetNtHeader()->FileHeader.NumberOfSections;
	if (dwRva < GetSectionHeader()->PointerToRawData)
	{
		return dwRva;
	}
	for (int i = 0; i <= nSections; ++i)
	{
		if ((dwRva >= GetSectionHeader(i)->PointerToRawData) && (dwRva <= GetSectionHeader(i)->PointerToRawData + GetSectionHeader(i)->SizeOfRawData))
		{
			return GetSectionHeader(i)->VirtualAddress + (dwRva - GetSectionHeader(i)->PointerToRawData);
		}
	}
	return -1;
}

