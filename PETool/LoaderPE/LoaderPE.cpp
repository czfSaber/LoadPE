#include "LoaderPE.h"

CLoaderPE::CLoaderPE()
{
	lpBuffer	= NULL;
	hFile		= NULL;
	pImgBuffer	= NULL;
	dLen		= 0;
	lpImageBuffer = NULL;
	lpNewFileBuff = NULL;

	pImageDosHeader			= NULL;
	pImageNTHeader			= NULL;
	pImageSectionHeader		= NULL;
	pImageFileHeader		= NULL;
	pImageOperFileHeader	= NULL;
}

CLoaderPE::CLoaderPE(LPCSTR lpFileName)
{
	if (OpenFile(lpFileName, &OpenBuff, OF_READWRITE) == HFILE_ERROR)
	{
		TCHAR szError[MAX_PATH] = { 0 };
		StringCchPrintf(szError, MAX_PATH, TEXT("OpenFile is Error,Error Id: %d"), GetLastError());
		MessageBox(NULL, szError, TEXT("Error"), MB_OK);
		return;
	}
	SetFilePointer(hFile, NULL, NULL, FILE_BEGIN);

	dFileLen = GetFileSize(hFile, &dLen);

	lpBuffer = malloc(dFileLen);
	if (!ReadFile(hFile, lpBuffer, dFileLen, &dLen, NULL))
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
	CloseHandle(hFile);
}

CLoaderPE::~CLoaderPE()
{
	hFile = NULL;
	if (lpBuffer != NULL)
	{
		free(lpBuffer);
		lpBuffer = NULL;
	}

	if (pImgBuffer != NULL)
	{
		free(pImgBuffer);
		pImgBuffer = NULL;
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

PIMAGE_DATA_DIRECTORY CLoaderPE::GetDataDir()
{
	return GetOperHeader()->DataDirectory;
}

PIMAGE_SECTION_HEADER CLoaderPE::GetSectionHeader(int nIndex)
{
	return (PIMAGE_SECTION_HEADER)((CHAR*)&GetOperHeader()->Magic + GetPeHeader()->SizeOfOptionalHeader) + nIndex;
}

LPVOID CLoaderPE::FileBuffCopyInImageBuff()
{
	lpImageBuffer = VirtualAlloc(NULL, GetOperHeader()->SizeOfImage, MEM_COMMIT, PAGE_READWRITE);
	if (lpImageBuffer == NULL)
	{
		printf("VirtualAlloc failed.\n");
		return NULL;
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
	
	RedirectHelder();
	
	return lpImageBuffer;
}

LPVOID CLoaderPE::ImageBuffToFileBuff()
{
	//如果内存中没内容，直接退出
	if (lpImageBuffer == NULL)
	{
		printf("lpImageBuffer is null");
		return NULL;
	}

	lpNewFileBuff = VirtualAlloc(NULL, strlen((CHAR*)lpBuffer), MEM_COMMIT, PAGE_READWRITE);
	if (lpNewFileBuff == NULL)
	{
		printf("VirtualAlloc failed.\n");
		return NULL;
	}

	memcpy(lpNewFileBuff, lpImageBuffer, pImageOperFileHeader->SizeOfHeaders);

	for (int i = 0; i < pImageFileHeader->NumberOfSections; ++i)
	{
		memcpy((LPVOID)((CHAR*)lpNewFileBuff + (pImageSectionHeader + i)->PointerToRawData), (LPVOID)((CHAR*)lpImageBuffer + (pImageSectionHeader + i)->VirtualAddress),
			(pImageSectionHeader + i)->SizeOfRawData);
	}

	return NULL;
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

BOOL CLoaderPE::AddSection(CHAR* szName,int nSize)
{
	realloc(lpImageBuffer, nSize);
	//随便把一个节表复制到总节表的下一个位置
	strcpy_s((CHAR*)pImageSectionHeader + pImageFileHeader->SizeOfOptionalHeader + 1,sizeof(IMAGE_SECTION_HEADER), (CHAR*)pImageSectionHeader + 0);
	PIMAGE_SECTION_HEADER pSectionHeaderBak = pImageSectionHeader + (pImageFileHeader->SizeOfOptionalHeader + 1);
	//修改节的数量
	pImageFileHeader->SizeOfOptionalHeader += 1;
	//修改节表
	strcpy_s((CHAR*)pSectionHeaderBak->Name, IMAGE_SIZEOF_SHORT_NAME, szName);

	return TRUE;
}

void CLoaderPE::RedirectHelder()
{
	pImageDosHeader = (PIMAGE_DOS_HEADER)lpImageBuffer;
	pImageNTHeader = (PIMAGE_NT_HEADERS)((CHAR*)lpImageBuffer + pImageDosHeader->e_lfanew);
	pImageFileHeader = &pImageNTHeader->FileHeader;
	pImageOperFileHeader = &pImageNTHeader->OptionalHeader;
	pImageSectionHeader = (PIMAGE_SECTION_HEADER)((CHAR*)&pImageOperFileHeader->Magic + pImageFileHeader->SizeOfOptionalHeader);
}

BOOL CLoaderPE::SaveFile(TCHAR* szBuff, TCHAR* szName)
{
	hFile = CreateFile(szName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		LPTSTR buf;
		FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_MAX_WIDTH_MASK, NULL, GetLastError(),
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&buf, 0, NULL);
		MessageBox(NULL, (LPCWSTR)buf, TEXT("FileError"), MB_OK);
		return FALSE;
	}
	WriteFile(hFile, lpImageBuffer, strlen((CHAR*)lpImageBuffer + 1), NULL, NULL);
	FlushFileBuffers(hFile);
	CloseHandle(hFile);
	return TRUE;
}
