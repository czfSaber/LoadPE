#include "LoaderPE.h"

CLoaderPE::CLoaderPE()
{
	lpBuffer	= NULL;
	hFile		= NULL;
	pImgBuffer	= NULL;
	dLen		= 0;

	pImageDosHeader			= NULL;
	pImageNTHeader			= NULL;
	pImageSectionHeader		= NULL;
}

CLoaderPE::CLoaderPE(LPCSTR lpFileName)
{
	hFile = OpenFile(lpFileName, &OpenBuff, OF_READWRITE);
	if (hFile == HFILE_ERROR)
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
}

CLoaderPE::~CLoaderPE()
{
	CloseHandle((HANDLE)hFile);
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

VOID CLoaderPE::FileBuffCopyInImageBuff()
{
	lpImageBuffer = VirtualAlloc(NULL, GetOperHeader()->SizeOfImage, MEM_COMMIT, PAGE_READWRITE);
	if (lpImageBuffer == NULL)
	{
		printf(TEXT("VirtualAlloc failed.\n"));
		return ;
	}
	//把文件头拷过去
	memcpy(lpImageBuffer, lpBuffer, GetOperHeader()->SizeOfHeaders);

	for (int i = 0; i < GetPeHeader()->NumberOfSections; ++i)
	{
		if (GetSectionHeader(i)->SizeOfRawData == 0 || GetSectionHeader(i)->PointerToRawData == 0)
		{
			continue;
		}
		CHAR* cDemo = (CHAR*)lpImageBuffer + GetSectionHeader(i)->VirtualAddress;
		CHAR* cDemo1 = (CHAR*)lpBuffer + GetSectionHeader(i)->PointerToRawData;
		//把节的内容拷过去
		memcpy((LPVOID)((CHAR)lpImageBuffer + GetSectionHeader(i)->VirtualAddress), (LPVOID)((CHAR)lpBuffer+GetSectionHeader(i)->PointerToRawData), 
			GetSectionHeader(i)->SizeOfRawData);
	}
	//重定向新的头
	pImageDosHeader = (PIMAGE_DOS_HEADER)lpImageBuffer;
	pImageNTHeader = (PIMAGE_NT_HEADERS)lpImageBuffer + pImageDosHeader->e_lfanew;
	pImageSectionHeader = (PIMAGE_SECTION_HEADER)lpImageBuffer + sizeof(IMAGE_NT_HEADERS);
}

