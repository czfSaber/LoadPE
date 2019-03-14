#include "LoaderPE.h"

CLoaderPE::CLoaderPE()
{
	lpBuffer = NULL;
	hFile = NULL;
	pImgBuffer = NULL;
	dLen = 0;
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
	return (PIMAGE_NT_HEADERS)((DWORD)lpBuffer+GetDosHeader()->e_lfanew);
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
	return (PIMAGE_SECTION_HEADER)((DWORD)(&GetOperHeader()->Magic) + GetPeHeader()->SizeOfOptionalHeader)+ nIndex;
}
