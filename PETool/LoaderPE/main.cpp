#include "LoaderPE.h"
#include <iostream>
#include <windows.h>
using namespace std;

int main()
{
	BYTE shellCode[] = {0x6A,0x00,0x68,0x30,0x7B,0xD0,0x00,0x68,0x38,0x7B,0xD0,0x00,0x6A,0x00,0xFF,0x15,0x98,0xB0,0xD0,0x00};
	CLoaderPE *Pe = new  CLoaderPE("K:\\game.exe");
	//printf("%s\n", Pe->GetSectionHeader(2)->Name);
	printf("%d\n", Pe->GetNULLSectionSize(1));
	delete Pe;
	system("pause");
	return 0;
}