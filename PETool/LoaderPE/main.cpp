#include "LoaderPE.h"
#include <iostream>
using namespace std;

int main()
{
	CLoaderPE *Pe = new  CLoaderPE("K:\\game.exe");
	Pe->FileBuffCopyInImageBuff();
	printf("%s\n", Pe->pImageSectionHeader->Name);
	/*printf("节的数量：%d\n", Pe->GetOperHeader()->NumberOfRvaAndSizes);
	printf("ImageBase：%X\n", Pe->GetOperHeader()->ImageBase);
	printf("%s\n", Pe->GetSectionHeader(1)->Name);
	printf("VirtualSize == 0x%X\n", Pe->GetSectionHeader(1)->Misc.VirtualSize);
	printf("0x%X\n", Pe->GetSectionHeader(1)->PointerToRawData);
	printf("0x%X\n", Pe->GetSectionHeader(1)->SizeOfRawData);*/
	delete Pe;
	system("pause");
	return 0;
}