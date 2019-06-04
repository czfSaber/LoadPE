#include "LoaderPE.h"
#include <iostream>
using namespace std;

int main()
{
	CLoaderPE *peTool = new  CLoaderPE("C:\\Users\\Saber\\Desktop\\PiggyStressTestClient.exe");
	peTool->FileBuffCopyInImageBuff();
	//peTool->AddSection(".test");
	peTool->SaveFile((LPCSTR)peTool->GetHardDiskFile(),TEXT("C:\\Users\\Saber\\Desktop\\1.exe"));
	delete peTool;
	system("pause");
	return 0;
}