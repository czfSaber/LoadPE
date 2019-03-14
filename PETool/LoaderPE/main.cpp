#include "LoaderPE.h"
#include <iostream>
using namespace std;

int main()
{
	CLoaderPE *Pe = new  CLoaderPE("F:\\game.exe");
	printf("%d\n", Pe->GetOperHeader()->SizeOfImage);
	delete Pe;
	system("pause");
	return 0;
}