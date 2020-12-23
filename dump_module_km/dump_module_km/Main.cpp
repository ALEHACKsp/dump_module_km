#define _CRT_SECURE_NO_WARNINGS
#include  <Windows.h>
#include <stdio.h>
#include <string>

using namespace std;

#include "control.h"





int main()
{
	DWORD PID = NULL;
	char ModuleName[260];

	printf("[+] Digite o PID do processo alvo: ");
	scanf_s("%i", &PID);	

	printf("[+] Digite o nome do modulo1: ");
	scanf("%s", ModuleName);

	system("cls");

	printf("[+] PID: %X\n", PID);
	printf("[+] Module name: %s\n",ModuleName);

	printf("[+] Iniciando processo de dump: \n");
	Sleep(3000);

	hDriver = CreateFileA("\\\\.\\first_driver", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
	if (hDriver == INVALID_HANDLE_VALUE)
	{
		printf("[-] Failed to create file: \n");
		return 0;
	}

	dump_user_module(PID, ModuleName);

	
	system("pause");
}
