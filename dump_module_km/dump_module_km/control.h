#pragma once

HANDLE hDriver;

#define IO_READ_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0701, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define IO_GETMODULEBASE_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0703, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

//Init Structs//
typedef struct _KERNEL_READ_REQUEST
{
    ULONG ProcessId;
    DWORD_PTR  Address;
    PVOID Response;
    SIZE_T  Size;
} KERNEL_READ_REQUEST, * PKERNEL_READ_REQUEST;

typedef struct _KERNEL_GETMODULEBASE_REQUEST
{
	ULONG ProcessId;
	WCHAR name[260];
	DWORD_PTR BaseAddress;
	DWORD Size;
} KERNEL_GETMODULEBASE_REQUEST, * PKERNEL_GETMODULEBASE_REQUEST;

//End of structs//

template <typename type>
type ReadVirtualMemory1(ULONG ProcessId, DWORD_PTR ReadAddress, SIZE_T Size)
{
    if (hDriver == INVALID_HANDLE_VALUE)
        return (type)false;   

    KERNEL_READ_REQUEST ReadRequest;

    ReadRequest.ProcessId = ProcessId;
    ReadRequest.Address = ReadAddress;    
    ReadRequest.Size = Size;
   

    if (DeviceIoControl(hDriver, IO_READ_REQUEST, &ReadRequest, sizeof(ReadRequest), &ReadRequest, sizeof(ReadRequest), 0, 0))       
        return (type)ReadRequest.Response;
    else        
        return (type)false;    

}

bool ModuleBaseInfo(ULONG ProcessId, const std::string& module_name, PDWORD_PTR BaseAddress, PDWORD Size)
{
	if (hDriver == INVALID_HANDLE_VALUE)
		return 0;

	KERNEL_GETMODULEBASE_REQUEST  GetModuleBaseRequest;
	GetModuleBaseRequest.ProcessId = ProcessId;

	std::wstring wstr{ std::wstring(module_name.begin(), module_name.end()) };
	memset(GetModuleBaseRequest.name, 0, sizeof(WCHAR) * 260);
	wcscpy(GetModuleBaseRequest.name, wstr.c_str());

	if (DeviceIoControl(hDriver, IO_GETMODULEBASE_REQUEST, &GetModuleBaseRequest, sizeof(GetModuleBaseRequest), &GetModuleBaseRequest, sizeof(GetModuleBaseRequest), 0, 0))
	{
		*BaseAddress = GetModuleBaseRequest.BaseAddress;
		*Size = GetModuleBaseRequest.Size;
		return true;
	}
	else
		return false;

}

void dump_user_module(DWORD process_id, const char* module_name)
{
    DWORD_PTR BaseAddress = NULL;
    DWORD SizeOfModule = NULL;

    printf("[+] Pegando info do modulo: \n");
    if (!ModuleBaseInfo(process_id, module_name, &BaseAddress, &SizeOfModule))
    {
        printf("[-] Falha ao adquirir info do modulo\n");
        return;
    }

    if (BaseAddress == NULL && SizeOfModule == NULL)
    {
        printf("[-] Falha ao recolher endereços: \n");
        return;
    }

    printf("[+] ModuleBase: %X\n", BaseAddress);
    printf("[+] SizeOfModule1: %X\n", SizeOfModule);
  
    auto buf = new char[SizeOfModule];
    if (!buf)
        return;
    
    printf("[+] Size Alocado em: %p\n",buf);
    printf("[+] Tentando dumpar: aguarde um momento, pode demorar minutos\n");   

    //HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, process_id);
    //SIZE_T bytes_read = 0;
    //ReadProcessMemory(hProcess, (PVOID)BaseAddress, buf, SizeOfModule, &bytes_read);         
    //CloseHandle(hProcess);
    
    for (int i = 0; i < SizeOfModule; i++)
    {
        buf[i] = ReadVirtualMemory1<char>(process_id, BaseAddress+i, 4);       
    }

   /* if (!bytes_read)
    {
        printf("[-] Erro ao ler bytes...\n");
        delete[] buf;
        return;
    }*/
    printf("[+] Dados copiados: Finalizando...\n");
    auto pimage_dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(buf);
    auto pimage_nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(buf + pimage_dos_header->e_lfanew);    
  
    if (pimage_nt_headers->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {   
        auto pimage_section_header = reinterpret_cast<PIMAGE_SECTION_HEADER>(pimage_nt_headers + 1);
        for (WORD i = 0; i < pimage_nt_headers->FileHeader.NumberOfSections; ++i, ++pimage_section_header)
        {
            
            pimage_section_header->PointerToRawData = pimage_section_header->VirtualAddress;
            pimage_section_header->SizeOfRawData = pimage_section_header->Misc.VirtualSize;
        }       
        pimage_nt_headers->OptionalHeader.ImageBase = (DWORD)BaseAddress;
    }

 
    else if (pimage_nt_headers->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        auto pimage_nt_headers32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(pimage_nt_headers);
        auto pimage_section_header = reinterpret_cast<PIMAGE_SECTION_HEADER>(pimage_nt_headers32 + 1);
        for (WORD i = 0; i < pimage_nt_headers32->FileHeader.NumberOfSections; ++i, ++pimage_section_header)
        {
            pimage_section_header->PointerToRawData = pimage_section_header->VirtualAddress;
            pimage_section_header->SizeOfRawData = pimage_section_header->Misc.VirtualSize;
        }      
        pimage_nt_headers32->OptionalHeader.ImageBase = (DWORD)(BaseAddress);
    }
    else
    {
        delete[] buf;
        return;
    }    

    string name = string("dump_") + module_name;
    HANDLE hFile = CreateFileA(name.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);   
   
    if (hFile != INVALID_HANDLE_VALUE)
    { 

        DWORD Ip1, Ip2;
        WriteFile(hFile, buf, (DWORD)SizeOfModule, &Ip1, nullptr);            
        printf("[+] Status: Modulo dumpado com sucesso\n\n ");        
    }
    else
    {
        printf("[+] Erro\n\n ");
    }
    
    CloseHandle(hFile);    
    delete[] buf;
}