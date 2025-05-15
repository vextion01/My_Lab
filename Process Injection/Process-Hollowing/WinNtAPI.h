//WinNtAPI.h

/*
hxxps://ntdoc.m417z.com
hxxps://doxygen.reactos.org
hxxps://www.vergiliusproject.com
hxxps://www.geoffchappell.com/
*/

#pragma once

#include <windows.h>
//#include <winternl.h>

#ifndef OPTIONAL
#define OPTIONAL
#endif

#define SEC_COMMIT  0x08000000
#define SEC_RESERVE 0x04000000
#define InitializeObjectAttributes(i, o, a, r, s) { \
    (i)->Length = sizeof(OBJECT_ATTRIBUTES);       \
    (i)->RootDirectory = r;                        \
    (i)->Attributes = a;                           \
    (i)->ObjectName = o;                           \
    (i)->SecurityDescriptor = s;                   \
    (i)->SecurityQualityOfService = NULL;          \
}

//typedef LONG NTSTATUS;

//typedef struct _OBJECT_ATTRIBUTES
//{
//    ULONG Length;
//    PVOID RootDirectory;
//    PUNICODE_STRING ObjectName;
//    ULONG Attributes;
//    PVOID SecurityDescriptor;
//    PVOID SecurityQualityOfService;
//} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  pBuffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef LONG KPRIORITY;

typedef enum _KWAIT_REASON
{
    Executive = 0,
    FreePage = 1,
    PageIn = 2,
    PoolAllocation = 3,
    DelayExecution = 4,
    Suspended = 5,
    UserRequest = 6,
    WrExecutive = 7,
    WrFreePage = 8,
    WrPageIn = 9,
    WrPoolAllocation = 10,
    WrDelayExecution = 11,
    WrSuspended = 12,
    WrUserRequest = 13,
    WrEventPair = 14,
    WrQueue = 15,
    WrLpcReceive = 16,
    WrLpcReply = 17,
    WrVirtualMemory = 18,
    WrPageOut = 19,
    WrRendezvous = 20,
    Spare2 = 21,
    Spare3 = 22,
    Spare4 = 23,
    Spare5 = 24,
    WrCalloutStack = 25,
    WrKernel = 26,
    WrResource = 27,
    WrPushLock = 28,
    WrMutex = 29,
    WrQuantumEnd = 30,
    WrDispatchInt = 31,
    WrPreempted = 32,
    WrYieldExecution = 33,
    WrFastMutex = 34,
    WrGuardedMutex = 35,
    WrRundown = 36,
    MaximumWaitReason = 37
} KWAIT_REASON;

//typedef struct _SYSTEM_THREAD {
//    LARGE_INTEGER KernelTime;
//    LARGE_INTEGER UserTime;
//    LARGE_INTEGER CreateTime;
//    ULONG WaitTime;
//    PVOID StartAddress;
//    CLIENT_ID ClientId;
//    KPRIORITY Priority;
//    LONG BasePriority;
//    ULONG ContextSwitches;
//    ULONG ThreadState;
//    KWAIT_REASON WaitReason;
//} SYSTEM_THREAD, *PSYSTEM_THREAD;

//typedef struct _SYSTEM_PROCESS_INFO {
//    ULONG NextEntryOffset;
//    ULONG NumberOfThreads;
//    LARGE_INTEGER WorkingSetPrivateSize;
//    ULONG HardFaultCount;
//    ULONG Reserved1;
//    ULONG Reserved2;
//    LARGE_INTEGER CreateTime;
//    LARGE_INTEGER UserTime;
//    LARGE_INTEGER KernelTime;
//    UNICODE_STRING ImageName;
//    KPRIORITY BasePriority;
//    HANDLE UniqueProcessId;
//    HANDLE InheritedFromUniqueProcessId;
//    ULONG HandleCount;
//    ULONG SessionId;
//    ULONG_PTR PagefileUsage;
//    ULONG_PTR PeakPagefileUsage;
//    ULONG_PTR WorkingSetSize;
//    ULONG_PTR PeakWorkingSetSize;
//    ULONG_PTR VirtualSize;
//    ULONG_PTR PeakVirtualSize;              
//    SYSTEM_THREAD Threads[1];
//} SYSTEM_PROCESS_INFO, *PSYSTEM_PROCESS_INFO;


typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    SystemProcessorInformation = 1,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemPathInformation = 4,
    SystemProcessInformation = 5,
    SystemCallCountInformation = 6,
    SystemDeviceInformation = 7,
    SystemProcessorPerformanceInformation = 8,
    SystemFlagsInformation = 9,
    SystemCallTimeInformation = 10,
    SystemModuleInformation = 11
} SYSTEM_INFORMATION_CLASS;


typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation = 0,
    ProcessDebugPort = 7,
    ProcessWow64Information = 26,
    ProcessImageFileName = 27,
    ProcessBreakOnTermination = 29
} PROCESSINFOCLASS;

typedef struct _PEB_LDR_DATA {
    BYTE       Reserved1[8];
    PVOID      Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    BYTE           Reserved1[16];
    PVOID          Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef VOID(WINAPI* PPS_POST_PROCESS_INIT_ROUTINE)(VOID);

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    BYTE Reserved4[104];
    PVOID Reserved5[52];
    PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
    BYTE Reserved6[128];
    PVOID Reserved7[1];
    ULONG SessionId;
} PEB, * PPEB;

typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PPEB PebBaseAddress;
    ULONG_PTR AffinityMask;
    KPRIORITY BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;

typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

typedef struct _CLIENT_ID
{
    PVOID UniqueProcess;
    PVOID UniqueThread;
} CLIENT_ID, * PCLIENT_ID;


typedef struct _IO_STATUS_BLOCK
{
    union
    {
        NTSTATUS Status;
        PVOID Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;


typedef HANDLE(WINAPI* W_OpenProcess)(
    DWORD dwDesiredAccess,
    BOOL bInheritHandle,
    DWORD dwProcessId
    );

typedef BOOL(WINAPI* W_VirtualProtectEx)(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flNewProtect,
    PDWORD lpflOldProtect
    );

typedef LPVOID(WINAPI* W_VirtualAllocEx)(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flAllocationType,
    DWORD flProtect
    );

typedef NTSTATUS(NTAPI* N_NtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* UBaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T URegionSize,
    ULONG AllocationType,
    ULONG Protect
    );

typedef BOOL(WINAPI* W_WriteProcessMemory)(
    HANDLE hProcess,
    LPVOID lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T nSize,
    SIZE_T* lpNumberOfBytesWritten
    );

typedef HANDLE(WINAPI* W_CreateRemoteThread)(
    HANDLE hProcess,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    DWORD dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPDWORD lpThreadId
    );

typedef NTSTATUS(NTAPI* N_NtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
    );

typedef NTSTATUS(NTAPI* N_NtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG NumberOfBytesToWrite,
    PULONG NumberOfBytesWritten
    );

typedef NTSTATUS(NTAPI* N_NtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG InformationLength,
    PULONG ResultLength
    );

typedef HANDLE(WINAPI* W_CreateToolhelp32Snapshot)(
    DWORD 	dwFlags,
    DWORD 	th32ProcessID
    );

typedef NTSTATUS(NTAPI* N_NtQueryInformationProcess)(
    HANDLE 	ProcessHandle,
    PROCESSINFOCLASS 	ProcessInformationClass,
    PVOID 	ProcessInformation,
    ULONG 	ProcessInformationLength,
    PULONG 	ReturnLength
    );

typedef NTSTATUS(NTAPI* N_NtOpenThread)(
    PHANDLE 	ThreadHandle,
    ACCESS_MASK 	DesiredAccess,
    POBJECT_ATTRIBUTES 	ObjectAttributes,
    PCLIENT_ID ClientId 	OPTIONAL
    );

typedef NTSTATUS(NTAPI* N_ZwDuplicateObject)(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    ULONG Options
    );

typedef BOOL(WINAPI* W_ReadProcessMemory)(
    HANDLE 	hProcess,
    LPCVOID 	lpBaseAddress,
    LPVOID 	lpBuffer,
    SIZE_T 	nSize,
    SIZE_T* lpNumberOfBytesRead
    );


typedef NTSTATUS(NTAPI* N_NtReadVirtualMemory)(
    HANDLE 	ProcessHandle,
    PVOID 	BaseAddress,
    PVOID 	Buffer,
    SIZE_T 	NumberOfBytesToRead,
    PSIZE_T NumberOfBytesRead 	OPTIONAL
    );

typedef NTSTATUS(NTAPI* N_ZwMapViewOfSection)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    SECTION_INHERIT InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
    );

typedef NTSTATUS(NTAPI* N_RtlCreateUserThread)(
    HANDLE               ProcessHandle,
    PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
    BOOLEAN              CreateSuspended,
    ULONG                StackZeroBits,
    PULONG           StackReserved,
    PULONG           StackCommit,
    PVOID                StartAddress,
    PVOID                StartParameter OPTIONAL,
    PHANDLE             ThreadHandle,
    PCLIENT_ID          ClientID
    );

typedef DWORD(WINAPI* W_QueueUserAPC)(
    PAPCFUNC 	pfnAPC,
    HANDLE 	hThread,
    ULONG_PTR 	dwData
    );

typedef NTSTATUS(NTAPI* N_NtQueueApcThread)(
    HANDLE ThreadHandle,
    PVOID  ApcRoutine,
    PVOID  ApcArgument1,
    PVOID  ApcArgument2,
    PVOID  ApcArgument3
    );

typedef BOOL(WINAPI* W_SetThreadContext)(
    HANDLE 	hThread,
    CONST CONTEXT* lpContext
    );

typedef NTSTATUS(NTAPI* N_NtCreateSection)(
    PHANDLE 	SectionHandle,
    ACCESS_MASK 	DesiredAccess,
    POBJECT_ATTRIBUTES 	ObjectAttributes,
    PLARGE_INTEGER 	MaximumSize,
    ULONG 	SectionPageProtection,
    ULONG 	AllocationAttributes,
    HANDLE 	FileHandle
    );

typedef NTSTATUS(NTAPI* N_NtCreateFile)(
    PHANDLE 	FileHandle,
    ACCESS_MASK 	DesiredAccess,
    POBJECT_ATTRIBUTES 	ObjectAttributes,
    PIO_STATUS_BLOCK 	IoStatusBlock,
    PLARGE_INTEGER 	AllocationSize,
    ULONG 	FileAttributes,
    ULONG 	ShareAccess,
    ULONG 	CreateDisposition,
    ULONG 	CreateOptions,
    PVOID 	EaBuffer,
    ULONG 	EaLength
    );

typedef FARPROC(WINAPI* W_GetProcAddress)(
    HMODULE 	hModule,
    LPCSTR 	lpProcName
    );

typedef NTSTATUS(NTAPI* N_NtCreateTransaction)(
    PHANDLE TransactionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    LPGUID Uow OPTIONAL,
    HANDLE TmHandle OPTIONAL,
    ULONG CreateOptions OPTIONAL,
    ULONG IsolationLevel OPTIONAL,
    ULONG IsolationFlags OPTIONAL,
    PLARGE_INTEGER Timeout OPTIONAL,
    PUNICODE_STRING Description OPTIONAL
    );

typedef NTSTATUS(NTAPI* N_NtUnmapViewOfSection)(
    HANDLE 	ProcessHandle,
    PVOID 	BaseAddress
    );

typedef NTSTATUS(NTAPI* N_NtSuspendThread)(
    HANDLE 	ThreadHandle,
    PULONG 	PreviousSuspendCount
    );

typedef NTSTATUS(NTAPI* N_NtResumeThread)(
    HANDLE 	ThreadHandle,
    PULONG 	SuspendCount
    );

typedef NTSTATUS(NTAPI* N_NtOpenProcess)(
    PHANDLE 	ProcessHandle,
    ACCESS_MASK 	DesiredAccess,
    POBJECT_ATTRIBUTES 	ObjectAttributes,
    PCLIENT_ID 	ClientId
    );

typedef NTSTATUS(NTAPI* N_NtGetContextThread)(
    HANDLE 	ThreadHandle,
    PCONTEXT 	Context
    );

typedef NTSTATUS(NTAPI* N_NtSetContextThread)(
    HANDLE 	ThreadHandle,
    PCONTEXT 	Context
    );
