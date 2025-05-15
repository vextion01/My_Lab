//Use to query all process and thread from a computer.all process and thread from a computer.


#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>


static void enumProcess() {
    HANDLE hSnapshot;
    HANDLE hThreadSnap;
    PROCESSENTRY32 pe = { 0 }; //Define the struct of Process
    THREADENTRY32 te = { 0 }; //Define the struct of Thread

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); // Create snapshot of Processes
    pe.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnapshot, &pe)) {
        do {
            wprintf(L"Name of Executable: %ws : PID: %6u \n", pe.szExeFile, pe.th32ProcessID);
            hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0); // Create snapshot of thread
            te.dwSize = sizeof(THREADENTRY32);
            if (Thread32First(hThreadSnap, &te)) {
                do {
                    if (te.th32OwnerProcessID == pe.th32ProcessID) { //Compare the process id of the owner of the thread and the process id now.
                        wprintf(L"    :- TID: %6u\n", te.th32ThreadID);
                    }
                } while (Thread32Next(hThreadSnap, &te));
            }
            CloseHandle(hThreadSnap);
        } while (Process32Next(hSnapshot, &pe));
    }
    else {
        printf("Cant enumerate processes\n");
    }

    CloseHandle(hSnapshot);
}

int main() {
    enumProcess();
    return 0;
}