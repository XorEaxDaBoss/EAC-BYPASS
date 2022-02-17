#include <mutex>
#include <basetsd.h>
#include <winnt.h>
#include <minwindef.h>
#include <libloaderapi.h>
#include "xorstr.hpp"
#include <handleapi.h>
#include <TlHelp32.h>
#include <WinUser.h>
#include <ntstatus.h>
#include <bcrypt.h>

void SaveCPU(int ms)
{
	return std::this_thread::sleep_for(std::chrono::milliseconds(ms));
}

enum E_COMMAND_CODE
{
	ID_NULL = 0,	//

	ID_READ_PROCESS_MEMORY = 5,	// 
	ID_WRITE_PROCESS_MEMORY = 6,	//

	ID_READ_KERNEL_MEMORY = 8,	// 

	ID_GET_PROCESS = 10,	//
	ID_GET_PROCESS_BASE = 11,	//
	ID_GET_PROCESS_MODULE = 12,	//
	ID_GET_UNITY_MODULE = 13, //

	ID_SET_PAGE_PROTECTION = 26,  //

	ID_REMOVE_HOOK = 99,	//

	ID_CONFIRM_DRIVER_LOADED = 100,	//
};

#pragma pack( push, 8 )
typedef struct _MEMORY_STRUCT
{
	UINT_PTR	process_id;
	PVOID		address;
	SIZE_T		size;
	SIZE_T		size_copied;
	PVOID		buffer;
} MEMORY_STRUCT, * PMEMORY_STRUCT;
#pragma pack( pop )

#pragma pack( push, 8 )
typedef struct _MEMORY_STRUCT_PROTECTION
{
	UINT_PTR	process_id;
	PVOID		address;
	SIZE_T		size;
	ULONG		protection;
	ULONG		protection_old;
} MEMORY_STRUCT_PROTECTION, * PMEMORY_STRUCT_PROTECTION;
#pragma pack( pop )


template<typename ... A>
uint64_t call_driver_control(void* control_function, const A ... arguments)
{
	if (!control_function)
		return 0;

	using tFunction = uint64_t(__stdcall*)(A...);
	const auto control = static_cast<tFunction>(control_function);

	return control(arguments ...);
}

void* kernel_control_function()
{
	HMODULE hModule = LoadLibrary(XorStr("win32u.dll"));

	if (!hModule)
		return nullptr;

	return reinterpret_cast<void*>(GetProcAddress(hModule, XorStr("NtUserGetPointerDevice")));
}

uint64_t read_kernel(void* control_function, uint64_t address, void* buffer, std::size_t size)
{
	return call_driver_control(control_function, ID_READ_KERNEL_MEMORY, address, buffer, size);
}


struct HandleDisposer
{
	using pointer = HANDLE;
	void operator()(HANDLE handle) const
	{
		if (handle != NULL || handle != INVALID_HANDLE_VALUE)
		{
			CloseHandle(handle);
		}
	}
};

using unique_handle = std::unique_ptr<HANDLE, HandleDisposer>;

static std::uint32_t GetProcessID(std::string process_name) {
	PROCESSENTRY32 processentry;
	const unique_handle snapshot_handle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));

	if (snapshot_handle.get() == INVALID_HANDLE_VALUE)
		return 0;

	processentry.dwSize = sizeof(MODULEENTRY32);

	while (Process32Next(snapshot_handle.get(), &processentry) == TRUE) {
		if (process_name.compare(processentry.szExeFile) == 0)
			return processentry.th32ProcessID;
	}
	return 0;
}


//int GetProcessThreadNumByID(DWORD dwPID)
//{
//	HANDLE hProcessSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
//	if (hProcessSnap == INVALID_HANDLE_VALUE)
//		return 0;
//
//	PROCESSENTRY32 pe32 = { 0 };
//	pe32.dwSize = sizeof(pe32);
//	BOOL bRet = ::Process32First(hProcessSnap, &pe32);;
//	while (bRet)
//	{
//		if (pe32.th32ProcessID == dwPID)
//		{
//			::CloseHandle(hProcessSnap);
//			return pe32.cntThreads;
//		}
//		bRet = ::Process32Next(hProcessSnap, &pe32);
//	}
//	return 0;
//}
//
//DWORD GetProcessID(LPCSTR lpExeName)
//{
//	DWORD dwRet = 0;
//	DWORD dwThreadCountMax = 0;
//	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
//	PROCESSENTRY32 pe32;
//	pe32.dwSize = sizeof(PROCESSENTRY32);
//	Process32First(hSnapshot, &pe32);
//	do
//	{
//		if (_tcsicmp(pe32.szExeFile, _T(lpExeName)) == 0)
//
//		{
//			DWORD dwTmpThreadCount = GetProcessThreadNumByID(pe32.th32ProcessID);
//
//			if (dwTmpThreadCount > dwThreadCountMax)
//			{
//				dwThreadCountMax = dwTmpThreadCount;
//				dwRet = pe32.th32ProcessID;
//			}
//		}
//	} while (Process32Next(hSnapshot, &pe32));
//	CloseHandle(hSnapshot);
//	return dwRet;
//}
//
//void killProcessByName(const char* filename)
//{
//	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
//	PROCESSENTRY32 pEntry;
//	pEntry.dwSize = sizeof(pEntry);
//	BOOL hRes = Process32First(hSnapShot, &pEntry);
//	while (hRes)
//	{
//		if (strcmp(pEntry.szExeFile, filename) == 0)
//		{
//			HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, 0,
//				(DWORD)pEntry.th32ProcessID);
//			if (hProcess != NULL)
//			{
//				TerminateProcess(hProcess, 9);
//				CloseHandle(hProcess);
//			}
//		}
//		hRes = Process32Next(hSnapShot, &pEntry);
//	}
//	CloseHandle(hSnapShot);
//}

void* m_driver_control;
DWORD PID;
uint64_t baseAddress;
uintptr_t unityModule;
uintptr_t assemblyModule;
uintptr_t game_object_manager;
uintptr_t base_networkable;



template<typename T>
T read(uint64_t address)
{
	T buffer{};

	if (!PID)
		return buffer;

	MEMORY_STRUCT memory_struct = { 0 };
	memory_struct.process_id = PID;
	memory_struct.address = reinterpret_cast<void*>(address);
	memory_struct.size = sizeof(T);
	memory_struct.buffer = &buffer;

	NTSTATUS result
		= (NTSTATUS)(call_driver_control(m_driver_control, ID_READ_PROCESS_MEMORY, &memory_struct));

	if (result != 0)
		return buffer;

	return buffer;
}

template<typename T>
bool write(uint64_t address, T buffer)
{
	MEMORY_STRUCT memory_struct = { 0 };
	memory_struct.process_id = PID;
	memory_struct.address = reinterpret_cast<void*>(address);
	memory_struct.size = sizeof(T);
	memory_struct.buffer = &buffer;

	NTSTATUS result
		= (NTSTATUS)(call_driver_control(m_driver_control, ID_WRITE_PROCESS_MEMORY, &memory_struct));

	if (result != 0)
		return false;

	return true;
}
template<typename T>
std::string read_string(uint64_t address)
{
	char buffer[100];

	if (!PID)
		return buffer;

	MEMORY_STRUCT memory_struct = { 0 };
	memory_struct.process_id = PID;
	memory_struct.address = reinterpret_cast<void*>(address);
	memory_struct.size = sizeof(T);
	memory_struct.buffer = &buffer;

	NTSTATUS result
		= (NTSTATUS)(call_driver_control(m_driver_control, ID_READ_PROCESS_MEMORY, &memory_struct));

	if (result != 0)
		return "";

	std::string nameString;
	for (int i = 0; i < 100; i++) {
		if (buffer[i] == 0)
			break;
		else
			nameString += buffer[i];
	};

	return nameString;

}

bool readto(uintptr_t Address, void* Buffer, SIZE_T Size)
{
	if (Address > 0x7FFFFFFFFFFF || Address < 1);

	if (!PID)
		return false;

	MEMORY_STRUCT memory_struct = { 0 };
	memory_struct.process_id = PID;
	memory_struct.address = reinterpret_cast<void*>(Address);
	memory_struct.size = Size;
	memory_struct.buffer = Buffer;

	NTSTATUS result
		= (NTSTATUS)(call_driver_control(m_driver_control, ID_READ_PROCESS_MEMORY, &memory_struct));

	if (result != 0)
		return false;

	return true;
}

std::string read_ascii(const std::uintptr_t address, std::size_t size)
{
	std::unique_ptr<char[]> buffer(new char[size]);
	readto(address, buffer.get(), size);
	return std::string(buffer.get());
}

std::wstring read_unicode(const std::uintptr_t address, std::size_t size)
{
	const auto buffer = std::make_unique<wchar_t[]>(size);
	readto(address, buffer.get(), size * 2);
	return std::wstring(buffer.get());
}