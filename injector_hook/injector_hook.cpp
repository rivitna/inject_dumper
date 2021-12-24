//---------------------------------------------------------------------------
#define WIN32_LEAN_AND_MEAN  // Exclude rarely-used stuff from Windows headers
#include <windows.h>
#include <winnt.h>
#include <winternl.h>
#include <tchar.h>
#include <intrin.h>
#include <iphlpapi.h>
#include <shellapi.h>
#include "StdUtils.h"
#include "Log.h"
#include "HookAPI.h"
#include "HookNTAPI.h"
#include "Dump.h"
#include "MemList.h"
#include "ProcInfo.h"
//---------------------------------------------------------------------------
#ifndef _DEBUG
#pragma comment(linker, "/ENTRY:MyDllMain")
#pragma comment(linker, "/MERGE:.rdata=.text")
#pragma comment(linker, "/NODEFAULTLIB")
#endif  // _DEBUG
//---------------------------------------------------------------------------
#ifndef countof
#define countof(a)  (sizeof(a)/sizeof(a[0]))
#endif  // countof
//---------------------------------------------------------------------------
// Начальное количество выделенных записей в списке блоков памяти
#define INIT_MEM_LIST_CAPACITY   64
// Минимальный размер блока памяти для добавления в список
#define MIN_MEM_LIST_BLOCK_SIZE  4096

// Размер буфера для информации о вызове функции
#define PROC_CALL_INFO_BUFFER_SIZE  1536
//---------------------------------------------------------------------------
// Имя файла отчета
const TCHAR LOG_FILE_NAME[] = _T("log.txt");
// Имя выходного каталога
const TCHAR OUT_DIR_NAME[] = _T("dumps");
//---------------------------------------------------------------------------
// Информация о целевом объекте
typedef struct _TARGET_INFO
{
  void     *pBaseAddress;
  HANDLE    hTargetProcess;
  HANDLE    hTargetThread;
  MEM_LIST  allocMemList;
} TARGET_INFO, *PTARGET_INFO;

// Параметры перехвата системного вызова Native API
typedef struct _SYSCALL_HOOK_PARAMS
{
  const char *pszProcName;
  const void *pHookProc;
  DWORD       dwArgSize;
} SYSCALL_HOOK_PARAMS, *PSYSCALL_HOOK_PARAMS;

// Параметры перехвата функций API
typedef struct _API_HOOK_PARAMS
{
  const TCHAR  *pszLibName;
  const char   *pszProcName;
  const void   *pHookProc;
  void        **ppOrigProcThunk;
} API_HOOK_PARAMS, *PAPI_HOOK_PARAMS;

// Тип возвращаемого функцией значения
typedef enum _RETVAL_TYPE
{
  RETVAL_ULONG,
  RETVAL_NTSTATUS,
  RETVAL_BOOL
} RETVAL_TYPE;
//---------------------------------------------------------------------------
// Прототип вызова оригинальной функции "NtResumeThread"
typedef NTSTATUS (__cdecl *PFNCallNtResumeThread)(
  DWORD dwOrdinal,
  HANDLE ThreadHandle,
  PULONG SuspendCount
  );
// Прототип вызова оригинальной функции "NtGetContextThread"
typedef NTSTATUS (__cdecl *PFNCallNtGetContextThread)(
  DWORD dwOrdinal,
  HANDLE ThreadHandle,
  PCONTEXT pContext
  );
// Прототип вызова оригинальной функции "NtSetContextThread"
typedef NTSTATUS (__cdecl *PFNCallNtSetContextThread)(
  DWORD dwOrdinal,
  HANDLE ThreadHandle,
  PCONTEXT pContext
  );
// Прототип вызова оригинальной функции "NtSetInformationThread"
typedef NTSTATUS (__cdecl *PFNCallNtSetInformationThread)(
  DWORD dwOrdinal,
  HANDLE ThreadHandle,
  unsigned int ThreadInformationClass,
  PVOID ThreadInformation,
  ULONG ThreadInformationLength
  );
// Прототип вызова оригинальной функции "NtAllocateVirtualMemory"
typedef NTSTATUS (__cdecl *PFNCallNtAllocateVirtualMemory)(
  DWORD dwOrdinal,
  HANDLE ProcessHandle,
  PVOID *BaseAddress,
  ULONG_PTR ZeroBits,
  PSIZE_T RegionSize,
  ULONG AllocationType,
  ULONG Protect
  );
// Прототип вызова оригинальной функции "NtFreeVirtualMemory"
typedef NTSTATUS (__cdecl *PFNCallNtFreeVirtualMemory)(
  DWORD dwOrdinal,
  HANDLE ProcessHandle,
  PVOID *BaseAddress,
  PSIZE_T RegionSize,
  ULONG FreeType
  );
// Прототип вызова оригинальной функции "NtWriteVirtualMemory"
typedef NTSTATUS (__cdecl *PFNCallNtWriteVirtualMemory)(
  DWORD dwOrdinal,
  HANDLE ProcessHandle,
  PVOID BaseAddress,
  PVOID Buffer,
  ULONG NumberOfBytesToWrite,
  PULONG NumberOfBytesWritten
  );
// Прототип вызова оригинальной функции "NtProtectVirtualMemory"
typedef NTSTATUS (__cdecl *PFNCallNtProtectVirtualMemory)(
  DWORD dwOrdinal,
  HANDLE ProcessHandle,
  PVOID *BaseAddress,
  PULONG NumberOfBytesToProtect,
  ULONG NewAccessProtection,
  PULONG OldAccessProtection
  );
// Прототип вызова оригинальной функции "NtCreateSection"
typedef NTSTATUS (__cdecl *PFNCallNtCreateSection)(
  DWORD dwOrdinal,
  PHANDLE SectionHandle,
  ULONG DesiredAccess,
  POBJECT_ATTRIBUTES ObjectAttributes,
  PLARGE_INTEGER MaximumSize,
  ULONG SectionPageProtection,
  ULONG AllocationAttributes,
  HANDLE FileHandle
  );
// Прототип вызова оригинальной функции "NtMapViewOfSection"
typedef NTSTATUS (__cdecl *PFNCallNtMapViewOfSection)(
  DWORD dwOrdinal,
  HANDLE SectionHandle,
  HANDLE ProcessHandle,
  PVOID *BaseAddress,
  ULONG_PTR ZeroBits,
  SIZE_T CommitSize,
  PLARGE_INTEGER SectionOffset,
  PSIZE_T ViewSize,
  unsigned int InheritDisposition,
  ULONG AllocationType,
  ULONG Win32Protect
  );
// Прототип вызова оригинальной функции "NtUnmapViewOfSection"
typedef NTSTATUS (__cdecl *PFNCallNtUnmapViewOfSection)(
  DWORD dwOrdinal,
  HANDLE ProcessHandle,
  PVOID BaseAddress
  );
// Прототип вызова оригинальной функции "NtCreateUserProcess"
typedef NTSTATUS (__cdecl *PFNCallNtCreateUserProcess)(
  DWORD dwOrdinal,
  PHANDLE ProcessHandle,
  PHANDLE ThreadHandle,
  ULONG ProcessDesiredAccess,
  ULONG ThreadDesiredAccess,
  POBJECT_ATTRIBUTES ProcessObjectAttributes,
  POBJECT_ATTRIBUTES ThreadObjectAttributes,
  ULONG ProcessFlags,
  ULONG ThreadFlags,
  PVOID ProcessParameters,
  PVOID CreateInfo,
  PVOID AttributeList
  );
// Прототип вызова оригинальной функции "NtTerminateProcess"
typedef NTSTATUS (__cdecl *PFNCallNtTerminateProcess)(
  DWORD dwOrdinal,
  HANDLE ProcessHandle,
  NTSTATUS ExitStatus
  );

// Функция перехвата "NtResumeThread"
NTSTATUS WINAPI NtResumeThreadHook(
  const void *pRetAddr,
  DWORD dwOrdinal,
  HANDLE ThreadHandle,
  PULONG SuspendCount
  );
// Функция перехвата "NtGetContextThread"
NTSTATUS WINAPI NtGetContextThreadHook(
  const void *pRetAddr,
  DWORD dwOrdinal,
  HANDLE ThreadHandle,
  PCONTEXT pContext
  );
// Функция перехвата "NtSetContextThread"
NTSTATUS WINAPI NtSetContextThreadHook(
  const void *pRetAddr,
  DWORD dwOrdinal,
  HANDLE ThreadHandle,
  PCONTEXT pContext
  );
// Функция перехвата "NtSetInformationThread"
NTSTATUS WINAPI NtSetInformationThreadHook(
  const void *pRetAddr,
  DWORD dwOrdinal,
  HANDLE ThreadHandle,
  unsigned int ThreadInformationClass,
  PVOID ThreadInformation,
  ULONG ThreadInformationLength
  );
// Функция перехвата "NtAllocateVirtualMemory"
NTSTATUS WINAPI NtAllocateVirtualMemoryHook(
  const void *pRetAddr,
  DWORD dwOrdinal,
  HANDLE ProcessHandle,
  PVOID *BaseAddress,
  ULONG_PTR ZeroBits,
  PSIZE_T RegionSize,
  ULONG AllocationType,
  ULONG Protect
  );
// Функция перехвата "NtFreeVirtualMemory"
NTSTATUS WINAPI NtFreeVirtualMemoryHook(
  const void *pRetAddr,
  DWORD dwOrdinal,
  HANDLE ProcessHandle,
  PVOID *BaseAddress,
  PSIZE_T RegionSize,
  ULONG FreeType
  );
// Функция перехвата "NtWriteVirtualMemory"
NTSTATUS WINAPI NtWriteVirtualMemoryHook(
  const void *pRetAddr,
  DWORD dwOrdinal,
  HANDLE ProcessHandle,
  PVOID BaseAddress,
  PVOID Buffer,
  ULONG NumberOfBytesToWrite,
  PULONG NumberOfBytesWritten
  );
// Функция перехвата "NtProtectVirtualMemory"
NTSTATUS WINAPI NtProtectVirtualMemoryHook(
  const void *pRetAddr,
  DWORD dwOrdinal,
  HANDLE ProcessHandle,
  PVOID *BaseAddress,
  PULONG NumberOfBytesToProtect,
  ULONG NewAccessProtection,
  PULONG OldAccessProtection
  );
// Функция перехвата "NtCreateSection"
NTSTATUS WINAPI NtCreateSectionHook(
  const void *pRetAddr,
  DWORD dwOrdinal,
  PHANDLE SectionHandle,
  ULONG DesiredAccess,
  POBJECT_ATTRIBUTES ObjectAttributes,
  PLARGE_INTEGER MaximumSize,
  ULONG SectionPageProtection,
  ULONG AllocationAttributes,
  HANDLE FileHandle
  );
// Функция перехвата "NtMapViewOfSection"
NTSTATUS WINAPI NtMapViewOfSectionHook(
  const void *pRetAddr,
  DWORD dwOrdinal,
  HANDLE SectionHandle,
  HANDLE ProcessHandle,
  PVOID *BaseAddress,
  ULONG_PTR ZeroBits,
  SIZE_T CommitSize,
  PLARGE_INTEGER SectionOffset,
  PSIZE_T ViewSize,
  unsigned int InheritDisposition,
  ULONG AllocationType,
  ULONG Win32Protect
  );
// Функция перехвата "NtUnmapViewOfSection"
NTSTATUS WINAPI NtUnmapViewOfSectionHook(
  const void *pRetAddr,
  DWORD dwOrdinal,
  HANDLE ProcessHandle,
  PVOID BaseAddress
  );
// Функция перехвата "NtCreateUserProcess"
NTSTATUS WINAPI NtCreateUserProcessHook(
  const void *pRetAddr,
  DWORD dwOrdinal,
  PHANDLE ProcessHandle,
  PHANDLE ThreadHandle,
  ULONG ProcessDesiredAccess,
  ULONG ThreadDesiredAccess,
  POBJECT_ATTRIBUTES ProcessObjectAttributes,
  POBJECT_ATTRIBUTES ThreadObjectAttributes,
  ULONG ProcessFlags,
  ULONG ThreadFlags,
  PVOID ProcessParameters,
  PVOID CreateInfo,
  PVOID AttributeList
  );
// Функция перехвата "NtTerminateProcess"
NTSTATUS WINAPI NtTerminateProcessHook(
  const void *pRetAddr,
  DWORD dwOrdinal,
  HANDLE ProcessHandle,
  NTSTATUS ExitStatus
  );

// Список параметров перехвата системного вызова Native API
const SYSCALL_HOOK_PARAMS SYSCALL_HOOK_PARAM_LIST[] =
{
  { "NtResumeThread", &NtResumeThreadHook, 8 },
  { "NtGetContextThread", &NtGetContextThreadHook, 8 },
  { "NtSetContextThread", &NtSetContextThreadHook, 8 },
  { "NtSetInformationThread", &NtSetInformationThreadHook, 16 },
  { "NtAllocateVirtualMemory", &NtAllocateVirtualMemoryHook, 24 },
  { "NtFreeVirtualMemory", &NtFreeVirtualMemoryHook, 16 },
  { "NtWriteVirtualMemory", &NtWriteVirtualMemoryHook, 20 },
  { "NtProtectVirtualMemory", &NtProtectVirtualMemoryHook, 20 },
  { "NtCreateSection", &NtCreateSectionHook, 28 },
  { "NtMapViewOfSection", &NtMapViewOfSectionHook, 40 },
  { "NtUnmapViewOfSection", &NtUnmapViewOfSectionHook, 8 },
  { "NtCreateUserProcess", &NtCreateUserProcessHook, 44 },
  { "NtTerminateProcess", &NtTerminateProcessHook, 8 }
};
//---------------------------------------------------------------------------
// Функция перехвата "LdrLoadDll"
NTSTATUS WINAPI LdrLoadDllHook(
  ULONG Flags,
  PVOID Reserved,
  PUNICODE_STRING ModuleFileName,
  HMODULE *ModuleHandle
  );
// Функция перехвата "CreateProcessInternalW"
BOOL WINAPI CreateProcessInternalWHook(
  HANDLE hToken,
  LPCWSTR lpApplicationName,
  LPWSTR lpCommandLine,
  LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  BOOL bInheritedHandles,
  DWORD dwCreationFlags,
  LPVOID lpEnvironment,
  LPCWSTR lpCurrentDirectory,
  LPSTARTUPINFOW lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInformation,
  PHANDLE hNewToken
  );
// Функция перехвата "WriteProcessMemory"
BOOL WINAPI WriteProcessMemoryHook(
  HANDLE hProcess,
  LPVOID lpBaseAddress,
  LPCVOID lpBuffer,
  SIZE_T nSize,
  SIZE_T *lpNumberOfBytesWritten
  );
// Функция перехвата "GetAdaptersInfo"
BOOL WINAPI GetAdaptersInfoHook(
  PIP_ADAPTER_INFO AdapterInfo,
  PULONG SizePointer
  );
// Функция перехвата "ShellExecuteExW"
BOOL WINAPI ShellExecuteExWHook(
  SHELLEXECUTEINFOW *pExecInfo
  );

// Код вызова оригинальной перехваченной функции "LdrLoadDll"
BOOL (WINAPI *g_pfnLdrLoadDllThunk)(
  ULONG Flags,
  PVOID Reserved,
  PUNICODE_STRING ModuleFileName,
  HMODULE *ModuleHandle
  );
// Код вызова оригинальной перехваченной функции "CreateProcessInternalW"
BOOL (WINAPI *g_pfnCreateProcessInternalWThunk)(
  HANDLE hToken,
  LPCWSTR lpApplicationName,
  LPWSTR lpCommandLine,
  LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  BOOL bInheritedHandles,
  DWORD dwCreationFlags,
  LPVOID lpEnvironment,
  LPCWSTR lpCurrentDirectory,
  LPSTARTUPINFOW lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInformation,
  PHANDLE hNewToken
  );
// Код вызова оригинальной перехваченной функции "WriteProcessMemory"
BOOL (WINAPI *g_pfnWriteProcessMemoryThunk)(
  HANDLE hProcess,
  LPVOID lpBaseAddress,
  LPCVOID lpBuffer,
  SIZE_T nSize,
  SIZE_T *lpNumberOfBytesWritten
  );
// Код вызова оригинальной перехваченной функции "GetAdaptersInfo"
ULONG (WINAPI *g_pfnGetAdaptersInfoThunk)(
  PIP_ADAPTER_INFO AdapterInfo,
  PULONG SizePointer
  );
// Код вызова оригинальной перехваченной функции "ShellExecuteExW"
ULONG (WINAPI *g_pfnShellExecuteExWThunk)(
  SHELLEXECUTEINFOW *pExecInfo
  );

// Список параметров перехвата функций API
const API_HOOK_PARAMS API_HOOK_PARAM_LIST[] =
{
  { _T("NTDLL.DLL"), "LdrLoadDll",
    &LdrLoadDllHook,
    (void **)&g_pfnLdrLoadDllThunk },
  { _T("KERNEL32.DLL"), "CreateProcessInternalW",
    &CreateProcessInternalWHook,
    (void **)&g_pfnCreateProcessInternalWThunk },
  { _T("KERNEL32.DLL"), "WriteProcessMemory",
    &WriteProcessMemoryHook,
    (void **)&g_pfnWriteProcessMemoryThunk },
  { _T("IPHLPAPI.DLL"), "GetAdaptersInfo",
    &GetAdaptersInfoHook,
    (void **)&g_pfnGetAdaptersInfoThunk },
  { _T("SHELL32.DLL"), "ShellExecuteExW",
    &ShellExecuteExWHook,
    (void **)&g_pfnShellExecuteExWThunk }
};

// Коды перехода на адреса оригинальных функций API
void *g_pOrigFuncThunks;

#define ORIG_FUNC_THUNKS_SIZE  \
  (countof(API_HOOK_PARAM_LIST) * MAX_THUNK_CODE_SIZE)
//---------------------------------------------------------------------------
// Информация о целевом объекте
TARGET_INFO g_targetInfo;

// Путь к выходному каталогу
TCHAR g_szOutDirPath[MAX_PATH];

// Дескриптор библиотеки IP Helper API
HMODULE g_hIpHlpAPILib;
// Дескриптор библиотеки Shell API
HMODULE g_hShellAPILib;

// Счетчик блокировки мониторинга
volatile LONG g_ulSpyBlockCount;

// Дескриптор библиотеки
HMODULE g_hDllHandle;
//---------------------------------------------------------------------------
// Инициализация
BOOL Init();
// Деинициализация
void Uninit();
// Проверка блокировки мониторинга
BOOL IsSpyBlocked();
// Блокировка мониторинга
void BlockSpy();
// Разблокировка мониторинга
void UnblockSpy();
// Копирование строки UNICODE_STRING
unsigned int CopyUnicodeString(
  wchar_t *pBuffer,
  unsigned int nSize,
  const UNICODE_STRING *pUnicodeStr
  );
// Запись в файл отчета информации о вызове функции
unsigned int LogProcCallIn(
  const wchar_t *pszProcName,
  const void *pRetAddr,
  const wchar_t *pszArgFmt,
  ...
  );
// Запись в файл отчета информации о результатах вызова функции
unsigned int LogProcCallOut(
  const wchar_t *pszProcName,
  const void *pRetAddr,
  unsigned int nRetVal,
  RETVAL_TYPE retValType,
  const wchar_t *pszArgFmt,
  ...
  );
//---------------------------------------------------------------------------
/***************************************************************************/
/* MyDllMain                                                               */
/***************************************************************************/
BOOL WINAPI MyDllMain(
  HINSTANCE hinstDLL,
  DWORD fdwReason,
  LPVOID lpvReserved
  )
{
  switch (fdwReason)
  {
    case DLL_PROCESS_ATTACH:
      g_hDllHandle = hinstDLL;
      // Запрет вызовов с нотификациями DLL_THREAD_ATTACH и DLL_THREAD_DETACH
      ::DisableThreadLibraryCalls(hinstDLL);
      // Инициализация
      if (!Init())
        return FALSE;
      break;

    case DLL_PROCESS_DETACH:
      // Деинициализация
      Uninit();
      break;
  }
  return TRUE;
}
/***************************************************************************/
/* HookNTAPIFuncs - Перехват функций Native API                            */
/***************************************************************************/
BOOL HookNTAPIFuncs()
{
  // Инициализация перехвата системных вызовов Native API
  if (!InitHookSysCall(countof(SYSCALL_HOOK_PARAM_LIST)))
  {
    LogW(L"Error: Failed to initialize system call hooking.");
    return FALSE;
  }

  const SYSCALL_HOOK_PARAMS *pParams = SYSCALL_HOOK_PARAM_LIST;
  for (size_t i = 0; i < countof(SYSCALL_HOOK_PARAM_LIST); i++, pParams++)
  {
    // Добавление перехвата системного вызова Native API
    if (!AddSysCallHook(pParams->pszProcName, pParams->pHookProc,
                        pParams->dwArgSize))
    {
      LogFmtW(L"Error: Could not set hook for \"%hs\".",
              pParams->pszProcName);
    }
  }

  return TRUE;
}
/***************************************************************************/
/* HookAPIFuncs - Перехват функций API                                     */
/***************************************************************************/
BOOL HookAPIFuncs()
{
  // Выделение памяти для кодов перехода на адреса оригинальных функций API
  void *pThunks = ::VirtualAlloc(NULL, ORIG_FUNC_THUNKS_SIZE,
                                 MEM_RESERVE | MEM_COMMIT,
                                 PAGE_EXECUTE_READWRITE);
  if (!pThunks)
  {
    LogW(L"Error: Not enough memory.");
    return FALSE;
  }

  g_pOrigFuncThunks = pThunks;

  unsigned char *pThunk = (unsigned char *)pThunks;

  const API_HOOK_PARAMS *pParams = API_HOOK_PARAM_LIST;
  for (size_t i = 0; i < countof(API_HOOK_PARAM_LIST); i++, pParams++)
  {
    void *pOrigProcThunk;
    if (pParams->ppOrigProcThunk)
    {
      *pParams->ppOrigProcThunk = pOrigProcThunk = pThunk;
      pThunk += MAX_THUNK_CODE_SIZE;
    }
    else
    {
      pOrigProcThunk = NULL;
    }
    // Перехват функции API
    if (!HookAPIFunc(pParams->pszLibName, pParams->pszProcName,
                     pParams->pHookProc, pOrigProcThunk))
    {
      LogFmtW(L"Error: Could not set hook for \"%hs\".",
              pParams->pszProcName);
    }
  }

  return TRUE;
}
/***************************************************************************/
/* Init - Инициализация                                                    */
/***************************************************************************/
BOOL Init()
{
  g_ulSpyBlockCount = 0;
  g_pOrigFuncThunks = NULL;
  g_szOutDirPath[0] = _T('\0');
  g_hIpHlpAPILib = NULL;
  g_hShellAPILib = NULL;

  g_targetInfo.pBaseAddress = (void *)::GetModuleHandle(NULL);
  g_targetInfo.hTargetProcess = NULL;
  g_targetInfo.hTargetThread = NULL;
  // Инициализация списка блоков памяти
  MemList_Init(&g_targetInfo.allocMemList, INIT_MEM_LIST_CAPACITY);

  unsigned int cch;
  TCHAR szPath[MAX_PATH];

  // Получение пути к динамической библиотеке
  cch = ::GetModuleFileName(g_hDllHandle, szPath, countof(szPath));
  if ((cch == 0) || (cch >= countof(szPath)))
    return FALSE;

  cch = GetFileName(szPath) - szPath;

  // Получение пути к выходному каталогу
#ifdef _UNICODE
  if (cch > countof(g_szOutDirPath) -
            (countof(L"\\\\?\\") - 1 + countof(L"\\") - 1 +
             countof(OUT_DIR_NAME)))
    return FALSE;
#else
  if (cch > sizeof(g_szOutDirPath) -
            (sizeof("\\") - 1 + sizeof(OUT_DIR_NAME)))
    return FALSE;
#endif  // _UNICODE
  TCHAR *pch = g_szOutDirPath;
#ifdef _UNICODE
  // Добавление префикса длинных имен
  if ((cch >= countof(L"X:\\") - 1) && (szPath[1] == L':') &&
      ((szPath[2] == L'\\') || (szPath[2] == L'/')))
  {
    wchar_t ch = szPath[0] | L' ';
    if ((ch >= L'a') && (ch <= L'z'))
    {
      pch[0] = pch[1] = pch[3] = L'\\';
      pch[2] = L'?';
      pch += countof(L"\\\\?\\") - 1;
    }
  }
#endif  // _UNICODE
  CopyMem(pch, szPath, cch * sizeof(TCHAR));
  pch += cch;
  CopyMem(pch, OUT_DIR_NAME, (countof(OUT_DIR_NAME) - 1) * sizeof(TCHAR));
  pch += countof(OUT_DIR_NAME) - 1;
  *pch++ = _T('\\');
  *pch = _T('\0');

  // Получение пути к файлу отчета
  if (cch > countof(szPath) - countof(LOG_FILE_NAME))
    return FALSE;
  CopyMem(&szPath[cch], LOG_FILE_NAME, sizeof(LOG_FILE_NAME));

  // Получение имени исполняемого файла
  wchar_t szExePath[MAX_PATH];
  cch = ::GetModuleFileNameW(NULL, szExePath, countof(szExePath));
  if ((cch == 0) || (cch >= countof(szExePath)))
    return FALSE;

  // Создание выходного каталога
  if (!::CreateDirectory(g_szOutDirPath, NULL) &&
      (::GetLastError() != ERROR_ALREADY_EXISTS))
    return FALSE;

  // Открытие файла отчета
  if (!OpenLog(szPath, TRUE))
    return FALSE;

  // Запись в файл отчета информации о целевом файле
  LogFmtW(L"Module:       \"%s\"\r\n" \
          L"Base address: %p\r\n" \
          L"Process Id:   %08lX",
          GetFileNameW(szExePath),
          g_targetInfo.pBaseAddress,
          ::GetCurrentProcessId());

  BOOL bSuccess = FALSE;

  // Блокировка мониторинга
  BlockSpy();

  // Загрузка библиотеки IP Helper API
  g_hIpHlpAPILib = ::LoadLibrary(_T("IPHLPAPI.DLL"));
  // Загрузка библиотеки Shell API
  g_hShellAPILib = ::LoadLibrary(_T("SHELL32.DLL"));

  // Перехват функций API и системных вызовов Native API
  if (HookAPIFuncs() && HookNTAPIFuncs())
    bSuccess = TRUE;

  // Разблокировка мониторинга
  UnblockSpy();

  return bSuccess;
}
/***************************************************************************/
/* Uninit - Деинициализация                                                */
/***************************************************************************/
void Uninit()
{
  // Блокировка мониторинга
  BlockSpy();

  // Закрытие файла отчета
  CloseLog();

  // Удаление перехватов системных вызовов Native API
  DelSysCallHooks();

  // Освобождение списка блоков памяти
  MemList_Free(&g_targetInfo.allocMemList);

  // Освобождение памяти, выделенной для кодов перехода на адреса
  // оригинальных функций API
  if (g_pOrigFuncThunks)
  {
    ::VirtualFree(g_pOrigFuncThunks, 0, MEM_RELEASE);
    g_pOrigFuncThunks = NULL;
  }

  // Освобождение библиотеки Shell API
  if (g_hShellAPILib)
  {
    ::FreeLibrary(g_hShellAPILib);
    g_hShellAPILib = NULL;
  }
  // Освобождение библиотеки IP Helper API
  if (g_hIpHlpAPILib)
  {
    ::FreeLibrary(g_hIpHlpAPILib);
    g_hIpHlpAPILib = NULL;
  }
}
/***************************************************************************/
/* WriteMemBlocksToFiles - Сохранение блоков памяти в файлы                */
/***************************************************************************/
void WriteMemBlocksToFiles(
  PMEM_LIST pMemList,
  const TCHAR *pszPrefixName
  )
{
  if (!pMemList)
    return;

  // Блокировка списка блоков памяти
  MemList_Lock(pMemList);

  PMEM_LIST_ENTRY pEntry = pMemList->pEntries;
  for (size_t i = 0; i < pMemList->nNumEntries; i++, pEntry++)
  {
    MEMORY_BASIC_INFORMATION memInfo;
    if (::VirtualQuery(pEntry->pAddr, &memInfo, sizeof(memInfo)) &&
        (memInfo.State == MEM_COMMIT) &&
        (memInfo.Protect != PAGE_NOACCESS))
    {
      size_t nSize = memInfo.RegionSize -
                     ((INT_PTR)pEntry->pAddr - (INT_PTR)memInfo.BaseAddress);
      if (nSize > pEntry->nSize)
        nSize = pEntry->nSize;
      if (nSize > MIN_MEM_LIST_BLOCK_SIZE)
      {
        // Запись блока в файл
        unsigned int res = WriteDataToFile(pEntry->pAddr,
                                           (unsigned int)nSize,
                                           _T("%s%s_mem_%p.dmp"),
                                           g_szOutDirPath, pszPrefixName,
                                           pEntry->pAddr);
        if (res != ERROR_SUCCESS)
        {
          LogFmtW(L"Error: Failed to save memory block %p of %u bytes (%u).",
                  pEntry->pAddr, (unsigned int)nSize, res);
        }
      }
    }
  }

  // Очистка списка блоков памяти
  MemList_Clear(pMemList);

  // Разблокировка списка блоков памяти
  MemList_Unlock(pMemList);
}
//---------------------------------------------------------------------------
/***************************************************************************/
/* LdrLoadDllHook - Функция перехвата "LdrLoadDll"                         */
/***************************************************************************/
NTSTATUS WINAPI LdrLoadDllHook(
  ULONG Flags,
  PVOID Reserved,
  PUNICODE_STRING ModuleFileName,
  HMODULE *ModuleHandle
  )
{
  const void *pRetAddr = HOOK_PROC_RET_ADDR(Flags);

  BOOL bSpyBlocked = IsSpyBlocked();

  // Блокировка мониторинга
  BlockSpy();

  NTSTATUS res;

  // Вызов оригинальной функции "LdrLoadDll"
  res = g_pfnLdrLoadDllThunk(Flags, Reserved, ModuleFileName, ModuleHandle);

  if (!bSpyBlocked)
  {
    if ((res == 0) && ModuleFileName && ModuleHandle)
    {
      wchar_t szModuleFileName[MAX_PATH];
      CopyUnicodeString(szModuleFileName, countof(szModuleFileName),
                        ModuleFileName);
      LogFmtW(L"\"%s\" is loaded at %p.", szModuleFileName, *ModuleHandle);
    }
  }

  // Разблокировка мониторинга
  UnblockSpy();

  return res;
}
/***************************************************************************/
/* CreateProcessInternalWHook - Функция перехвата "CreateProcessInternalW" */
/***************************************************************************/
BOOL WINAPI CreateProcessInternalWHook(
  HANDLE hToken,
  LPCWSTR lpApplicationName,
  LPWSTR lpCommandLine,
  LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  BOOL bInheritedHandles,
  DWORD dwCreationFlags,
  LPVOID lpEnvironment,
  LPCWSTR lpCurrentDirectory,
  LPSTARTUPINFOW lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInformation,
  PHANDLE hNewToken
  )
{
  const void *pRetAddr = HOOK_PROC_RET_ADDR(hToken);

  BOOL bSpyBlocked = IsSpyBlocked();

  // Блокировка мониторинга
  BlockSpy();

  if (!bSpyBlocked)
  {
    // Запись в файл отчета информации о вызове функции
    LogProcCallIn(L"CreateProcessInternalW", pRetAddr,
                  L"lpApplicationName=\"%s\", " \
                  L"lpCommandLine=\"%s\", " \
                  L"dwCreationFlags=%08lX",
                  lpApplicationName ? lpApplicationName : L"",
                  lpCommandLine ? lpCommandLine : L"",
                  dwCreationFlags);
  }

  BOOL bRet;

  // Вызов оригинальной функции "CreateProcessInternalW"
  bRet = g_pfnCreateProcessInternalWThunk(hToken,
                                          lpApplicationName,
                                          lpCommandLine,
                                          lpProcessAttributes,
                                          lpThreadAttributes,
                                          bInheritedHandles,
                                          dwCreationFlags,
                                          lpEnvironment,
                                          lpCurrentDirectory,
                                          lpStartupInfo,
                                          lpProcessInformation,
                                          hNewToken);

  if (!bSpyBlocked)
  {
    if (bRet)
    {
      if (dwCreationFlags & CREATE_SUSPENDED)
      {
        g_targetInfo.hTargetProcess = lpProcessInformation->hProcess;
        g_targetInfo.hTargetThread = lpProcessInformation->hThread;
      }

      // Запись в файл отчета информации о результатах вызова функции
      LogProcCallOut(L"CreateProcessInternalW", pRetAddr, bRet, RETVAL_BOOL,
                     L"hProcess=%p, " \
                     L"hThread=%p, " \
                     L"dwProcessId=%08lX, " \
                     L"dwThreadId=%08lX",
                     lpProcessInformation->hProcess,
                     lpProcessInformation->hThread,
                     lpProcessInformation->dwProcessId,
                     lpProcessInformation->dwThreadId);
    }
    else
    {
      // Запись в файл отчета информации о результатах вызова функции
      LogProcCallOut(L"CreateProcessInternalW", pRetAddr, bRet, RETVAL_BOOL,
                     NULL);
    }
  }

  // Разблокировка мониторинга
  UnblockSpy();

  return bRet;
}
/***************************************************************************/
/* WriteProcessMemoryHook - Функция перехвата "WriteProcessMemory"         */
/***************************************************************************/
BOOL WINAPI WriteProcessMemoryHook(
  HANDLE hProcess,
  LPVOID lpBaseAddress,
  LPCVOID lpBuffer,
  SIZE_T nSize,
  SIZE_T *lpNumberOfBytesWritten
  )
{
  const void *pRetAddr = HOOK_PROC_RET_ADDR(hProcess);

  BOOL bSpyBlocked = IsSpyBlocked();

  // Блокировка мониторинга
  BlockSpy();

  if (!bSpyBlocked)
  {
    // Запись в файл отчета информации о вызове функции
    LogProcCallIn(L"WriteProcessMemory", pRetAddr,
                  L"hProcess=%p, " \
                  L"lpBaseAddress=%p, " \
                  L"lpBuffer=%p, " \
                  L"nSize=%u",
                  hProcess,
                  lpBaseAddress,
                  lpBuffer,
                  (unsigned int)nSize);

    if (hProcess == g_targetInfo.hTargetProcess)
    {
      // Запись данных в файл
      unsigned int res = WriteDataToFile(lpBuffer, (unsigned int)nSize,
                                         _T("%swpm_%p_%p_%p_%u.dmp"),
                                         g_szOutDirPath,
                                         hProcess, lpBaseAddress, lpBuffer,
                                         (unsigned int)nSize);
      if (res != ERROR_SUCCESS)
      {
        LogFmtW(L"Error: Failed to save memory block %p (%u).",
                lpBuffer, res);
      }
    }
  }

  BOOL bRet;

  SIZE_T nBytesWritten;

  // Вызов оригинальной функции "WriteProcessMemory"
  bRet = g_pfnWriteProcessMemoryThunk(hProcess, lpBaseAddress, lpBuffer,
                                      nSize, &nBytesWritten);

  if (!bSpyBlocked)
  {
    if (bRet)
    {
      // Запись в файл отчета информации о результатах вызова функции
      LogProcCallOut(L"WriteProcessMemory", pRetAddr, bRet, RETVAL_BOOL,
                     L"NumberOfBytesWritten=%u",
                     (unsigned int)nBytesWritten);
    }
    else
    {
      // Запись в файл отчета информации о результатах вызова функции
      LogProcCallOut(L"WriteProcessMemory", pRetAddr, bRet, RETVAL_BOOL,
                     NULL);
    }
  }

  // Разблокировка мониторинга
  UnblockSpy();

  if (lpNumberOfBytesWritten)
    *lpNumberOfBytesWritten = nBytesWritten;
  return bRet;
}
/***************************************************************************/
/* GetAdaptersInfoHook - Функция перехвата "GetAdaptersInfo"               */
/***************************************************************************/
BOOL WINAPI GetAdaptersInfoHook(
  PIP_ADAPTER_INFO AdapterInfo,
  PULONG SizePointer
  )
{
  const void *pRetAddr = HOOK_PROC_RET_ADDR(AdapterInfo);

  BOOL bSpyBlocked = IsSpyBlocked();

  // Блокировка мониторинга
  BlockSpy();

  if (!bSpyBlocked)
  {
    // Запись в файл отчета информации о вызове функции
    LogProcCallIn(L"GetAdaptersInfo", pRetAddr,
                  L"AdapterInfo=%p, " \
                  L"Size=%lu",
                  AdapterInfo,
                  SizePointer ? *SizePointer : 0UL);
  }

  ULONG ulRet;

  // Вызов оригинальной функции "GetAdaptersInfo"
  ulRet = g_pfnGetAdaptersInfoThunk(AdapterInfo, SizePointer);

  if (!bSpyBlocked)
  {
    if ((ulRet == ERROR_SUCCESS) &&
        AdapterInfo && !AdapterInfo->Description[0])
    {
      AdapterInfo->Description[0] = 'X';
      AdapterInfo->Description[1] = '\0';
      LogW(L"The Description Member of the IP_ADAPTER_INFO changed.");
      // Изменение поля IsDebuggerPresent в PEB
      unsigned char *pPEB = (unsigned char *)__readfsdword(0x30);
      pPEB[2] = 1;
      LogW(L"The IsDebuggerPresent Member of the PEB changed.");
    }

    // Запись в файл отчета информации о результатах вызова функции
    LogProcCallOut(L"GetAdaptersInfo", pRetAddr, ulRet, RETVAL_ULONG,
                   L"Size=%lu",
                   SizePointer ? *SizePointer : 0UL);
  }

  // Разблокировка мониторинга
  UnblockSpy();

  return ulRet;
}
/***************************************************************************/
/* ShellExecuteExWHook - Функция перехвата "ShellExecuteExWHook"           */
/***************************************************************************/
BOOL WINAPI ShellExecuteExWHook(
  SHELLEXECUTEINFOW *pExecInfo
  )
{
  const void *pRetAddr = HOOK_PROC_RET_ADDR(pExecInfo);

  BOOL bSpyBlocked = IsSpyBlocked();

  // Блокировка мониторинга
  BlockSpy();

  if (!bSpyBlocked)
  {
    // Запись в файл отчета информации о вызове функции
    LPCWSTR lpVerb = NULL;
    LPCWSTR lpFile = NULL;
    LPCWSTR lpParameters = NULL;
    int nShow = -1;
    if (pExecInfo && (pExecInfo->cbSize == sizeof(SHELLEXECUTEINFOW)))
    {
      lpVerb = pExecInfo->lpVerb;
      lpFile = pExecInfo->lpFile;
      lpParameters = pExecInfo->lpParameters;
      nShow = pExecInfo->nShow;
    }
    LogProcCallIn(L"ShellExecuteExW", pRetAddr,
                  L"lpVerb=\"%s\", " \
                  L"lpFile=\"%s\", " \
                  L"lpParameters=\"%s\", " \
                  L"nShow=%d",
                  lpVerb ? lpVerb : L"",
                  lpFile ? lpFile : L"",
                  lpParameters ? lpParameters : L"",
                  nShow);
  }

  BOOL bRet;

  // Вызов оригинальной функции "ShellExecuteExW"
  bRet = g_pfnShellExecuteExWThunk(pExecInfo);

  if (!bSpyBlocked)
  {
    // Запись в файл отчета информации о результатах вызова функции
    LogProcCallOut(L"ShellExecuteExW", pRetAddr, bRet, RETVAL_BOOL, NULL);
  }

  // Разблокировка мониторинга
  UnblockSpy();

  return bRet;
}
/***************************************************************************/
/* NtResumeThreadHook - Функция перехвата "NtResumeThread"                 */
/***************************************************************************/
NTSTATUS WINAPI NtResumeThreadHook(
  const void *pRetAddr,
  DWORD dwOrdinal,
  HANDLE ThreadHandle,
  PULONG SuspendCount
  )
{
  BOOL bSpyBlocked = IsSpyBlocked();

  // Блокировка мониторинга
  BlockSpy();

  if (!bSpyBlocked)
  {
    // Запись в файл отчета информации о вызове функции
    LogProcCallIn(L"NtResumeThread", pRetAddr,
                  L"ThreadHandle=%p", ThreadHandle);

    if (ThreadHandle == g_targetInfo.hTargetThread)
    {
      // Сохранение исполняемого модуля процесса в файл
      unsigned int res;
      res = WriteProcessModuleToFile(g_targetInfo.hTargetProcess,
                                     g_targetInfo.hTargetThread,
                                     _T("%srt_module_%p_%p.dmp"),
                                     g_szOutDirPath,
                                     g_targetInfo.hTargetProcess,
                                     g_targetInfo.hTargetThread);
      if (res != ERROR_SUCCESS)
      {
        LogFmtW(L"Error: Failed to save process module (%u).", res);
      }

      // Сохранение выделенных блоков памяти в файлы
      WriteMemBlocksToFiles(&g_targetInfo.allocMemList, _T("rt"));

      // Разблокировка мониторинга
      UnblockSpy();

      return 0;
    }
  }

  NTSTATUS res;

  // Вызов оригинальной функции "NtResumeThread"
  res = ((PFNCallNtResumeThread)&CallSysCall)(dwOrdinal, ThreadHandle,
                                              SuspendCount);

  if (!bSpyBlocked)
  {
    // Запись в файл отчета информации о результатах вызова функции
    LogProcCallOut(L"NtResumeThread", pRetAddr, res, RETVAL_NTSTATUS, NULL);
  }

  // Разблокировка мониторинга
  UnblockSpy();

  return res;
}
/***************************************************************************/
/* NtGetContextThreadHook - Функция перехвата "NtGetContextThread"         */
/***************************************************************************/
NTSTATUS WINAPI NtGetContextThreadHook(
  const void *pRetAddr,
  DWORD dwOrdinal,
  HANDLE ThreadHandle,
  PCONTEXT pContext
  )
{
  BOOL bSpyBlocked = IsSpyBlocked();

  // Блокировка мониторинга
  BlockSpy();

  if (!bSpyBlocked)
  {
    // Запись в файл отчета информации о вызове функции
    LogProcCallIn(L"NtGetContextThread", pRetAddr,
                  L"ThreadHandle=%p, " \
                  L"pContext=%p",
                  ThreadHandle,
                  pContext);
  }

  NTSTATUS res;

  // Вызов оригинальной функции "NtGetContextThread"
  res = ((PFNCallNtGetContextThread)&CallSysCall)(dwOrdinal,
                                                  ThreadHandle,
                                                  pContext);

  if (!bSpyBlocked)
  {
    // Запись в файл отчета информации о результатах вызова функции
    LogProcCallOut(L"NtGetContextThread", pRetAddr, res, RETVAL_NTSTATUS,
                   NULL);
  }

  // Разблокировка мониторинга
  UnblockSpy();

  return res;
}
/***************************************************************************/
/* NtSetContextThreadHook - Функция перехвата "NtSetContextThread"         */
/***************************************************************************/
NTSTATUS WINAPI NtSetContextThreadHook(
  const void *pRetAddr,
  DWORD dwOrdinal,
  HANDLE ThreadHandle,
  PCONTEXT pContext
  )
{
  BOOL bSpyBlocked = IsSpyBlocked();

  // Блокировка мониторинга
  BlockSpy();

  if (!bSpyBlocked)
  {
    // Запись в файл отчета информации о вызове функции
    LogProcCallIn(L"NtSetContextThread", pRetAddr,
                  L"ThreadHandle=%p, " \
                  L"pContext=%p",
                  ThreadHandle,
                  pContext);

    if (ThreadHandle == g_targetInfo.hTargetThread)
    {
      // Сохранение исполняемого модуля процесса в файл
      unsigned int res;
      res = WriteProcessModuleToFile(g_targetInfo.hTargetProcess,
                                     g_targetInfo.hTargetThread,
                                     _T("%ssct_module_%p_%p.dmp"),
                                     g_szOutDirPath,
                                     g_targetInfo.hTargetProcess,
                                     g_targetInfo.hTargetThread);
      if (res != ERROR_SUCCESS)
      {
        LogFmtW(L"Error: Failed to save process module (%u).", res);
      }

      // Сохранение выделенных блоков памяти в файлы
      WriteMemBlocksToFiles(&g_targetInfo.allocMemList, _T("sct"));
    }
  }

  NTSTATUS res;

  // Вызов оригинальной функции "NtSetContextThread"
  res = ((PFNCallNtSetContextThread)&CallSysCall)(dwOrdinal,
                                                  ThreadHandle,
                                                  pContext);

  if (!bSpyBlocked)
  {
    // Запись в файл отчета информации о результатах вызова функции
    LogProcCallOut(L"NtSetContextThread", pRetAddr, res, RETVAL_NTSTATUS,
                   NULL);
  }

  // Разблокировка мониторинга
  UnblockSpy();

  return res;
}
/***************************************************************************/
/* NtSetInformationThreadHook - Функция перехвата "NtSetInformationThread" */
/***************************************************************************/
NTSTATUS WINAPI NtSetInformationThreadHook(
  const void *pRetAddr,
  DWORD dwOrdinal,
  HANDLE ThreadHandle,
  unsigned int ThreadInformationClass,
  PVOID ThreadInformation,
  ULONG ThreadInformationLength
  )
{
  BOOL bSpyBlocked = IsSpyBlocked();

  // Блокировка мониторинга
  BlockSpy();

  if (!bSpyBlocked)
  {
    // Запись в файл отчета информации о вызове функции
    LogProcCallIn(L"NtSetInformationThread", pRetAddr,
                  L"ThreadHandle=%p, " \
                  L"ThreadInformationClass=%u, " \
                  L"ThreadInformation=%p, " \
                  L"ThreadInformationLength=%lu",
                  ThreadHandle,
                  (unsigned int)ThreadInformationClass,
                  ThreadInformation,
                  ThreadInformationLength);
  }

  NTSTATUS res;

  // Вызов оригинальной функции "NtSetInformationThread"
  res = ((PFNCallNtSetInformationThread)&CallSysCall)(dwOrdinal,
                                                      ThreadHandle,
                                                      ThreadInformationClass,
                                                      ThreadInformation,
                                                      ThreadInformationLength);

  if (!bSpyBlocked)
  {
    // Запись в файл отчета информации о результатах вызова функции
    LogProcCallOut(L"NtSetInformationThread", pRetAddr, res, RETVAL_NTSTATUS,
                   NULL);
  }

  // Разблокировка мониторинга
  UnblockSpy();

  return res;
}
/***************************************************************************/
/* NtAllocateVirtualMemoryHook - Функция перехвата                         */
/*                               "NtAllocateVirtualMemory"                 */
/***************************************************************************/
NTSTATUS WINAPI NtAllocateVirtualMemoryHook(
  const void *pRetAddr,
  DWORD dwOrdinal,
  HANDLE ProcessHandle,
  PVOID *BaseAddress,
  ULONG_PTR ZeroBits,
  PSIZE_T RegionSize,
  ULONG AllocationType,
  ULONG Protect
  )
{
  BOOL bSpyBlocked = IsSpyBlocked();

  // Блокировка мониторинга
  BlockSpy();

  if (!bSpyBlocked)
  {
    // Запись в файл отчета информации о вызове функции
    LogProcCallIn(L"NtAllocateVirtualMemory", pRetAddr,
                  L"ProcessHandle=%p, " \
                  L"BaseAddress=%p, " \
                  L"RegionSize=%u, " \
                  L"AllocationType=%08lX, " \
                  L"Protect=%08lX",
                  ProcessHandle,
                  BaseAddress ? *BaseAddress : (PVOID)0,
                  (unsigned int)(RegionSize ? *RegionSize : (SIZE_T)0),
                  AllocationType,
                  Protect);
  }

  NTSTATUS res;

  // Вызов оригинальной функции "NtAllocateVirtualMemory"
  res = ((PFNCallNtAllocateVirtualMemory)&CallSysCall)(dwOrdinal,
                                                       ProcessHandle,
                                                       BaseAddress,
                                                       ZeroBits,
                                                       RegionSize,
                                                       AllocationType,
                                                       Protect);

  if (!bSpyBlocked)
  {
    PVOID pBaseAddress = BaseAddress ? *BaseAddress : (PVOID)0;
    SIZE_T nRegionSize = RegionSize ? *RegionSize : (SIZE_T)0;

    if ((res == 0) &&
        (ProcessHandle == (HANDLE)-1) &&
        (AllocationType & MEM_COMMIT) &&
        pBaseAddress &&
        (nRegionSize > MIN_MEM_LIST_BLOCK_SIZE))
    {
      // Добавление блока памяти в список
      MemList_Add(&g_targetInfo.allocMemList, pBaseAddress, nRegionSize);
    }

    // Запись в файл отчета информации о результатах вызова функции
    LogProcCallOut(L"NtAllocateVirtualMemory", pRetAddr,
                   res, RETVAL_NTSTATUS,
                   L"BaseAddress=%p, " \
                   L"RegionSize=%u",
                   pBaseAddress,
                   (unsigned int)nRegionSize);
  }

  // Разблокировка мониторинга
  UnblockSpy();

  return res;
}
/***************************************************************************/
/* NtFreeVirtualMemoryHook - Функция перехвата "NtFreeVirtualMemory"       */
/***************************************************************************/
NTSTATUS WINAPI NtFreeVirtualMemoryHook(
  const void *pRetAddr,
  DWORD dwOrdinal,
  HANDLE ProcessHandle,
  PVOID *BaseAddress,
  PSIZE_T RegionSize,
  ULONG FreeType
  )
{
  BOOL bSpyBlocked = IsSpyBlocked();

  // Блокировка мониторинга
  BlockSpy();

  if (!bSpyBlocked)
  {
    // Запись в файл отчета информации о вызове функции
    LogProcCallIn(L"NtFreeVirtualMemory", pRetAddr,
                  L"ProcessHandle=%p, " \
                  L"BaseAddress=%p, " \
                  L"RegionSize=%u, " \
                  L"FreeType=%08lX",
                  ProcessHandle,
                  BaseAddress ? *BaseAddress : (PVOID)0,
                  (unsigned int)(RegionSize ? *RegionSize : (SIZE_T)0),
                  FreeType);
  }

  NTSTATUS res;

  // Вызов оригинальной функции "NtFreeVirtualMemory"
  res = ((PFNCallNtFreeVirtualMemory)&CallSysCall)(dwOrdinal,
                                                   ProcessHandle,
                                                   BaseAddress,
                                                   RegionSize,
                                                   FreeType);

  if (!bSpyBlocked)
  {
    PVOID pBaseAddress = BaseAddress ? *BaseAddress : (PVOID)0;

    if ((res == 0) &&
        (ProcessHandle == (HANDLE)-1) &&
        pBaseAddress)
    {
      // Удаление блока памяти из списка
      MemList_Del(&g_targetInfo.allocMemList, pBaseAddress);
    }

    // Запись в файл отчета информации о результатах вызова функции
    LogProcCallOut(L"NtFreeVirtualMemory", pRetAddr, res, RETVAL_NTSTATUS,
                   L"BaseAddress=%p, " \
                   L"RegionSize=%u",
                   pBaseAddress,
                   (unsigned int)(RegionSize ? *RegionSize : (SIZE_T)0));
  }

  // Разблокировка мониторинга
  UnblockSpy();

  return res;
}
/***************************************************************************/
/* NtWriteVirtualMemoryHook - Функция перехвата "NtWriteVirtualMemory"     */
/***************************************************************************/
NTSTATUS WINAPI NtWriteVirtualMemoryHook(
  const void *pRetAddr,
  DWORD dwOrdinal,
  HANDLE ProcessHandle,
  PVOID BaseAddress,
  PVOID Buffer,
  ULONG NumberOfBytesToWrite,
  PULONG NumberOfBytesWritten
  )
{
  BOOL bSpyBlocked = IsSpyBlocked();

  // Блокировка мониторинга
  BlockSpy();

  if (!bSpyBlocked)
  {
    // Запись в файл отчета информации о вызове функции
    LogProcCallIn(L"NtWriteVirtualMemory", pRetAddr,
                  L"ProcessHandle=%p, " \
                  L"BaseAddress=%p, " \
                  L"Buffer=%p, " \
                  L"NumberOfBytesToWrite=%lu",
                  ProcessHandle,
                  BaseAddress,
                  Buffer,
                  NumberOfBytesToWrite);

    if (ProcessHandle == g_targetInfo.hTargetProcess)
    {
      // Запись данных в файл
      unsigned int res = WriteDataToFile(Buffer, NumberOfBytesToWrite,
                                         _T("%swvm_%p_%p_%p_%lu.dmp"),
                                         g_szOutDirPath,
                                         ProcessHandle, BaseAddress, Buffer,
                                         NumberOfBytesToWrite);
      if (res != ERROR_SUCCESS)
      {
        LogFmtW(L"Error: Failed to save memory block %p (%u).",
                Buffer, res);
      }
    }
 }

  NTSTATUS res;

  ULONG ulBytesWritten;

  // Вызов оригинальной функции "NtWriteVirtualMemory"
  res = ((PFNCallNtWriteVirtualMemory)&CallSysCall)(dwOrdinal,
                                                    ProcessHandle,
                                                    BaseAddress,
                                                    Buffer,
                                                    NumberOfBytesToWrite,
                                                    &ulBytesWritten);

  if (!bSpyBlocked)
  {
    // Запись в файл отчета информации о результатах вызова функции
    LogProcCallOut(L"NtWriteVirtualMemory", pRetAddr, res, RETVAL_NTSTATUS,
                   L"NumberOfBytesWritten=%lu",
                   ulBytesWritten);
  }

  // Разблокировка мониторинга
  UnblockSpy();

  if (NumberOfBytesWritten)
    *NumberOfBytesWritten = ulBytesWritten;
  return res;
}
/***************************************************************************/
/* NtProtectVirtualMemoryHook - Функция перехвата "NtProtectVirtualMemory" */
/***************************************************************************/
NTSTATUS WINAPI NtProtectVirtualMemoryHook(
  const void *pRetAddr,
  DWORD dwOrdinal,
  HANDLE ProcessHandle,
  PVOID *BaseAddress,
  PULONG NumberOfBytesToProtect,
  ULONG NewAccessProtection,
  PULONG OldAccessProtection
  )
{
  BOOL bSpyBlocked = IsSpyBlocked();

  // Блокировка мониторинга
  BlockSpy();

  if (!bSpyBlocked)
  {
    // Запись в файл отчета информации о вызове функции
    LogProcCallIn(L"NtProtectVirtualMemory", pRetAddr,
                  L"ProcessHandle=%p, " \
                  L"BaseAddress=%p, " \
                  L"NumberOfBytesToProtect=%lu, " \
                  L"NewAccessProtection=%08lX",
                  ProcessHandle,
                  BaseAddress ? *BaseAddress : (PVOID)0,
                  NumberOfBytesToProtect ? *NumberOfBytesToProtect : 0UL,
                  NewAccessProtection);

    if ((ProcessHandle == (HANDLE)-1) &&
        BaseAddress && (*BaseAddress == g_targetInfo.pBaseAddress))
    {
      // Сохранение выделенных блоков памяти в файлы
      WriteMemBlocksToFiles(&g_targetInfo.allocMemList, _T("pvm"));
    }
  }

  NTSTATUS res;

  // Вызов оригинальной функции "NtProtectVirtualMemory"
  res = ((PFNCallNtProtectVirtualMemory)&CallSysCall)(dwOrdinal,
                                                      ProcessHandle,
                                                      BaseAddress,
                                                      NumberOfBytesToProtect,
                                                      NewAccessProtection,
                                                      OldAccessProtection);

  if (!bSpyBlocked)
  {
    // Запись в файл отчета информации о результатах вызова функции
    LogProcCallOut(L"NtProtectVirtualMemory", pRetAddr, res, RETVAL_NTSTATUS,
                   L"BaseAddress=%p, " \
                   L"NumberOfBytesToProtect=%lu, " \
                   L"OldAccessProtection=%08lX)",
                   BaseAddress ? *BaseAddress : (PVOID)0,
                   NumberOfBytesToProtect ? *NumberOfBytesToProtect : 0UL,
                   OldAccessProtection ? *OldAccessProtection : 0UL);
  }

  // Разблокировка мониторинга
  UnblockSpy();

  return res;
}
/***************************************************************************/
/* NtCreateSectionHook - Функция перехвата "NtCreateSection"               */
/***************************************************************************/
NTSTATUS WINAPI NtCreateSectionHook(
  const void *pRetAddr,
  DWORD dwOrdinal,
  PHANDLE SectionHandle,
  ULONG DesiredAccess,
  POBJECT_ATTRIBUTES ObjectAttributes,
  PLARGE_INTEGER MaximumSize,
  ULONG SectionPageProtection,
  ULONG AllocationAttributes,
  HANDLE FileHandle
  )
{
  BOOL bSpyBlocked = IsSpyBlocked();

  // Блокировка мониторинга
  BlockSpy();

  if (!bSpyBlocked)
  {
    // Запись в файл отчета информации о вызове функции
    LogProcCallIn(L"NtCreateSection", pRetAddr,
                  L"DesiredAccess=%08lX, " \
                  L"MaximumSize=%IX, " \
                  L"SectionPageProtection=%08lX, " \
                  L"AllocationAttributes=%08lX, " \
                  L"FileHandle=%p",
                  DesiredAccess,
                  (unsigned __int64)(MaximumSize ? MaximumSize->QuadPart
                                                 : 0i64),
                  SectionPageProtection,
                  AllocationAttributes,
                  FileHandle);
  }

  NTSTATUS res;

  // Вызов оригинальной функции "NtCreateSection"
  res = ((PFNCallNtCreateSection)&CallSysCall)(dwOrdinal,
                                               SectionHandle,
                                               DesiredAccess,
                                               ObjectAttributes,
                                               MaximumSize,
                                               SectionPageProtection,
                                               AllocationAttributes,
                                               FileHandle);

  if (!bSpyBlocked)
  {
    // Запись в файл отчета информации о результатах вызова функции
    LogProcCallOut(L"NtCreateSection", pRetAddr, res, RETVAL_NTSTATUS,
                   L"SectionHandle=%p",
                   SectionHandle ? *SectionHandle : (HANDLE)0);
  }

  // Разблокировка мониторинга
  UnblockSpy();

  return res;
}
/***************************************************************************/
/* NtMapViewOfSectionHook - Функция перехвата "NtMapViewOfSection"         */
/***************************************************************************/
NTSTATUS WINAPI NtMapViewOfSectionHook(
  const void *pRetAddr,
  DWORD dwOrdinal,
  HANDLE SectionHandle,
  HANDLE ProcessHandle,
  PVOID *BaseAddress,
  ULONG_PTR ZeroBits,
  SIZE_T CommitSize,
  PLARGE_INTEGER SectionOffset,
  PSIZE_T ViewSize,
  unsigned int InheritDisposition,
  ULONG AllocationType,
  ULONG Win32Protect
  )
{
  BOOL bSpyBlocked = IsSpyBlocked();

  // Блокировка мониторинга
  BlockSpy();

  if (!bSpyBlocked)
  {
    // Запись в файл отчета информации о вызове функции
    LogProcCallIn(L"NtMapViewOfSection", pRetAddr,
                  L"SectionHandle=%p, " \
                  L"ProcessHandle=%p, " \
                  L"BaseAddress=%p, " \
                  L"CommitSize=%u, " \
                  L"SectionOffset=%IX, " \
                  L"ViewSize=%u, " \
                  L"AllocationType=%08lX",
                  SectionHandle,
                  ProcessHandle,
                  BaseAddress ? *BaseAddress : (PVOID)0,
                  (unsigned int)CommitSize,
                  (unsigned __int64)(SectionOffset ? SectionOffset->QuadPart
                                                   : 0i64),
                  (unsigned int)(ViewSize ? *ViewSize : (SIZE_T)0),
                  AllocationType);
  }

  NTSTATUS res;

  // Вызов оригинальной функции "NtMapViewOfSection"
  res = ((PFNCallNtMapViewOfSection)&CallSysCall)(dwOrdinal,
                                                  SectionHandle,
                                                  ProcessHandle,
                                                  BaseAddress,
                                                  ZeroBits,
                                                  CommitSize,
                                                  SectionOffset,
                                                  ViewSize,
                                                  InheritDisposition,
                                                  AllocationType,
                                                  Win32Protect);

  if (!bSpyBlocked)
  {
    PVOID pBaseAddress = BaseAddress ? *BaseAddress : (PVOID)0;

    if ((res == 0) &&
        (ProcessHandle == (HANDLE)-1) &&
        !(AllocationType & MEM_RESERVE) &&
        pBaseAddress &&
        (CommitSize > MIN_MEM_LIST_BLOCK_SIZE))
    {
      // Добавление блока памяти в список
      MemList_Add(&g_targetInfo.allocMemList, pBaseAddress, CommitSize);
    }

    // Запись в файл отчета информации о результатах вызова функции
    LogProcCallOut(L"NtMapViewOfSection", pRetAddr, res, RETVAL_NTSTATUS,
                   L"BaseAddress=%p, " \
                   L"SectionOffset=%IX, " \
                   L"ViewSize=%u",
                   pBaseAddress,
                   (unsigned __int64)(SectionOffset ? SectionOffset->QuadPart
                                                    : 0i64),
                   (unsigned int)(ViewSize ? *ViewSize : (SIZE_T)0));
  }

  // Разблокировка мониторинга
  UnblockSpy();

  return res;
}
/***************************************************************************/
/* NtUnmapViewOfSectionHook - Функция перехвата "NtUnmapViewOfSection"     */
/***************************************************************************/
NTSTATUS WINAPI NtUnmapViewOfSectionHook(
  const void *pRetAddr,
  DWORD dwOrdinal,
  HANDLE ProcessHandle,
  PVOID BaseAddress
  )
{
  BOOL bSpyBlocked = IsSpyBlocked();

  // Блокировка мониторинга
  BlockSpy();

  if (!bSpyBlocked)
  {
    // Запись в файл отчета информации о вызове функции
    LogProcCallIn(L"NtUnmapViewOfSection", pRetAddr,
                  L"ProcessHandle=%p, " \
                  L"BaseAddress=%p",
                  ProcessHandle,
                  BaseAddress);
  }

  NTSTATUS res;

  // Вызов оригинальной функции "NtUnmapViewOfSection"
  res = ((PFNCallNtUnmapViewOfSection)&CallSysCall)(dwOrdinal,
                                                    ProcessHandle,
                                                    BaseAddress);

  if (!bSpyBlocked)
  {
    if ((res == 0) &&
        (ProcessHandle == (HANDLE)-1) &&
        BaseAddress)
    {
      // Удаление блока памяти из списка
      MemList_Del(&g_targetInfo.allocMemList, BaseAddress);
    }

    // Запись в файл отчета информации о результатах вызова функции
    LogProcCallOut(L"NtUnmapViewOfSection", pRetAddr, res, RETVAL_NTSTATUS,
                   NULL);
  }

  // Разблокировка мониторинга
  UnblockSpy();

  return res;
}
/***************************************************************************/
/* NtCreateUserProcessHook - Функция перехвата "NtCreateUserProcess"       */
/***************************************************************************/
NTSTATUS WINAPI NtCreateUserProcessHook(
  const void *pRetAddr,
  DWORD dwOrdinal,
  PHANDLE ProcessHandle,
  PHANDLE ThreadHandle,
  ULONG ProcessDesiredAccess,
  ULONG ThreadDesiredAccess,
  POBJECT_ATTRIBUTES ProcessObjectAttributes,
  POBJECT_ATTRIBUTES ThreadObjectAttributes,
  ULONG ProcessFlags,
  ULONG ThreadFlags,
  PVOID ProcessParameters,
  PVOID CreateInfo,
  PVOID AttributeList
  )
{
  BOOL bSpyBlocked = IsSpyBlocked();

  // Блокировка мониторинга
  BlockSpy();

  if (!bSpyBlocked)
  {
    // Запись в файл отчета информации о вызове функции
    wchar_t szImagePathName[MAX_PATH];
    wchar_t szCommandLine[512];
    szImagePathName[0] = L'\0';
    szCommandLine[0] = L'\0';
    if (ProcessParameters)
    {
      PUNICODE_STRING pstr;
      pstr = (PUNICODE_STRING)((INT_PTR)ProcessParameters +
                               (16 * sizeof(BYTE) + 10 * sizeof(PVOID)));
      // RTL_USER_PROCESS_PARAMETERS::ImagePathName
      CopyUnicodeString(szImagePathName, countof(szImagePathName), pstr);
      pstr++;
      // RTL_USER_PROCESS_PARAMETERS::CommandLine
      CopyUnicodeString(szCommandLine, countof(szCommandLine), pstr);
    }
    LogProcCallIn(L"NtCreateUserProcess", pRetAddr,
                  L"ProcessFlags=%08lX, " \
                  L"ThreadFlags=%08lX, " \
                  L"ImagePathName=\"%s\", " \
                  L"CommandLine=\"%s\"",
                  ProcessFlags,
                  ThreadFlags,
                  szImagePathName,
                  szCommandLine);
  }

  NTSTATUS res;

  // Вызов оригинальной функции "NtCreateUserProcess"
  res = ((PFNCallNtCreateUserProcess)&CallSysCall)(dwOrdinal,
                                                   ProcessHandle,
                                                   ThreadHandle,
                                                   ProcessDesiredAccess,
                                                   ThreadDesiredAccess,
                                                   ProcessObjectAttributes,
                                                   ThreadObjectAttributes,
                                                   ProcessFlags,
                                                   ThreadFlags,
                                                   ProcessParameters,
                                                   CreateInfo,
                                                   AttributeList);

  if (!bSpyBlocked)
  {
    if (res == 0)
    {
      if (ThreadFlags & 1 /* THREAD_CREATE_FLAGS_CREATE_SUSPENDED */)
      {
        if (ProcessHandle && ThreadHandle)
        {
          g_targetInfo.hTargetProcess = *ProcessHandle;
          g_targetInfo.hTargetThread = *ThreadHandle;
        }
      }
    }

    // Запись в файл отчета информации о результатах вызова функции
    LogProcCallOut(L"NtCreateUserProcess", pRetAddr, res, RETVAL_NTSTATUS,
                   L"ProcessHandle=%p, " \
                   L"ThreadHandle=%p",
                   ProcessHandle ? *ProcessHandle : (PVOID)0,
                   ThreadHandle ? *ThreadHandle : (PVOID)0);
  }

  // Разблокировка мониторинга
  UnblockSpy();

  return res;
}
/***************************************************************************/
/* NtTerminateProcessHook - Функция перехвата "NtTerminateProcess"         */
/***************************************************************************/
NTSTATUS WINAPI NtTerminateProcessHook(
  const void *pRetAddr,
  DWORD dwOrdinal,
  HANDLE ProcessHandle,
  NTSTATUS ExitStatus
  )
{
  NTSTATUS res;

  BOOL bSpyBlocked = IsSpyBlocked();

  // Блокировка мониторинга
  BlockSpy();

  if (!bSpyBlocked)
  {
    if (!ProcessHandle || (ProcessHandle == (HANDLE)-1))
    {
      if (g_targetInfo.hTargetProcess)
      {
        // Завершение запущенного целевого процесса путем вызова оригинальной
        // функции "NtTerminateProcess"
        HANDLE hProcess = g_targetInfo.hTargetProcess;
        res = ((PFNCallNtTerminateProcess)&CallSysCall)(dwOrdinal,
                                                        hProcess,
                                                        ExitStatus);
        g_targetInfo.hTargetProcess = NULL;
        g_targetInfo.hTargetThread = NULL;
        if (res == 0)
        {
          LogFmtW(L"Process (ProcessHandle=%p) terminated.", hProcess);
        }
      }
      // Деинициализация
      Uninit();
    }
    else
    {
      // Запись в файл отчета информации о вызове функции
      LogProcCallIn(L"NtTerminateProcess", pRetAddr,
                    L"ProcessHandle=%p, " \
                    L"ExitStatus=%08X",
                    ProcessHandle,
                    (unsigned int)ExitStatus);
    }
  }

  // Вызов оригинальной функции "NtTerminateProcess"
  res = ((PFNCallNtTerminateProcess)&CallSysCall)(dwOrdinal,
                                                  ProcessHandle,
                                                  ExitStatus);

  if (!bSpyBlocked)
  {
    if (ProcessHandle && (ProcessHandle != (HANDLE)-1))
    {
      // Запись в файл отчета информации о результатах вызова функции
      LogProcCallOut(L"NtTerminateProcess", pRetAddr, res, RETVAL_NTSTATUS,
                     NULL);
    }
  }

  // Разблокировка мониторинга
  UnblockSpy();

  return res;
}
//---------------------------------------------------------------------------
/***************************************************************************/
/* IsSpyBlocked - Проверка блокировки мониторинга                          */
/***************************************************************************/
BOOL IsSpyBlocked()
{
  return (g_ulSpyBlockCount != 0);
}
/***************************************************************************/
/* BlockSpy - Блокировка мониторинга                                       */
/***************************************************************************/
void BlockSpy()
{
  _InterlockedIncrement((LONG *)&g_ulSpyBlockCount);
}
/***************************************************************************/
/* UnblockSpy - Разблокировка мониторинга                                  */
/***************************************************************************/
void UnblockSpy()
{
  if (g_ulSpyBlockCount != 0)
    _InterlockedDecrement((LONG *)&g_ulSpyBlockCount);
}
/***************************************************************************/
/* CopyUnicodeString - Копирование строки UNICODE_STRING                   */
/***************************************************************************/
unsigned int CopyUnicodeString(
  wchar_t *pBuffer,
  unsigned int nSize,
  const UNICODE_STRING *pUnicodeStr
  )
{
  if (!pBuffer || (nSize == 0) || !pUnicodeStr)
    return 0;
  unsigned int cchStr = pUnicodeStr->Length / sizeof(WCHAR);
  unsigned int cchCopy = min(cchStr, nSize - 1);
  if (cchCopy != 0)
    CopyMem(pBuffer, pUnicodeStr->Buffer, cchCopy * sizeof(WCHAR));
  pBuffer[cchCopy] = L'\0';
  return cchStr;
}
/***************************************************************************/
/* GetProcInfoStr - Получение строки с информацией о вызове функции        */
/***************************************************************************/
unsigned int GetProcCallStr(
  const wchar_t *pszProcName,
  const void *pRetAddr,
  BOOL bInOrOut,
  wchar_t *pBuffer
  )
{
  wchar_t szModuleName[MAX_PATH];

  szModuleName[0] = L'\0';

  // Получение имени модуля по адресу
  const UNICODE_STRING *pModuleNameStr = GetModuleNameByAddress(pRetAddr);
  if (pModuleNameStr)
  {
    // Копирование строки UNICODE_STRING
    CopyUnicodeString(szModuleName, countof(szModuleName), pModuleNameStr);
    wchar_t *p = StrRCharW(szModuleName, L'.');
    if (p)
    {
      if (p == szModuleName)
        p++;
      *p = L'\0';
    }
  }

  return ::wsprintfW(pBuffer, L"%s.%p\t%s\t%s",
                     szModuleName[0] ? szModuleName : L"UNKNOWN",
                     pRetAddr,
                     bInOrOut ? L"IN" : L"OUT",
                     pszProcName);
}
/***************************************************************************/
/* LogProcCallIn - Запись в файл отчета информации о вызове функции        */
/***************************************************************************/
unsigned int LogProcCallIn(
  const wchar_t *pszProcName,
  const void *pRetAddr,
  const wchar_t *pszArgFmt,
  ...
  )
{
  wchar_t buf[PROC_CALL_INFO_BUFFER_SIZE];

  wchar_t *p = buf;
  unsigned int cch;

  // Получение строки с информацией о вызове функции
  cch = GetProcCallStr(pszProcName, pRetAddr, TRUE, p);
  p += cch;

  // Добавление строки с информацией об аргументах функции
  *p++ = L'(';
  if (pszArgFmt && pszArgFmt[0])
  {
    va_list arglist;
    va_start(arglist, pszArgFmt);
    cch = ::wvsprintfW(p, pszArgFmt, arglist);
    va_end(arglist);
    p += cch;
  }
  *p++ = L')';

  // Запись текста в файл отчета
  return LogW(buf, (unsigned int)(p - buf));
}
/***************************************************************************/
/* LogProcCallOut - Запись в файл отчета информации о результатах вызова   */
/*                  функции                                                */
/***************************************************************************/
unsigned int LogProcCallOut(
  const wchar_t *pszProcName,
  const void *pRetAddr,
  unsigned int nRetVal,
  RETVAL_TYPE retValType,
  const wchar_t *pszArgFmt,
  ...
  )
{
  wchar_t buf[PROC_CALL_INFO_BUFFER_SIZE];

  wchar_t *p = buf;
  unsigned int cch;

  // Получение строки с информацией о вызове функции
  cch = GetProcCallStr(pszProcName, pRetAddr, FALSE, p);
  p += cch;
  *p++ = L' ';

  // Добавление возвращенного функцией значения
  *p++ = L'(';
  if (retValType == RETVAL_BOOL)
  {
    const wchar_t *pszBoolRetVal;
    if (nRetVal != 0)
    {
      pszBoolRetVal = L"TRUE";
      cch = countof(L"TRUE") - 1;
    }
    else
    {
      pszBoolRetVal = L"FALSE";
      cch = countof(L"FALSE") - 1;
    }
    CopyMem(p, pszBoolRetVal, cch * sizeof(wchar_t));
  }
  else
  {
    cch = ::wsprintfW(p, (retValType == RETVAL_NTSTATUS) ? L"%08X" : L"%u",
                      nRetVal);
  }
  p += cch;
  *p++ = L')';

  if (pszArgFmt && pszArgFmt[0])
  {
    *p++ = L':';
    *p++ = L' ';

    // Добавление форматированной строки с информацией об аргументах функции
    va_list arglist;
    va_start(arglist, pszArgFmt);
    cch = ::wvsprintfW(p, pszArgFmt, arglist);
    va_end(arglist);
    p += cch;
  }

  // Запись текста в файл отчета
  return LogW(buf, (unsigned int)(p - buf));
}
//---------------------------------------------------------------------------
