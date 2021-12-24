//---------------------------------------------------------------------------
#define WIN32_LEAN_AND_MEAN  // Exclude rarely-used stuff from Windows headers
#include <windows.h>
#include <shellapi.h>
#include <tchar.h>
#include <wininet.h>
#include <wininet.h>
#include "StdUtils.h"
#include "Log.h"
#include "HookAPI.h"
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
// Имя файла отчета
const TCHAR LOG_FILE_NAME[] = _T("log.txt");
//---------------------------------------------------------------------------
// Код вызова оригинальной перехваченной функции InternetCrackUrlW
BOOL (WINAPI *g_pfnInternetCrackUrlWThunk)(
  LPCWSTR lpszUrl,
  DWORD dwUrlLength,
  DWORD dwFlags,
  LPURL_COMPONENTSW lpUrlComponents
  );

// Коды перехода на адреса оригинальных функций API
void *g_pOrigFuncThunks;

// Дескриптор библиотеки WinInet
HMODULE g_hWinInetLib;

// Дескриптор библиотеки
HMODULE g_hDllHandle;
//---------------------------------------------------------------------------
// Инициализация
BOOL Init();
// Деинициализация
void Uninit();
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
//---------------------------------------------------------------------------
/***************************************************************************/
/* MyInternetCrackUrlW - Функция перехвата "InternetCrackUrlW"             */
/***************************************************************************/
BOOL WINAPI MyInternetCrackUrlW(
  LPCWSTR lpszUrl,
  DWORD dwUrlLength,
  DWORD dwFlags,
  LPURL_COMPONENTSW lpUrlComponents
  )
{
  // Запись ссылки в файл отчета
  LogW(lpszUrl, dwUrlLength);

  return g_pfnInternetCrackUrlWThunk(lpszUrl, dwUrlLength, dwFlags,
                                     lpUrlComponents);
}
/***************************************************************************/
/* MyInternetConnectW - Функция перехвата "InternetConnectW"               */
/***************************************************************************/
HINTERNET WINAPI MyInternetConnectW(
  HINTERNET hInternet,
  LPCWSTR lpszServerName,
  INTERNET_PORT nServerPort,
  LPCWSTR lpszUserName,
  LPCWSTR lpszPassword,
  DWORD dwService,
  DWORD dwFlags,
  DWORD_PTR dwContext
  )
{
  return (HINTERNET)0;
}
/***************************************************************************/
/* Init - Инициализация                                                    */
/***************************************************************************/
BOOL Init()
{
  g_pOrigFuncThunks = NULL;
  g_hWinInetLib = NULL;

  TCHAR szLogPath[MAX_PATH];
  unsigned int cch;

  // Получение пути к динамической библиотеке
  cch = ::GetModuleFileName(g_hDllHandle, szLogPath, countof(szLogPath));
  if ((cch == 0) || (cch >= countof(szLogPath)))
    return FALSE;

  // Получение пути к файлу отчета
  TCHAR *pName = GetFileName(szLogPath);
  if (pName - szLogPath > countof(szLogPath) - countof(LOG_FILE_NAME))
    return FALSE;
  CopyMem(pName, LOG_FILE_NAME, sizeof(LOG_FILE_NAME));

  // Загрузка библиотеки WinInet
  HMODULE hWinInetLib = ::LoadLibrary(_T("WININET.DLL"));
  if (!hWinInetLib)
    return FALSE;

  BOOL bSuccess = FALSE;

  // Выделение памяти для кодов перехода на адреса оригинальных функций API
  void *pThunks = ::VirtualAlloc(NULL, MAX_THUNK_CODE_SIZE,
                                 MEM_RESERVE | MEM_COMMIT,
                                 PAGE_EXECUTE_READWRITE);
  if (pThunks)
  {
    // Перехват функций WinInet API "InternetCrackUrlW", "InternetConnectW"
    *(void **)&g_pfnInternetCrackUrlWThunk = pThunks;
    if (HookAPIFunc(hWinInetLib, "InternetCrackUrlW", &MyInternetCrackUrlW,
                    g_pfnInternetCrackUrlWThunk) &&
        HookAPIFunc(hWinInetLib, "InternetConnectW", &MyInternetConnectW,
                    NULL))
    {
      // Открытие файла отчета
      if (OpenLog(szLogPath, TRUE))
        bSuccess = TRUE;
    }
  }

  if (!bSuccess)
  {
    // Закрытие файла отчета
    CloseLog();
    // Освобождение памяти, выделенной для кодов перехода на адреса
    // оригинальных функций API
    if (pThunks)
      ::VirtualFree(pThunks, 0, MEM_RELEASE);
    // Освобождение библиотеки WinInet
    ::FreeLibrary(hWinInetLib);
    return FALSE;
  }

  g_pOrigFuncThunks = pThunks;
  g_hWinInetLib = hWinInetLib;

  // Запись в файл отчета имени скрипта
  int wargc = 0;
  LPWSTR *wargv = ::CommandLineToArgvW(::GetCommandLineW(), &wargc);
  if (wargv)
  {
    if (wargc >= 2)
    {
      LogW(GetFileNameW(wargv[1]), 0);
    }
    ::LocalFree(wargv);
  }

  return TRUE;
}
/***************************************************************************/
/* Uninit - Деинициализация                                                */
/***************************************************************************/
void Uninit()
{
  // Закрытие файла отчета
  CloseLog();

  // Освобождение памяти, выделенной для кодов перехода на адреса
  // оригинальных функций API
  if (g_pOrigFuncThunks)
    ::VirtualFree(g_pOrigFuncThunks, 0, MEM_RELEASE);

  // Освобождение библиотеки WinInet
  if (g_hWinInetLib)
    ::FreeLibrary(g_hWinInetLib);
}
//---------------------------------------------------------------------------
