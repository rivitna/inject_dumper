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
// ��� ����� ������
const TCHAR LOG_FILE_NAME[] = _T("log.txt");
//---------------------------------------------------------------------------
// ��� ������ ������������ ������������� ������� InternetCrackUrlW
BOOL (WINAPI *g_pfnInternetCrackUrlWThunk)(
  LPCWSTR lpszUrl,
  DWORD dwUrlLength,
  DWORD dwFlags,
  LPURL_COMPONENTSW lpUrlComponents
  );

// ���� �������� �� ������ ������������ ������� API
void *g_pOrigFuncThunks;

// ���������� ���������� WinInet
HMODULE g_hWinInetLib;

// ���������� ����������
HMODULE g_hDllHandle;
//---------------------------------------------------------------------------
// �������������
BOOL Init();
// ���������������
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
      // ������ ������� � ������������� DLL_THREAD_ATTACH � DLL_THREAD_DETACH
      ::DisableThreadLibraryCalls(hinstDLL);
      // �������������
      if (!Init())
        return FALSE;
      break;

    case DLL_PROCESS_DETACH:
      // ���������������
      Uninit();
      break;
  }
  return TRUE;
}
//---------------------------------------------------------------------------
/***************************************************************************/
/* MyInternetCrackUrlW - ������� ��������� "InternetCrackUrlW"             */
/***************************************************************************/
BOOL WINAPI MyInternetCrackUrlW(
  LPCWSTR lpszUrl,
  DWORD dwUrlLength,
  DWORD dwFlags,
  LPURL_COMPONENTSW lpUrlComponents
  )
{
  // ������ ������ � ���� ������
  LogW(lpszUrl, dwUrlLength);

  return g_pfnInternetCrackUrlWThunk(lpszUrl, dwUrlLength, dwFlags,
                                     lpUrlComponents);
}
/***************************************************************************/
/* MyInternetConnectW - ������� ��������� "InternetConnectW"               */
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
/* Init - �������������                                                    */
/***************************************************************************/
BOOL Init()
{
  g_pOrigFuncThunks = NULL;
  g_hWinInetLib = NULL;

  TCHAR szLogPath[MAX_PATH];
  unsigned int cch;

  // ��������� ���� � ������������ ����������
  cch = ::GetModuleFileName(g_hDllHandle, szLogPath, countof(szLogPath));
  if ((cch == 0) || (cch >= countof(szLogPath)))
    return FALSE;

  // ��������� ���� � ����� ������
  TCHAR *pName = GetFileName(szLogPath);
  if (pName - szLogPath > countof(szLogPath) - countof(LOG_FILE_NAME))
    return FALSE;
  CopyMem(pName, LOG_FILE_NAME, sizeof(LOG_FILE_NAME));

  // �������� ���������� WinInet
  HMODULE hWinInetLib = ::LoadLibrary(_T("WININET.DLL"));
  if (!hWinInetLib)
    return FALSE;

  BOOL bSuccess = FALSE;

  // ��������� ������ ��� ����� �������� �� ������ ������������ ������� API
  void *pThunks = ::VirtualAlloc(NULL, MAX_THUNK_CODE_SIZE,
                                 MEM_RESERVE | MEM_COMMIT,
                                 PAGE_EXECUTE_READWRITE);
  if (pThunks)
  {
    // �������� ������� WinInet API "InternetCrackUrlW", "InternetConnectW"
    *(void **)&g_pfnInternetCrackUrlWThunk = pThunks;
    if (HookAPIFunc(hWinInetLib, "InternetCrackUrlW", &MyInternetCrackUrlW,
                    g_pfnInternetCrackUrlWThunk) &&
        HookAPIFunc(hWinInetLib, "InternetConnectW", &MyInternetConnectW,
                    NULL))
    {
      // �������� ����� ������
      if (OpenLog(szLogPath, TRUE))
        bSuccess = TRUE;
    }
  }

  if (!bSuccess)
  {
    // �������� ����� ������
    CloseLog();
    // ������������ ������, ���������� ��� ����� �������� �� ������
    // ������������ ������� API
    if (pThunks)
      ::VirtualFree(pThunks, 0, MEM_RELEASE);
    // ������������ ���������� WinInet
    ::FreeLibrary(hWinInetLib);
    return FALSE;
  }

  g_pOrigFuncThunks = pThunks;
  g_hWinInetLib = hWinInetLib;

  // ������ � ���� ������ ����� �������
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
/* Uninit - ���������������                                                */
/***************************************************************************/
void Uninit()
{
  // �������� ����� ������
  CloseLog();

  // ������������ ������, ���������� ��� ����� �������� �� ������
  // ������������ ������� API
  if (g_pOrigFuncThunks)
    ::VirtualFree(g_pOrigFuncThunks, 0, MEM_RELEASE);

  // ������������ ���������� WinInet
  if (g_hWinInetLib)
    ::FreeLibrary(g_hWinInetLib);
}
//---------------------------------------------------------------------------
