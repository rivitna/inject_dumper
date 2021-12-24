//---------------------------------------------------------------------------
#define WIN32_LEAN_AND_MEAN  // Exclude rarely-used stuff from Windows headers
#include <windows.h>
#include <stdio.h>
#include <io.h>
#include <fcntl.h>
#include <tchar.h>
#include "StdUtils.h"
#include "ProcInj.h"
#include "Resource.h"
//---------------------------------------------------------------------------
#ifndef countof
#define countof(a)  (sizeof(a)/sizeof(a[0]))
#endif  // countof
//---------------------------------------------------------------------------
#ifndef _DEBUG
#pragma comment(linker, "/MERGE:.rdata=.text")
#endif  // _DEBUG
//---------------------------------------------------------------------------
// Имя исполняемого файла "wscript.exe"
const TCHAR WSCRIPT_FILENAME[] = _T("wscript.exe");
// Имя библиотеки перехвата
const TCHAR HOOKDLL_FILENAME[] = _T("hookdll.dll");
//---------------------------------------------------------------------------
// Извлечение бинарного файла
BOOL DropBinaryFile(
  const TCHAR *pszFileName
  );
//---------------------------------------------------------------------------
/***************************************************************************/
/* main                                                                    */
/***************************************************************************/
int _tmain(int argc, TCHAR *argv[])
{
#ifdef _UNICODE
  _setmode(_fileno(stdout), _O_U16TEXT);
#endif  // _UNICODE

  if (argc < 2)
  {
    _tprintf_s(_T("Usage: %s scriptname\n") \
               _T("\n") \
               _T("WARNING! This program must be run in VM.\n") \
               _T("\n"),
               GetFileName(argv[0]));
    return 0;
  }

  const TCHAR *pszScriptName = argv[1];

  if (::GetFileAttributes(pszScriptName) & FILE_ATTRIBUTE_DIRECTORY)
  {
    _tprintf_s(_T("Error: File '%s' not found.\n"), pszScriptName);
    return 1;
  }

  TCHAR szWscriptPath[MAX_PATH];
  size_t cch = ::GetSystemDirectory(szWscriptPath, countof(szWscriptPath));
  if ((cch == 0) ||
      (cch >= countof(szWscriptPath) - countof(WSCRIPT_FILENAME)))
  {
    _tprintf_s(_T("Error: Could not get '%s' path.\n"), WSCRIPT_FILENAME);
    return 1;
  }
  szWscriptPath[cch] = _T('\\');
  memcpy(&szWscriptPath[cch + 1], WSCRIPT_FILENAME,
         sizeof(WSCRIPT_FILENAME));

  TCHAR szCmdLine[1024];
  szCmdLine[0] = _T('\0');
  _stprintf_s(szCmdLine, countof(szCmdLine), _T("\"%s\" \"%s\""),
              WSCRIPT_FILENAME, pszScriptName);
  if (!szCmdLine[0])
  {
    _tprintf_s(_T("Error: Script name is too long.\n"));
    return 1;
  }

  // Извлечение динамической библиотеки перехвата
  if (!DropBinaryFile(HOOKDLL_FILENAME))
  {
    _tprintf_s(_T("Error: Failed to extract hook dll.\n"));
    return 1;
  }

  _tprintf_s(_T("Script: '%s'.\n"), GetFileName(pszScriptName));

  // Запуск процесса и внедрение в него DLL
  BOOL bSuccess = CreateProcessAndInjectDll(szWscriptPath, szCmdLine,
                                            HOOKDLL_FILENAME, FALSE, TRUE);

  _tprintf_s(_T("Status: %s.\n"), bSuccess ? _T("OK") : _T("Failed"));

  // Удаление динамической библиотеки перехвата
  ::DeleteFile(HOOKDLL_FILENAME);

  if (bSuccess)
    return 0;
  return 1;
}
//---------------------------------------------------------------------------
/***************************************************************************/
/* WriteDataToFile - Запись данных в файл                                  */
/***************************************************************************/
BOOL WriteDataToFile(
  const TCHAR *pszFileName,
  const void *pData,
  unsigned int cbData
  )
{
  HANDLE hFile;

  hFile = ::CreateFile(pszFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                       FILE_FLAG_SEQUENTIAL_SCAN, NULL);
  if (hFile == INVALID_HANDLE_VALUE)
    return FALSE;

  BOOL bSuccess = FALSE;

  DWORD dwBytesWritten;
  if (::WriteFile(hFile, pData, cbData, &dwBytesWritten, NULL) &&
      (dwBytesWritten == cbData))
    bSuccess = TRUE;

  ::CloseHandle(hFile);

  if (!bSuccess)
  {
    // Удаление неудачно записанных данных
    ::DeleteFile(pszFileName);
    return FALSE;
  }
  return TRUE;
}
/***************************************************************************/
/* DropBinaryFile - Извлечение бинарного файла                             */
/***************************************************************************/
BOOL DropBinaryFile(
  const TCHAR *pszFileName
  )
{
  HRSRC hRes = ::FindResource(NULL, MAKEINTRESOURCE(ID_BINDATA),
                              MAKEINTRESOURCE(ID_BINARY_TYPE));
  if (!hRes)
    return FALSE;

  HGLOBAL hResData = ::LoadResource(NULL, hRes);
  if (!hResData)
    return FALSE;

  BOOL bSuccess = FALSE;

  LPVOID pResData = ::LockResource(hResData);
  if (pResData)
  {
    DWORD dwResSize = ::SizeofResource(NULL, hRes);
    if (dwResSize != 0)
    {
      // Запись данных в файл
      if (WriteDataToFile(pszFileName, pResData, dwResSize))
        bSuccess = TRUE;
    }
  }

  ::FreeResource(hResData);

  return bSuccess;
}
//---------------------------------------------------------------------------
