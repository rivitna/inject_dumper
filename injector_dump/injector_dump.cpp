//---------------------------------------------------------------------------
#define WIN32_LEAN_AND_MEAN  // Exclude rarely-used stuff from Windows headers
#include <windows.h>
#include <stdio.h>
#include <io.h>
#include <fcntl.h>
#include <tchar.h>
#include "StdUtils.h"
#include "ProcInj.h"
#include "PEFile.h"
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

  const TCHAR *pszAppName = argv[0];

  if (argc < 2)
  {
    _tprintf_s(_T("Usage: %s appname [arguments]\n") \
               _T("\n") \
               _T("WARNING! This program must be run in VM.\n") \
               _T("\n"),
               GetFileName(pszAppName));
    return 0;
  }

  const TCHAR *pszFileName = argv[1];

  if (::GetFileAttributes(pszFileName) & FILE_ATTRIBUTE_DIRECTORY)
  {
    _tprintf_s(_T("Error: File '%s' not found.\n"), pszFileName);
    return 1;
  }

  // Детектирование PE-файла
  unsigned long peType = DetectPEFile(pszFileName);

  // Извлечение динамической библиотеки перехвата
  if (!DropBinaryFile(HOOKDLL_FILENAME))
  {
    _tprintf_s(_T("Error: Failed to extract hook dll.\n"));
    return 1;
  }

  // Получение командной строки
  TCHAR *pszCmdLine = NULL;
  if (argc >= 3)
  {
    TCHAR *pCmdLine = ::GetCommandLine();
    TCHAR *p = _tcsstr(pCmdLine, pszAppName);
    if (p)
    {
      unsigned int cch = ::lstrlen(pszAppName);
      if ((p > pCmdLine) && (p[-1] == _T('\"')) && (p[cch] == _T('\"')))
        p++;
      p += cch;
      while (isspace(*p)) p++;
      pszCmdLine = p;
    }
  }

  _tprintf_s(_T("File: \"%s\"\n"), GetFileName(pszFileName));
  if (pszCmdLine)
    _tprintf_s(_T("Command line: \"%s\"\n"), pszCmdLine);

  // Запуск процесса и внедрение в него DLL
  BOOL bUseRemoteThread = FALSE;
  if ((peType != PE_FILE_ERROR) && (peType & PE_FILE_DOTNET))
    bUseRemoteThread = TRUE;
  BOOL bSuccess = CreateProcessAndInjectDll(pszFileName, pszCmdLine,
                                            HOOKDLL_FILENAME,
                                            bUseRemoteThread, TRUE);

  _tprintf_s(_T("Status: %s\n"), bSuccess ? _T("OK") : _T("Failed"));

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
