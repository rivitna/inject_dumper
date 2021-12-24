//---------------------------------------------------------------------------
#define WIN32_LEAN_AND_MEAN  // Exclude rarely-used stuff from Windows headers
#include <windows.h>
#include <tchar.h>
#include "StdUtils.h"
#include "Log.h"
//---------------------------------------------------------------------------
// Размер буфера
#define BUFFER_SIZE  1024
//---------------------------------------------------------------------------
// Дескриптор файла отчета
HANDLE g_hLogFile;
// Критическая секция блокировки вывода в файл отчета
CRITICAL_SECTION g_csLogLock;
//---------------------------------------------------------------------------
/***************************************************************************/
/* OpenLog - Открытие файла отчета                                         */
/***************************************************************************/
BOOL OpenLog(
  const TCHAR *pszLogPath,
  BOOL bAppend
  )
{
  g_hLogFile = INVALID_HANDLE_VALUE;

  if (!pszLogPath || !pszLogPath[0])
    return FALSE;

  HANDLE hLogFile;

  // Создание файла отчета
  hLogFile = ::CreateFile(pszLogPath,
                          bAppend ? (GENERIC_READ | GENERIC_WRITE)
                                  : GENERIC_WRITE,
                          FILE_SHARE_READ,
                          NULL,
                          bAppend ? OPEN_ALWAYS : CREATE_ALWAYS,
                          FILE_FLAG_SEQUENTIAL_SCAN,
                          NULL);
  if (hLogFile == INVALID_HANDLE_VALUE)
    return FALSE;

  BOOL bError = FALSE;

  DWORD dwPos;

  if (bAppend)
  {
    // Перемещение указателя файла в конец
    dwPos = ::SetFilePointer(hLogFile, 0, NULL, FILE_END);
    if (dwPos == INVALID_SET_FILE_POINTER)
      bError = TRUE;
  }
  else
  {
    dwPos = 0;
  }

  if (dwPos == 0)
  {
    // Добавление BOM в начало файла
    unsigned char bom[3];
    bom[0] = 0xEF;
    bom[1] = 0xBB;
    bom[2] = 0xBF;
    DWORD dwBytesWritten;
    if (!::WriteFile(hLogFile, bom, sizeof(bom), &dwBytesWritten, NULL) ||
        (dwBytesWritten != sizeof(bom)))
      bError = TRUE;
  }

  if (bError)
  {
    ::CloseHandle(hLogFile);
    return FALSE;
  }

  // Инициализация критической секции блокировки записи в файл отчет
  ::InitializeCriticalSection(&g_csLogLock);

  g_hLogFile = hLogFile;

  return TRUE;
}
/***************************************************************************/
/* CloseLog - Закрытие файла отчета                                         */
/***************************************************************************/
void CloseLog()
{
  if (g_hLogFile == INVALID_HANDLE_VALUE)
    return;

  // Уничтожение критической секции блокировки записи в файл отчета
  ::DeleteCriticalSection(&g_csLogLock);

  ::CloseHandle(g_hLogFile);

  g_hLogFile = INVALID_HANDLE_VALUE;
}
/***************************************************************************/
/* WriteLog - Запись в файл отчета                                         */
/***************************************************************************/
unsigned int WriteLog(
  const char *pchText,
  unsigned int cbText
  )
{
  if ((g_hLogFile == INVALID_HANDLE_VALUE) ||
      !pchText || (cbText == 0))
    return 0;

  unsigned int nRet = 0;

  ::EnterCriticalSection(&g_csLogLock);

  DWORD dwBytesWritten;
  if (::WriteFile(g_hLogFile, pchText, (DWORD)cbText, &dwBytesWritten, NULL))
    nRet = dwBytesWritten;

  ::LeaveCriticalSection(&g_csLogLock);

  return nRet;
}
/***************************************************************************/
/* LogW - Запись текста в файл отчета                                      */
/***************************************************************************/
unsigned int LogW(
  const wchar_t *pchText,
  unsigned int cchText
  )
{
  if ((g_hLogFile == INVALID_HANDLE_VALUE) ||
      !pchText)
    return 0;

  if (cchText == 0)
    cchText = ::lstrlenW(pchText);

  if (cchText == 0)
    return 0;

  BOOL bAddNewLine = FALSE;
  if (pchText[cchText - 1] != L'\n')
  {
    if (cchText == 1)
      return 0;
    bAddNewLine = TRUE;
  }

  char buf[BUFFER_SIZE];
  char *pchBuf = buf;
  unsigned int nBufSize = sizeof(buf);
  unsigned int cb;

  cb = ::WideCharToMultiByte(CP_UTF8, 0, pchText, cchText, NULL, 0, NULL,
                             NULL);
  if (bAddNewLine)
    cb += 2;
  if (cb > sizeof(buf))
  {
    pchBuf = (char *)AllocMem(cb);
    if (!pchBuf)
      return 0;
    nBufSize = cb;
  }

  unsigned int nRet = 0;

  cb = ::WideCharToMultiByte(CP_UTF8, 0, pchText, cchText, pchBuf, nBufSize,
                             NULL, NULL);
  if (cb != 0)
  {
    // Запись в файл отчета
    if (bAddNewLine)
    {
      pchBuf[cb] = '\r';
      pchBuf[cb + 1] = '\n';
      cb += 2;
    }
    nRet = WriteLog(pchBuf, cb);
  }

  if (pchBuf != buf)
    FreeMem(pchBuf);

  return nRet;
}
/***************************************************************************/
/* LogFmtW - Запись форматированного текста в файл отчета                  */
/***************************************************************************/
unsigned int LogFmtW(
  const wchar_t *pszFormat,
  ...
  )
{
  wchar_t buf[BUFFER_SIZE];
  unsigned int cch;
  va_list arglist;
  va_start(arglist, pszFormat);
  cch = ::wvsprintfW(buf, pszFormat, arglist);
  va_end(arglist);
  // Запись текста в файл отчета
  return LogW(buf, cch);
}
//---------------------------------------------------------------------------
