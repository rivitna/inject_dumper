//---------------------------------------------------------------------------
#define WIN32_LEAN_AND_MEAN  // Exclude rarely-used stuff from Windows headers
#include <windows.h>
#include <winnt.h>
#include <tchar.h>
#include "StdUtils.h"
#include "Dump.h"
//---------------------------------------------------------------------------
#ifndef offsetof
#define offsetof(type, field)  ((size_t)&(((type *)0)->field))
#endif  // offsetof
//---------------------------------------------------------------------------
// Максимальный размер пути к файлу
#define MAX_DUMP_PATH  1024
//---------------------------------------------------------------------------
/***************************************************************************/
/* WriteDataToFile - Запись данных в файл                                  */
/***************************************************************************/
unsigned int WriteDataToFile(
  const TCHAR *pszFileName,
  const void *pData,
  unsigned int cbData
  )
{
  HANDLE hFile;
  hFile = ::CreateFile(pszFileName, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                       CREATE_ALWAYS, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
  if (hFile == INVALID_HANDLE_VALUE)
    return (unsigned int)::GetLastError();

  unsigned int res = ERROR_SUCCESS;

  DWORD dwBytesWritten;
  if (!::WriteFile(hFile, pData, (DWORD)cbData, &dwBytesWritten, NULL))
  {
    res = ::GetLastError();
  }
  else if (dwBytesWritten != cbData)
  {
    res = ERROR_WRITE_FAULT;
  }

  ::CloseHandle(hFile);

  return res;
}
/***************************************************************************/
/* WriteDataToFile - Запись данных в файл                                  */
/***************************************************************************/
unsigned int WriteDataToFile(
  const void *pData,
  unsigned int cbData,
  const TCHAR *pszFileNameFormat,
  ...
  )
{
  TCHAR szFileName[MAX_DUMP_PATH];
  va_list arglist;
  va_start(arglist, pszFileNameFormat);
  ::wvsprintf(szFileName, pszFileNameFormat, arglist);
  va_end(arglist);

  // Запись данных в файл
  return WriteDataToFile(szFileName, pData, cbData);
}
/***************************************************************************/
/* WritePESectionToFile - Сохранение PE-секциио в файл                     */
/***************************************************************************/
unsigned int WritePESectionToFile(
  HANDLE hFile,
  HANDLE hProcess,
  INT_PTR pSection,
  unsigned int nVirtualSize,
  unsigned int nSizeOfRawData
  )
{
  if (nSizeOfRawData == 0)
    return ERROR_SUCCESS;

  // Выделение памяти для данных секции
  void *pSectionData = AllocArray(nSizeOfRawData, 1);
  if (!pSectionData)
    return ERROR_NOT_ENOUGH_MEMORY;

  unsigned int res = ERROR_SUCCESS;

  SIZE_T nBytesToRead = nSizeOfRawData;
  if (nBytesToRead > nVirtualSize)
    nBytesToRead = nVirtualSize;
  if (nBytesToRead != 0)
  {
    // Чтение данных секции
    SIZE_T nBytesRead;
    if (!::ReadProcessMemory(hProcess, (LPCVOID)pSection, pSectionData,
                             nBytesToRead, &nBytesRead))
    {
      res = ::GetLastError();
    }
    else if (nBytesRead != nBytesToRead)
    {
      res = ERROR_INVALID_DATA;
    }
  }

  if (res == ERROR_SUCCESS)
  {
    DWORD dwBytesWritten;
    if (!::WriteFile(hFile, pSectionData, (DWORD)nSizeOfRawData,
        &dwBytesWritten, NULL))
    {
      res = ::GetLastError();
    }
    else if (dwBytesWritten != (DWORD)nSizeOfRawData)
    {
      res = ERROR_WRITE_FAULT;
    }
  }

  FreeMem(pSectionData);

  return res;
}
/***************************************************************************/
/* WriteProcessModuleToFile - Сохранение исполняемого модуля процесса      */
/*                            в файл                                       */
/***************************************************************************/
unsigned int WriteProcessModuleToFile(
  const TCHAR *pszFileName,
  INT_PTR pBaseAddress,
  HANDLE hProcess
  )
{
  if (!pBaseAddress)
    return ERROR_INVALID_PARAMETER;

  SIZE_T nBytesRead;

  union
  {
    IMAGE_DOS_HEADER dosHdr;
    IMAGE_NT_HEADERS peHdr;
  };

  // Чтение DOS-заголовка
  if (!::ReadProcessMemory(hProcess, (LPCVOID)pBaseAddress, &dosHdr,
                           sizeof(dosHdr), &nBytesRead))
    return (unsigned int)::GetLastError();

  if ((nBytesRead != sizeof(dosHdr)) ||
      (dosHdr.e_magic != IMAGE_DOS_SIGNATURE))
    return ERROR_INVALID_DATA;

  // Определение адреса PE-заголовка
  INT_PTR pPEHdr = pBaseAddress + (unsigned int)dosHdr.e_lfanew;

  // Чтение PE-заголовка
  if (!::ReadProcessMemory(hProcess, (LPCVOID)pPEHdr, &peHdr, sizeof(peHdr),
                           &nBytesRead))
    return (unsigned int)::GetLastError();

  if ((nBytesRead != sizeof(peHdr)) ||
      (peHdr.Signature != IMAGE_NT_SIGNATURE))
    return ERROR_INVALID_DATA;

  unsigned int nNumSections = peHdr.FileHeader.NumberOfSections;
  unsigned int nFileAlignment = peHdr.OptionalHeader.FileAlignment;
  if ((nNumSections == 0) || (nFileAlignment < 2))
    return ERROR_INVALID_DATA;

  unsigned int cbSectionHdrs = nNumSections * sizeof(IMAGE_SECTION_HEADER);
  PIMAGE_SECTION_HEADER pSectionHdrs;

  pSectionHdrs = (PIMAGE_SECTION_HEADER)AllocMem(cbSectionHdrs);
  if (!pSectionHdrs)
    return ERROR_NOT_ENOUGH_MEMORY;

  unsigned int res = ERROR_SUCCESS;

  unsigned int cbPEHdr = (sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)) +
                         peHdr.FileHeader.SizeOfOptionalHeader;

  // Чтение заголовков секций
  if (!::ReadProcessMemory(hProcess, (LPCVOID)(pPEHdr + cbPEHdr),
                           pSectionHdrs, cbSectionHdrs, &nBytesRead))
  {
    res = ::GetLastError();
  }
  else if (nBytesRead != cbSectionHdrs)
  {
    res = ERROR_INVALID_DATA;
  }

  if (res == ERROR_SUCCESS)
  {
    HANDLE hFile;
    hFile = ::CreateFile(pszFileName, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                         CREATE_ALWAYS, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
      res = ::GetLastError();
    }
    else
    {
      PIMAGE_SECTION_HEADER pSectionHdr = pSectionHdrs;
      // Сохранение заголовков PE-файла
      res = WritePESectionToFile(hFile, hProcess, pBaseAddress,
                                 pSectionHdr->VirtualAddress,
                                 pSectionHdr->PointerToRawData);
      if (res == ERROR_SUCCESS)
      {
        // Сохранение секций в файл
        for (unsigned int i = 0; i < nNumSections; i++, pSectionHdr++)
        {
          // Сохранение секции в файл
          unsigned int nSizeOfRawData = ((pSectionHdr->SizeOfRawData +
                                          (nFileAlignment - 1)) /
                                         nFileAlignment) *
                                        nFileAlignment;
          res = WritePESectionToFile(hFile, hProcess,
                                     pBaseAddress +
                                     pSectionHdr->VirtualAddress,
                                     pSectionHdr->Misc.VirtualSize,
                                     nSizeOfRawData);
          if (res != ERROR_SUCCESS)
            break;
        }
      }

      ::CloseHandle(hFile);
    }
  }

  FreeMem(pSectionHdrs);

  return res;
}
/***************************************************************************/
/* WriteProcessModuleToFile - Сохранение исполняемого модуля процесса      */
/*                            в файл                                       */
/***************************************************************************/
unsigned int WriteProcessModuleToFile(
  const TCHAR *pszFileName,
  HANDLE hProcess,
  HANDLE hThread
  )
{
  CONTEXT ctx;

  // Получение контекста потока для определения адреса PEB
  ctx.ContextFlags = CONTEXT_FULL;
  if (!::GetThreadContext(hThread, &ctx))
    return (unsigned int)::GetLastError();

  INT_PTR p;
#ifdef _WIN64
  p = ctx.Rdx + 0x10;
#else
  p = ctx.Ebx + 8;
#endif  // _WIN64

  INT_PTR pBaseAddress;

  // Получение базового адреса
  SIZE_T nBytesRead;
  if (!::ReadProcessMemory(hProcess, (LPCVOID)p, &pBaseAddress,
                           sizeof(INT_PTR), &nBytesRead))
    return (unsigned int)::GetLastError();
  if (nBytesRead != sizeof(INT_PTR))
    return ERROR_INVALID_DATA;

  // Сохранение исполняемого файла процесса в файл
  return WriteProcessModuleToFile(pszFileName, pBaseAddress, hProcess);
}
/***************************************************************************/
/* WriteProcessModuleToFile - Сохранение исполняемого модуля процесса      */
/*                            в файл                                       */
/***************************************************************************/
unsigned int WriteProcessModuleToFile(
  HANDLE hProcess,
  HANDLE hThread,
  const TCHAR *pszFileNameFormat,
  ...
  )
{
  TCHAR szFileName[MAX_DUMP_PATH];
  va_list arglist;
  va_start(arglist, pszFileNameFormat);
  ::wvsprintf(szFileName, pszFileNameFormat, arglist);
  va_end(arglist);

  // Сохранение исполняемого файла процесса в файл
  return WriteProcessModuleToFile(szFileName, hProcess, hThread);
}
//---------------------------------------------------------------------------
