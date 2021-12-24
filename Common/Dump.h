//---------------------------------------------------------------------------
#ifndef __DUMP_H__
#define __DUMP_H__
//---------------------------------------------------------------------------
// Запись данных в файл
unsigned int WriteDataToFile(
  const TCHAR *pszFileName,
  const void *pData,
  unsigned int cbData
  );
// Запись данных в файл
unsigned int WriteDataToFile(
  const void *pData,
  unsigned int cbData,
  const TCHAR *pszFileNameFormat,
  ...
  );
// Сохранение исполняемого модуля процесса в файл
unsigned int WriteProcessModuleToFile(
  const TCHAR *pszFileName,
  INT_PTR pBaseAddress,
  HANDLE hProcess
  );
// Сохранение исполняемого модуля процесса в файл
unsigned int WriteProcessModuleToFile(
  const TCHAR *pszFileName,
  HANDLE hProcess,
  HANDLE hThread
  );
// Сохранение исполняемого модуля процесса в файл
unsigned int WriteProcessModuleToFile(
  HANDLE hProcess,
  HANDLE hThread,
  const TCHAR *pszFileNameFormat,
  ...
  );
//---------------------------------------------------------------------------
#endif  // __DUMP_H__
