//---------------------------------------------------------------------------
#ifndef __DUMP_H__
#define __DUMP_H__
//---------------------------------------------------------------------------
// ������ ������ � ����
unsigned int WriteDataToFile(
  const TCHAR *pszFileName,
  const void *pData,
  unsigned int cbData
  );
// ������ ������ � ����
unsigned int WriteDataToFile(
  const void *pData,
  unsigned int cbData,
  const TCHAR *pszFileNameFormat,
  ...
  );
// ���������� ������������ ������ �������� � ����
unsigned int WriteProcessModuleToFile(
  const TCHAR *pszFileName,
  INT_PTR pBaseAddress,
  HANDLE hProcess
  );
// ���������� ������������ ������ �������� � ����
unsigned int WriteProcessModuleToFile(
  const TCHAR *pszFileName,
  HANDLE hProcess,
  HANDLE hThread
  );
// ���������� ������������ ������ �������� � ����
unsigned int WriteProcessModuleToFile(
  HANDLE hProcess,
  HANDLE hThread,
  const TCHAR *pszFileNameFormat,
  ...
  );
//---------------------------------------------------------------------------
#endif  // __DUMP_H__
