//---------------------------------------------------------------------------
#ifndef __PROCINJ_H__
#define __PROCINJ_H__
//---------------------------------------------------------------------------
// Информация об образе целевого процесса
typedef struct _TARGET_PROCESS_IMAGE_INFO
{
  unsigned int  nPEHdrRVA;
  unsigned int  nPEHdrSize;
  unsigned int  nEntryPointRVA;
  unsigned int  nNumSections;
  unsigned int  nCodeSectionFreeAreaRVA;
  unsigned int  nCodeSectionEndRVA;
} TARGET_PROCESS_IMAGE_INFO, *PTARGET_PROCESS_IMAGE_INFO;

// Получение информации об образе целевого процесса
BOOL GetTargetProcessImageInfo(
  INT_PTR pBaseAddress,
  HANDLE hProcess,
  PTARGET_PROCESS_IMAGE_INFO pProcImgInfo
  );

// Запуск процесса и внедрение в него кода
BOOL CreateProcessAndInjectCode(
  const TCHAR *pszAppName,
  TCHAR *pszCmdLine,
  const void *pCode,
  size_t cbCode,
  BOOL bUseRemoteThread,
  BOOL bWait,
  DWORD *pdwExitCode
  );
// Запуск процесса и внедрение в него DLL
BOOL CreateProcessAndInjectDll(
  const TCHAR *pszAppName,
  TCHAR *pszCmdLine,
  const TCHAR *pszDllName,
  BOOL bUseRemoteThread,
  BOOL bWait
  );
//---------------------------------------------------------------------------
#endif // __PROCINJ_H__
