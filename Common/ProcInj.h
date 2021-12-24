//---------------------------------------------------------------------------
#ifndef __PROCINJ_H__
#define __PROCINJ_H__
//---------------------------------------------------------------------------
// ���������� �� ������ �������� ��������
typedef struct _TARGET_PROCESS_IMAGE_INFO
{
  unsigned int  nPEHdrRVA;
  unsigned int  nPEHdrSize;
  unsigned int  nEntryPointRVA;
  unsigned int  nNumSections;
  unsigned int  nCodeSectionFreeAreaRVA;
  unsigned int  nCodeSectionEndRVA;
} TARGET_PROCESS_IMAGE_INFO, *PTARGET_PROCESS_IMAGE_INFO;

// ��������� ���������� �� ������ �������� ��������
BOOL GetTargetProcessImageInfo(
  INT_PTR pBaseAddress,
  HANDLE hProcess,
  PTARGET_PROCESS_IMAGE_INFO pProcImgInfo
  );

// ������ �������� � ��������� � ���� ����
BOOL CreateProcessAndInjectCode(
  const TCHAR *pszAppName,
  TCHAR *pszCmdLine,
  const void *pCode,
  size_t cbCode,
  BOOL bUseRemoteThread,
  BOOL bWait,
  DWORD *pdwExitCode
  );
// ������ �������� � ��������� � ���� DLL
BOOL CreateProcessAndInjectDll(
  const TCHAR *pszAppName,
  TCHAR *pszCmdLine,
  const TCHAR *pszDllName,
  BOOL bUseRemoteThread,
  BOOL bWait
  );
//---------------------------------------------------------------------------
#endif // __PROCINJ_H__
