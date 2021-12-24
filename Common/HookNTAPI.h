//---------------------------------------------------------------------------
#ifndef __HOOKNTAPI_H__
#define __HOOKNTAPI_H__
//---------------------------------------------------------------------------
#ifndef _WIN64
// ������������� ��������� ��������� ������� Native API
BOOL InitHookSysCall(
  unsigned int nNumAllocatedEntries = 0
  );
// ����� ������������� ���������� ������
void __cdecl CallSysCall(
  DWORD dwOrdinal
  );
// ���������� ��������� ���������� ������ Native API
BOOL AddSysCallHook(
  const char *pszProcName,
  const void *pHookProc,
  DWORD dwArgSize
  );
// �������� ��������� ���������� ������ Native API
BOOL DelSysCallHook(
  const char *pszProcName
  );
// �������� ���������� ��������� ������� Native API
void DelSysCallHooks();
#endif  // _WIN64
//---------------------------------------------------------------------------
#endif  // __HOOKNTAPI_H__
