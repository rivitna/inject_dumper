//---------------------------------------------------------------------------
#ifndef __HOOKAPI_H__
#define __HOOKAPI_H__
//---------------------------------------------------------------------------
// ������ ���� �������� �� ���������� �����
// push OFFSET Proc
// retn
#define JMP_CODE_SIZE  6

// ������������ ������ ���������� ���� �������
#define MAX_PROC_START_CODE  14

// ������ ���� �������� �� ����� ������������ ������� API
#define MAX_THUNK_CODE_SIZE  (MAX_PROC_START_CODE + JMP_CODE_SIZE)

// ��������� ������ �������� ��� ������� API
#define HOOK_PROC_RET_ADDR(first_arg)  \
  (*((void **)((INT_PTR)&first_arg - sizeof(void *))))
//---------------------------------------------------------------------------
// �������� ������� API
BOOL HookAPIFunc(
  HMODULE hLib,
  const char *pszProcName,
  const void *pHookProc,
  void *pOrigProcThunk
  );
// �������� ������� API
BOOL HookAPIFunc(
  const TCHAR *pszLibName,
  const char *pszProcName,
  const void *pHookProc,
  void *pOrigProcThunk
  );
//---------------------------------------------------------------------------
#endif  // __HOOKAPI_H__
