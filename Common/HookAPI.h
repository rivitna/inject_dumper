//---------------------------------------------------------------------------
#ifndef __HOOKAPI_H__
#define __HOOKAPI_H__
//---------------------------------------------------------------------------
// Размер кода перехода на абсолютный адрес
// push OFFSET Proc
// retn
#define JMP_CODE_SIZE  6

// Максимальный размер начального кода функции
#define MAX_PROC_START_CODE  14

// Размер кода перехода на адрес оригинальной функции API
#define MAX_THUNK_CODE_SIZE  (MAX_PROC_START_CODE + JMP_CODE_SIZE)

// Получение адреса возврата для функций API
#define HOOK_PROC_RET_ADDR(first_arg)  \
  (*((void **)((INT_PTR)&first_arg - sizeof(void *))))
//---------------------------------------------------------------------------
// Перехват функции API
BOOL HookAPIFunc(
  HMODULE hLib,
  const char *pszProcName,
  const void *pHookProc,
  void *pOrigProcThunk
  );
// Перехват функции API
BOOL HookAPIFunc(
  const TCHAR *pszLibName,
  const char *pszProcName,
  const void *pHookProc,
  void *pOrigProcThunk
  );
//---------------------------------------------------------------------------
#endif  // __HOOKAPI_H__
