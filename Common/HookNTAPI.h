//---------------------------------------------------------------------------
#ifndef __HOOKNTAPI_H__
#define __HOOKNTAPI_H__
//---------------------------------------------------------------------------
#ifndef _WIN64
// Инициализация перехвата системных вызовов Native API
BOOL InitHookSysCall(
  unsigned int nNumAllocatedEntries = 0
  );
// Вызов оригинального системного вызова
void __cdecl CallSysCall(
  DWORD dwOrdinal
  );
// Добавление перехвата системного вызова Native API
BOOL AddSysCallHook(
  const char *pszProcName,
  const void *pHookProc,
  DWORD dwArgSize
  );
// Удаление перехвата системного вызова Native API
BOOL DelSysCallHook(
  const char *pszProcName
  );
// Удаление перехватов системных вызовов Native API
void DelSysCallHooks();
#endif  // _WIN64
//---------------------------------------------------------------------------
#endif  // __HOOKNTAPI_H__
