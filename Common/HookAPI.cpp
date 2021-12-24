//---------------------------------------------------------------------------
#define WIN32_LEAN_AND_MEAN  // Exclude rarely-used stuff from Windows headers
#include <windows.h>
#include <tchar.h>
#include <intrin.h>
#include "StdUtils.h"
#include "HookAPI.h"
//---------------------------------------------------------------------------
#ifndef countof
#define countof(a)  (sizeof(a)/sizeof(a[0]))
#endif  // countof
//---------------------------------------------------------------------------
// Шаблоны начального кода функций

// mov  edi, edi
// push ebp
// mov  ebp, esp
// sub  esp, N / and  esp, N / sub eax, N / and  eax, N
const unsigned char START_CODE_PATTERN0[8] =
  { 0x8B, 0xFF, 0x55, 0x8B, 0xEC, 0x83, 0xE0, 0 };
const unsigned char START_CODE_MASK0[8] =
  { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF3, 0 };
// mov  edi, edi
// push ebp
// mov  ebp, esp
// sub  esp, N
const unsigned char START_CODE_PATTERN1[11] =
  { 0x8B, 0xFF, 0x55, 0x8B, 0xEC, 0x81, 0xEC, 0, 0, 0, 0 };
const unsigned char START_CODE_MASK1[11] =
  { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0 };
// mov  edi, edi
// push ebp
// mov  ebp, esp
// pop  ... / push ...
const unsigned char START_CODE_PATTERN2[6] =
  { 0x8B, 0xFF, 0x55, 0x8B, 0xEC, 0x50 };
const unsigned char START_CODE_MASK2[6] =
  { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF0 };
// push Arg2
// push Arg1
const unsigned char START_CODE_PATTERN3[10] =
  { 0x68, 0, 0, 0, 0, 0x68, 0, 0, 0, 0 };
const unsigned char START_CODE_MASK3[10] =
  { 0xFF, 0, 0, 0, 0, 0xFF, 0, 0, 0, 0 };

typedef struct _CODE_PATTERN
{
  unsigned int         nLength;
  const unsigned char *pPattern;
  const unsigned char *pMask;
} CODE_PATTERN, *PCODE_PATTERN;

const CODE_PATTERN PROC_START_CODE_PATTERNS[] =
{
  { sizeof(START_CODE_PATTERN0), START_CODE_PATTERN0, START_CODE_MASK0 },
  { sizeof(START_CODE_PATTERN0) - 2, &START_CODE_PATTERN0[2],
    &START_CODE_MASK0[2] },
  { sizeof(START_CODE_PATTERN1), START_CODE_PATTERN1, START_CODE_MASK1 },
  { sizeof(START_CODE_PATTERN1) - 2, &START_CODE_PATTERN1[2],
    &START_CODE_MASK1[2] },
  { sizeof(START_CODE_PATTERN2), START_CODE_PATTERN2, START_CODE_MASK2 },
  { sizeof(START_CODE_PATTERN3), START_CODE_PATTERN3, START_CODE_MASK3 }
};
//---------------------------------------------------------------------------
/***************************************************************************/
/* MatchPattern - Проверка соответствия цепочки байтов шаблону             */
/***************************************************************************/
BOOL MatchPattern(
  const void *s,
  size_t len,
  const void *pattern,
  const void *mask,
  size_t patternlen
  )
{
  if (!s || (len == 0))
    return FALSE;
  if (!pattern || (patternlen == 0))
    return TRUE;
  if (len < patternlen)
    return FALSE;

  const unsigned char *ps = (unsigned char *)s;
  const unsigned char *pp = (unsigned char *)pattern;
  if (mask)
  {
    const unsigned char *pm = (unsigned char *)mask;
    while ((patternlen != 0) && (!*pm || ((*ps & *pm) == *pp)))
    {
      patternlen--;
      ps++;
      pp++;
      pm++;
    }
  }
  else
  {
    while ((patternlen != 0) && (*ps == *pp))
    {
      patternlen--;
      ps++;
      pp++;
    }
  }
  return (patternlen == 0);
}
/***************************************************************************/
/* MatchProcStartCode - Проверка соответствия начального кода функции      */
/*                      одному из шаблонов                                 */
/***************************************************************************/
const CODE_PATTERN *MatchProcStartCode(
  const void *pProc,
  size_t cbProc
  )
{
  const CODE_PATTERN *pPattern = PROC_START_CODE_PATTERNS;
  for (size_t i = 0; i < countof(PROC_START_CODE_PATTERNS); i++, pPattern++)
  {
    // Проверка соответствия цепочки байтов шаблону
    if (MatchPattern(pProc, cbProc, pPattern->pPattern, pPattern->pMask,
                     pPattern->nLength))
      return pPattern;
  }
  return NULL;
}
/***************************************************************************/
/* HookAPIFunc - Перехват функции API                                      */
/***************************************************************************/
BOOL HookAPIFunc(
  HMODULE hLib,
  const char *pszProcName,
  const void *pHookProc,
  void *pOrigProcThunk
  )
{
  if (!hLib ||
      !pszProcName || !pszProcName[0] ||
      !pHookProc)
    return FALSE;

  void *pProc = (void *)::GetProcAddress(hLib, pszProcName);
  if (!pProc)
    return FALSE;

  const CODE_PATTERN *pPattern;

  // Проверка соответствия начального кода функции одному из шаблонов
  pPattern = MatchProcStartCode(pProc, MAX_PROC_START_CODE);
  if (!pPattern)
    return FALSE;

  unsigned char hookCode[8];

  DWORD flOldProtect;

  if (!::VirtualProtect(pProc, sizeof(hookCode), PAGE_EXECUTE_READWRITE,
                        &flOldProtect))
    return FALSE;

  if (pOrigProcThunk)
  {
    // Создание кода вызова кода оригинальной перехваченной функции
    unsigned char *p = (unsigned char *)pOrigProcThunk;
    CopyMem(p, pProc, pPattern->nLength);
    p += pPattern->nLength;
    // push (OFFSET OldProc + pPattern->nLength)
    p[0] = 0x68;
    *((DWORD *)&p[1]) = (DWORD)pProc + pPattern->nLength;
    p += 1 + sizeof(DWORD);
    // retn
    p[0] = 0xC3;
  }

  // push OFFSET NewProc
  hookCode[0] = 0x68;
  *((DWORD *)&hookCode[1]) = (DWORD)pHookProc;
  // retn
  hookCode[1 + sizeof(DWORD)] = 0xC3;
  // Выравнивание оригинальными байтами функции
  hookCode[2 + sizeof(DWORD)] = ((unsigned char *)pProc)[2 + sizeof(DWORD)];
  hookCode[3 + sizeof(DWORD)] = ((unsigned char *)pProc)[3 + sizeof(DWORD)];

  // Изменение кода перехватываемой функции атомарной операцией
  _InterlockedCompareExchange64((LONG64 *)pProc, *((LONG64 *)hookCode),
                                *((LONG64 *)pProc));

  ::VirtualProtect(pProc, sizeof(hookCode), flOldProtect, &flOldProtect);

  return TRUE;
}
/***************************************************************************/
/* HookAPIFunc - Перехват функции API                                      */
/***************************************************************************/
BOOL HookAPIFunc(
  const TCHAR *pszLibName,
  const char *pszProcName,
  const void *pHookProc,
  void *pOrigProcThunk
  )
{
  if (!pszLibName || !pszLibName[0] ||
      !pszProcName || !pszProcName[0] ||
      !pHookProc)
    return FALSE;

  // Получение дескриптора библиотеки
  HMODULE hLib = ::GetModuleHandle(pszLibName);
  if (!hLib)
    return FALSE;

  // Перехват функции API
  return HookAPIFunc(hLib, pszProcName, pHookProc, pOrigProcThunk);
}
//---------------------------------------------------------------------------
