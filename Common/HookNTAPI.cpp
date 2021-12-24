//---------------------------------------------------------------------------
#define WIN32_LEAN_AND_MEAN  // Exclude rarely-used stuff from Windows headers
#include <windows.h>
#include <tchar.h>
#include <intrin.h>
#include "StdUtils.h"
#include "HookNTAPI.h"
//---------------------------------------------------------------------------
// ������ ���� ��������� ������� "KiFastSystemCall"
// clc
// jmp  short ...
#define KIFASTSYSCALL_CODE_SIZE  3
// �������� ���������� �������� � ���� ��������� ������� "KiIntSystemCall"
// stc
// ...
#define KIINTSYSCALL_JMP_OFFSET  1
//---------------------------------------------------------------------------
#pragma pack(push, 1)

// ������ ������� ���������������
typedef struct _SYSCALL_DISPATCH_TABLE_ENTRY
{
  DWORD       dwOrdinal;
  const void *pHookProc;
  DWORD       dwArgSize;
} SYSCALL_DISPATCH_TABLE_ENTRY, *PSYSCALL_DISPATCH_TABLE_ENTRY;

// ������� ���������������
typedef struct _SYSCALL_DISPATCH_TABLE
{
  PSYSCALL_DISPATCH_TABLE_ENTRY  pEntries;
  unsigned int                   nNumEntries;
  unsigned int                   nNumAllocatedEntries;
} SYSCALL_DISPATCH_TABLE, *PSYSCALL_DISPATCH_TABLE;

#pragma pack(pop)

#define SYSCALL_DISPATCH_TABLE_ENTRY_SIZE  \
  sizeof(SYSCALL_DISPATCH_TABLE_ENTRY)

// ��������� ������ ��� ������� ������� ���������������
#define DispatchTableAlloc(num)  (PSYSCALL_DISPATCH_TABLE_ENTRY)\
  AllocArray(num, SYSCALL_DISPATCH_TABLE_ENTRY_SIZE)
//---------------------------------------------------------------------------
// ������� ���������������
SYSCALL_DISPATCH_TABLE  g_dispatchTable;
//---------------------------------------------------------------------------
#ifndef _WIN64
//---------------------------------------------------------------------------
/***************************************************************************/
/* SysCallDispatch - ������� ��������������� ��������� ������� Native API  */
/***************************************************************************/
__declspec(naked) void SysCallDispatch()
{
  __asm
  {
    jc    KiIntSysCall

    lea   edx,[g_dispatchTable]
    cmp   DWORD PTR [edx],0      // g_dispatchTable.pEntries == NULL ?
    je    KiFastSysCall
    cmp   DWORD PTR [edx+4],0    // g_dispatchTable.nNumEntries == 0 ?
    je    KiFastSysCall

    mov   ecx,[edx+4]            // ECX = g_dispatchTable.nNumEntries
    mov   edx,[edx]              // EDX = g_dispatchTable.pEntries
EntryLoop:
    cmp   eax,[edx]              // ������ ���������� ������ =
                                 //   pEntry->dwOrdinal ?
    je    HookSysCall
    add   edx,0Ch
    loop  EntryLoop

KiFastSysCall:
    mov   edx,esp
    // sysenter
    _emit 0Fh
    _emit 34h
    ret

KiIntSysCall:
    lea   edx,[esp+8]
    int   2Eh
    ret

HookSysCall:
    push  ebp
    mov   ebp,esp
    and   esp,NOT (4-1)

    mov   ecx,[edx+8]            // ECX = ������ ���������� �������
    sub   esp,ecx
    push  eax                    // ������ ���������� ������
    push  DWORD PTR [ebp+8]      // ����� ��������
    jecxz DoCallHookProc

    // ����������� ���������� �������
    push  esi
    push  edi
    lea   edi,[esp+10h]
    lea   esi,[ebp+0Ch]
    rep   movsb
    pop   edi
    pop   esi

DoCallHookProc:
    call  DWORD PTR [edx+4]

    mov   esp,ebp
    pop   ebp
    ret
  }
}
/***************************************************************************/
/* CallSysCall - ����� ������������� ���������� ������                     */
/***************************************************************************/
__declspec(naked) void __cdecl CallSysCall(
  DWORD dwOrdinal
  )
{
  __asm
  {
    pop   edx                    // EDX = ����� ��������
    pop   eax                    // EAX = ������ ���������� ������
    push  edx

    call  KiFastSysCall

    push  DWORD PTR [esp]
    ret

KiFastSysCall:
    mov   edx,esp
    // sysenter
    _emit 0Fh
    _emit 34h
    ret
  }
}
/***************************************************************************/
/* InitHookSysCall - ������������� ��������� ��������� ������� Native API  */
/***************************************************************************/
BOOL InitHookSysCall(
  unsigned int nNumAllocatedEntries
  )
{
  g_dispatchTable.pEntries = NULL;
  g_dispatchTable.nNumEntries = 0;
  g_dispatchTable.nNumAllocatedEntries = 0;

  HMODULE hNtDllLib = ::GetModuleHandle(_T("NTDLL.DLL"));
  if (!hNtDllLib)
    return FALSE;

  INT_PTR pfnKiFastSystemCall;
  INT_PTR pfnKiIntSystemCall;

  if (!(pfnKiFastSystemCall =
          (INT_PTR)::GetProcAddress(hNtDllLib, "KiFastSystemCall")) ||
      !(pfnKiIntSystemCall =
          (INT_PTR)::GetProcAddress(hNtDllLib, "KiIntSystemCall")) ||
      (pfnKiFastSystemCall == pfnKiIntSystemCall))
    return FALSE;

  // ����������� �������� �������� �� "jmp near ..." � "KiIntSystemCall"
  INT_PTR nJmpDistance = pfnKiIntSystemCall + KIINTSYSCALL_JMP_OFFSET -
                         pfnKiFastSystemCall - KIFASTSYSCALL_CODE_SIZE;
  if ((nJmpDistance > 127) || (nJmpDistance < -128))
    return FALSE;

  if (nNumAllocatedEntries != 0)
  {
    // ��������� ������ ��� ������� ������� ���������������
    g_dispatchTable.pEntries = DispatchTableAlloc(nNumAllocatedEntries);
    if (!g_dispatchTable.pEntries)
      return FALSE;
    g_dispatchTable.nNumAllocatedEntries = nNumAllocatedEntries;
  }

  unsigned char fastSysCallHookCode[4];
  unsigned char intSysCallHookCode[8];

  // clc
  fastSysCallHookCode[0] = 0xF8;
  // jmp  short ...
  fastSysCallHookCode[1] = 0xEB;
  fastSysCallHookCode[2] = (char)nJmpDistance;
  // ������������ ������������ ������ �������
  fastSysCallHookCode[3] = ((unsigned char *)pfnKiFastSystemCall)[3];

  // stc
  intSysCallHookCode[0] = 0xF9;
  // push OFFSET SysCallDispatch
  intSysCallHookCode[1] = 0x68;
  *((DWORD *)&intSysCallHookCode[2]) = (DWORD)&SysCallDispatch;
  // retn
  intSysCallHookCode[6] = 0xC3;
  // ������������ ������������ ������ �������
  intSysCallHookCode[7] = ((unsigned char *)pfnKiIntSystemCall)[7];

  BOOL bSuccess = FALSE;

  DWORD flOldProtect1;
  if (::VirtualProtect((LPVOID)pfnKiFastSystemCall,
                       sizeof(fastSysCallHookCode),
                       PAGE_EXECUTE_READWRITE, &flOldProtect1))
  {
    DWORD flOldProtect2;
    if (::VirtualProtect((LPVOID)pfnKiIntSystemCall,
                         sizeof(intSysCallHookCode),
                         PAGE_EXECUTE_READWRITE, &flOldProtect2))
    {
      // ��������� ���� ������� "KiIntSystemCall" ��������� ���������
      _InterlockedCompareExchange64((LONG64 *)pfnKiIntSystemCall,
                                    *((LONG64 *)intSysCallHookCode),
                                    *((LONG64 *)pfnKiIntSystemCall));
      // ��������� ���� ������� "KiFastSystemCall" ��������� ���������
      _InterlockedCompareExchange((LONG *)pfnKiFastSystemCall,
                                  *((LONG *)fastSysCallHookCode),
                                  *((LONG *)pfnKiFastSystemCall));
      bSuccess = TRUE;
      ::VirtualProtect((LPVOID)pfnKiIntSystemCall,
                       sizeof(intSysCallHookCode),
                       flOldProtect2, &flOldProtect2);
    }
    ::VirtualProtect((LPVOID)pfnKiFastSystemCall,
                     sizeof(fastSysCallHookCode),
                     flOldProtect1, &flOldProtect1);
  }

  if (!bSuccess)
  {
    if (g_dispatchTable.pEntries)
    {
      // ������������ ������, ���������� ��� ������� ���������������
      FreeMem(g_dispatchTable.pEntries);
      g_dispatchTable.pEntries = NULL;
      g_dispatchTable.nNumAllocatedEntries = 0;
    }
    return FALSE;
  }

  return TRUE;
}
/***************************************************************************/
/* GetSysCallOrdinal - ��������� ������� ���������� ������                 */
/***************************************************************************/
DWORD GetSysCallOrdinal(
  const char *pszProcName
  )
{
  if (!pszProcName || !pszProcName[0])
    return (DWORD)-1;

  HMODULE hNtDllLib = ::GetModuleHandle(_T("NTDLL.DLL"));
  if (!hNtDllLib)
    return (DWORD)-1;

  const unsigned char *p;
  if (!(p = (const unsigned char *)::GetProcAddress(hNtDllLib, pszProcName)))
    return (DWORD)-1;

  // mov eax, PROC_ORDINAL
  if (p[0] != 0xB8)
    return (DWORD)-1;

  return *((DWORD *)&p[1]);
}
/***************************************************************************/
/* FindDispatchTableEntryByOrdinal - ����� ������ � ������� ���������������*/
/*                                   �� ������� ���������� ������          */
/***************************************************************************/
PSYSCALL_DISPATCH_TABLE_ENTRY FindDispatchTableEntryByOrdinal(
  DWORD dwOrdinal
  )
{
  if (!g_dispatchTable.pEntries || (g_dispatchTable.nNumEntries == 0))
    return NULL;
  PSYSCALL_DISPATCH_TABLE_ENTRY pEntry = g_dispatchTable.pEntries;
  for (size_t i = 0; i < g_dispatchTable.nNumEntries; i++, pEntry++)
  {
    if (dwOrdinal == pEntry->dwOrdinal)
      return pEntry;
  }
  return NULL;
}
/***************************************************************************/
/* ReplaceDispatchTable - ������ ������� ���������������                   */
/***************************************************************************/
void ReplaceDispatchTable(
  SYSCALL_DISPATCH_TABLE *pDestTable,
  const SYSCALL_DISPATCH_TABLE *pNewTable
  )
{
  void *pPrevEntries = pDestTable->pEntries;

  // ������ ����� pEntries � nNumEntries ������� ��������������� ���������
  // ���������
  _InterlockedCompareExchange64((LONG64 *)&pDestTable->pEntries,
                                *((LONG64 *)&pNewTable->pEntries),
                                *((LONG64 *)&pDestTable->pEntries));
  // ������ ���� nNumAllocatedEntries ������� ��������������� ���������
  // ���������
  _InterlockedCompareExchange((LONG *)&pDestTable->nNumAllocatedEntries,
                              (LONG)pNewTable->nNumAllocatedEntries,
                              (LONG)pDestTable->nNumAllocatedEntries);

  // ������������ ������, ���������� ��� ���������� ������� ���������������
  FreeMem(pPrevEntries);
}
/***************************************************************************/
/* AddSysCallHook - ���������� ��������� ���������� ������ Native API      */
/***************************************************************************/
BOOL AddSysCallHook(
  const char *pszProcName,
  const void *pHookProc,
  DWORD dwArgSize
  )
{
  if (!pHookProc)
    return FALSE;

  // ��������� ������� ���������� ������
  DWORD dwOrdinal = GetSysCallOrdinal(pszProcName);
  if (dwOrdinal == (DWORD)-1)
    return FALSE;

  PSYSCALL_DISPATCH_TABLE_ENTRY pEntry;

  // ����� ������ � ������� ��������������� �� ������� ���������� ������
  pEntry = FindDispatchTableEntryByOrdinal(dwOrdinal);
  if (pEntry)
  {
    // ������ ������� ��������� � ������ �������
    _InterlockedCompareExchange((LONG *)&pEntry->pHookProc,
                                (LONG)pHookProc, (LONG)pEntry->pHookProc);
    return TRUE;
  }

  unsigned int nPrevNumEntries = g_dispatchTable.nNumEntries;
  unsigned int nNumAllocatedEntries = g_dispatchTable.nNumAllocatedEntries;
  if (!g_dispatchTable.pEntries)
  {
    nPrevNumEntries = 0;
    nNumAllocatedEntries = 0;
  }

  if (nPrevNumEntries < nNumAllocatedEntries)
  {
    pEntry = &g_dispatchTable.pEntries[nPrevNumEntries];
    pEntry->dwOrdinal = dwOrdinal;
    pEntry->pHookProc = pHookProc;
    pEntry->dwArgSize = dwArgSize;
    _InterlockedIncrement((LONG *)&g_dispatchTable.nNumEntries);
    return TRUE;
  }

  SYSCALL_DISPATCH_TABLE dispatchTable;

  nNumAllocatedEntries += (nNumAllocatedEntries > 64)
                            ? (nNumAllocatedEntries >> 2)
                            : ((nNumAllocatedEntries > 8) ? 16 : 4);
  dispatchTable.pEntries = DispatchTableAlloc(nNumAllocatedEntries);
  if (!dispatchTable.pEntries)
    return FALSE;

  dispatchTable.nNumEntries = nPrevNumEntries + 1;
  dispatchTable.nNumAllocatedEntries = nNumAllocatedEntries;

  if (nPrevNumEntries != 0)
  {
    CopyMem(dispatchTable.pEntries, g_dispatchTable.pEntries,
            nPrevNumEntries * SYSCALL_DISPATCH_TABLE_ENTRY_SIZE);
  }

  pEntry = &dispatchTable.pEntries[nPrevNumEntries];
  pEntry->dwOrdinal = dwOrdinal;
  pEntry->pHookProc = pHookProc;
  pEntry->dwArgSize = dwArgSize;

  // ������ ������� ���������������
  ReplaceDispatchTable(&g_dispatchTable, &dispatchTable);

  return TRUE;
}
/***************************************************************************/
/* DelSysCallHook - �������� ��������� ���������� ������ Native API        */
/***************************************************************************/
BOOL DelSysCallHook(
  const char *pszProcName
  )
{
  // ��������� ������� ���������� ������
  DWORD dwOrdinal = GetSysCallOrdinal(pszProcName);
  if (dwOrdinal == (DWORD)-1)
    return FALSE;

  // ����� ������ � ������� ��������������� �� ������� ���������� ������
  PSYSCALL_DISPATCH_TABLE_ENTRY pEntry;
  pEntry = FindDispatchTableEntryByOrdinal(dwOrdinal);
  if (!pEntry)
    return TRUE;

  unsigned int nPrevNumEntries = g_dispatchTable.nNumEntries;

  SYSCALL_DISPATCH_TABLE dispatchTable;
  dispatchTable.nNumEntries = nPrevNumEntries - 1;
  if (dispatchTable.nNumEntries != 0)
  {
    dispatchTable.nNumAllocatedEntries =
      g_dispatchTable.nNumAllocatedEntries;
    dispatchTable.pEntries =
      DispatchTableAlloc(dispatchTable.nNumAllocatedEntries);
    if (!dispatchTable.pEntries)
      return FALSE;
    size_t nIndex = pEntry - g_dispatchTable.pEntries;
    if (nIndex != 0)
    {
      CopyMem(dispatchTable.pEntries, g_dispatchTable.pEntries,
              nIndex * SYSCALL_DISPATCH_TABLE_ENTRY_SIZE);
    }
    if (nIndex < nPrevNumEntries - 1)
    {
      CopyMem(&dispatchTable.pEntries[nIndex],
              &g_dispatchTable.pEntries[nIndex + 1],
              (nPrevNumEntries - nIndex - 1) *
              SYSCALL_DISPATCH_TABLE_ENTRY_SIZE);
    }
  }
  else
  {
    dispatchTable.nNumAllocatedEntries = 0;
    dispatchTable.pEntries = NULL;
  }

  // ������ ������� ���������������
  ReplaceDispatchTable(&g_dispatchTable, &dispatchTable);

  return TRUE;
}
/***************************************************************************/
/* DelSysCallHooks - �������� ���������� ��������� ������� Native API      */
/***************************************************************************/
void DelSysCallHooks()
{
  if (!g_dispatchTable.pEntries || (g_dispatchTable.nNumEntries == 0))
    return;

  SYSCALL_DISPATCH_TABLE dispatchTable;
  dispatchTable.pEntries = NULL;
  dispatchTable.nNumEntries = 0;
  dispatchTable.nNumAllocatedEntries = 0;

  // ������ ������� ���������������
  ReplaceDispatchTable(&g_dispatchTable, &dispatchTable);
}
//---------------------------------------------------------------------------
#endif  // _WIN64
//---------------------------------------------------------------------------
