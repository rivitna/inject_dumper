//---------------------------------------------------------------------------
#define WIN32_LEAN_AND_MEAN  // Exclude rarely-used stuff from Windows headers
#include <windows.h>
#include <winnt.h>
#include <winternl.h>
#include "ProcInfo.h"
//---------------------------------------------------------------------------
typedef struct _LDR_DATA_TABLE_ENTRY
{
  LIST_ENTRY      InLoadOrderLinks;
  LIST_ENTRY      InMemoryOrderLinks;
  LIST_ENTRY      InInitializationOrderLinks;
  PVOID           DllBase;
  PVOID           EntryPoint;
  ULONG           SizeOfImage;
  UNICODE_STRING  FullDllName;
  UNICODE_STRING  BaseDllName;
  ULONG           Flags;
  USHORT          LoadCount;
  USHORT          TlsIndex;
  LIST_ENTRY      HashLinks;
  ULONG           TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
//---------------------------------------------------------------------------
/***************************************************************************/
/* GetModuleNameByAddress - Получение имени модуля по адресу               */
/***************************************************************************/
const UNICODE_STRING *GetModuleNameByAddress(
  const void *pAddr
  )
{
  INT_PTR pPEB;
  INT_PTR pLdr;
  PLDR_DATA_TABLE_ENTRY pModuleLink;
#ifdef _WIN64
  pPEB = __readgsqword(0x60);
  pLdr = *(INT_PTR *)(pPEB + 0x18);
  pModuleLink = (PLDR_DATA_TABLE_ENTRY)*(INT_PTR *)(pLdr + 0x18);
#else
  pPEB = __readfsdword(0x30);
  pLdr = *(INT_PTR *)(pPEB + 0x0C);
  pModuleLink = (PLDR_DATA_TABLE_ENTRY)*(INT_PTR *)(pLdr + 0x0C);
#endif  // _WIN64

  PLDR_DATA_TABLE_ENTRY pModuleEntry = pModuleLink;
  do
  {
    if (pModuleEntry->DllBase &&
        ((INT_PTR)pAddr >= (INT_PTR)pModuleEntry->DllBase))
    {
      size_t nOffset = (INT_PTR)pAddr - (INT_PTR)pModuleEntry->DllBase;
      if (nOffset < pModuleEntry->SizeOfImage)
        return &pModuleEntry->BaseDllName;
    }
    pModuleEntry =
      (PLDR_DATA_TABLE_ENTRY)pModuleEntry->InLoadOrderLinks.Flink;
  }
  while (pModuleEntry != pModuleLink);

  return (UNICODE_STRING *)NULL;
}
//---------------------------------------------------------------------------
