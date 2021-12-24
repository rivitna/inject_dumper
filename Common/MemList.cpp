//---------------------------------------------------------------------------
#define WIN32_LEAN_AND_MEAN  // Exclude rarely-used stuff from Windows headers
#include <windows.h>
#include "StdUtils.h"
#include "MemList.h"
//---------------------------------------------------------------------------
/***************************************************************************/
/* MemList_Init - ������������� ������ ������ ������                       */
/***************************************************************************/
BOOL MemList_Init(
  PMEM_LIST pMemList,
  size_t nNumAllocatedEntries
  )
{
  if (!pMemList)
    return FALSE;

  pMemList->pEntries = NULL;
  pMemList->nNumEntries = 0;
  pMemList->nNumAllocatedEntries = 0;

  // ������������� ����������� ������ ����������
  ::InitializeCriticalSection(&pMemList->csLock);

  if (nNumAllocatedEntries != 0)
  {
    pMemList->pEntries = (PMEM_LIST_ENTRY)AllocMem(nNumAllocatedEntries *
                                                   sizeof(MEM_LIST_ENTRY));
    if (!pMemList->pEntries)
      return FALSE;
    pMemList->nNumAllocatedEntries = nNumAllocatedEntries;
  }

  return TRUE;
}
/***************************************************************************/
/* MemList_Free - ������������ ������ ������ ������                        */
/***************************************************************************/
void MemList_Free(
  PMEM_LIST pMemList
  )
{
  if (!pMemList)
    return;

  pMemList->nNumEntries = 0;
  pMemList->nNumAllocatedEntries = 0;
  // ������������ ���������� ������
  if (pMemList->pEntries)
  {
    FreeMem(pMemList->pEntries);
    pMemList->pEntries = NULL;
  }

  // ����������� ����������� ������ ����������
  ::DeleteCriticalSection(&pMemList->csLock);
}
/***************************************************************************/
/* MemList_Lock - ���������� ������ ������ ������                          */
/***************************************************************************/
void MemList_Lock(
  PMEM_LIST pMemList
  )
{
  if (pMemList)
    ::EnterCriticalSection(&pMemList->csLock);
}
/***************************************************************************/
/* MemList_Unlock - ������������� ������ ������ ������                     */
/***************************************************************************/
void MemList_Unlock(
  PMEM_LIST pMemList
  )
{
  if (pMemList)
    ::LeaveCriticalSection(&pMemList->csLock);
}
/***************************************************************************/
/* MemList_FindByAddr - ����� � ������ �� ������ ����� ������              */
/***************************************************************************/
PMEM_LIST_ENTRY MemList_FindByAddr(
  PMEM_LIST pMemList,
  void *pAddr
  )
{
  if (!pMemList)
    return NULL;

  PMEM_LIST_ENTRY pEntry = pMemList->pEntries;
  for (size_t i = 0; i < pMemList->nNumEntries; i++, pEntry++)
  {
    if (pAddr == pEntry->pAddr)
      return pEntry;
  }
  return NULL;
}
/***************************************************************************/
/* MemList_Add - ���������� ����� ������ � ������                          */
/***************************************************************************/
BOOL MemList_Add(
  PMEM_LIST pMemList,
  void *pAddr,
  size_t nSize
  )
{
  if (!pMemList)
    return FALSE;

  BOOL bError = FALSE;

  PMEM_LIST_ENTRY pEntry;

  // ���������� ������ ������ ������
  MemList_Lock(pMemList);

  // ����� � ������ �� ������ ����� ������
  pEntry = MemList_FindByAddr(pMemList, pAddr);
  if (pEntry)
  {
    pEntry->nSize = nSize;
  }
  else
  {
    if (pMemList->nNumEntries >= pMemList->nNumAllocatedEntries)
    {
      size_t nNumAllocatedEntries = pMemList->nNumAllocatedEntries;
      nNumAllocatedEntries += (nNumAllocatedEntries > 64)
                                ? (nNumAllocatedEntries >> 2)
                                : ((nNumAllocatedEntries > 8) ? 16 : 4);
      // ��������� ������ ��� ������� ������
      void *pEntries;
      pEntries = ReAllocMem(pMemList->pEntries,
                            nNumAllocatedEntries * sizeof(MEM_LIST_ENTRY));
      if (!pEntries)
      {
        bError = TRUE;
      }
      else
      {
        pMemList->pEntries = (PMEM_LIST_ENTRY)pEntries;
        pMemList->nNumAllocatedEntries = nNumAllocatedEntries;
      }
    }
    if (!bError)
    {
      pEntry = &pMemList->pEntries[pMemList->nNumEntries];
      pEntry->pAddr = pAddr;
      pEntry->nSize = nSize;
      pMemList->nNumEntries++;
    }
  }

  // ������������� ������ ������ ������
  MemList_Unlock(pMemList);

  return !bError;
}
/***************************************************************************/
/* MemList_Del - �������� ����� ������ �� ������                           */
/***************************************************************************/
BOOL MemList_Del(
  PMEM_LIST pMemList,
  void *pAddr
  )
{
  if (!pMemList)
    return FALSE;

  BOOL bSuccess = FALSE;

  // ���������� ������ ������ ������
  MemList_Lock(pMemList);

  // ����� � ������ �� ������ ����� ������
  PMEM_LIST_ENTRY pEntry = MemList_FindByAddr(pMemList, pAddr);
  if (pEntry)
  {
    size_t nMoveEntries = pMemList->nNumEntries -
                          (pEntry - pMemList->pEntries + 1);
    if (nMoveEntries != 0)
    {
      // ����������� ����� ������
      MoveMem(pEntry, pEntry + 1, nMoveEntries * sizeof(MEM_LIST_ENTRY));
    }
    pMemList->nNumEntries--;
    bSuccess = TRUE;
  }

  // ������������� ������ ������ ������
  MemList_Unlock(pMemList);

  return bSuccess;
}
/***************************************************************************/
/* MemList_Clear - ������� ������ ������ ������                            */
/***************************************************************************/
void MemList_Clear(
  PMEM_LIST pMemList,
  BOOL bFree
  )
{
  if (!pMemList)
    return;

  // ���������� ������ ������ ������
  MemList_Lock(pMemList);

  pMemList->nNumEntries = 0;

  if (bFree)
  {
    // ������������ ���������� ������
    if (pMemList->pEntries)
    {
      FreeMem(pMemList->pEntries);
      pMemList->pEntries = NULL;
    }
    pMemList->nNumAllocatedEntries = 0;
  }

  // ������������� ������ ������ ������
  MemList_Unlock(pMemList);
}
//---------------------------------------------------------------------------
