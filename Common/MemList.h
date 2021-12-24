//---------------------------------------------------------------------------
#ifndef __MEMLIST_H__
#define __MEMLIST_H__
//---------------------------------------------------------------------------
typedef struct _MEM_LIST_ENTRY
{
  void   *pAddr;
  size_t  nSize;
} MEM_LIST_ENTRY, *PMEM_LIST_ENTRY;

typedef struct _MEM_LIST
{
  PMEM_LIST_ENTRY   pEntries;
  size_t            nNumEntries;
  size_t            nNumAllocatedEntries;
  CRITICAL_SECTION  csLock;
} MEM_LIST, *PMEM_LIST;

// Инициализация списка блоков памяти
BOOL MemList_Init(
  PMEM_LIST pMemList,
  size_t nNumAllocatedEntries = 0
  );
// Освобождение списка блоков памяти
void MemList_Free(
  PMEM_LIST pMemList
  );
// Блокировка списка блоков памяти
void MemList_Lock(
  PMEM_LIST pMemList
  );
// Разблокировка списка блоков памяти
void MemList_Unlock(
  PMEM_LIST pMemList
  );
// Добавление блока памяти в список
BOOL MemList_Add(
  PMEM_LIST pMemList,
  void *pAddr,
  size_t nSize
  );
// Удаление блока памяти из списка
BOOL MemList_Del(
  PMEM_LIST pMemList,
  void *pAddr
  );
// Очистка списка блоков памяти
void MemList_Clear(
  PMEM_LIST pMemList,
  BOOL bFree = FALSE
  );
//---------------------------------------------------------------------------
#endif  // __MEMLIST_H__
