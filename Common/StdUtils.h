//---------------------------------------------------------------------------
#ifndef __STDUTILS_H__
#define __STDUTILS_H__
//---------------------------------------------------------------------------
// Выделение буфера памяти
void *AllocMem(
  size_t size
  );
// Изменение размера буфера памяти
void *ReAllocMem(
  void *memblock,
  size_t size
  );
// Выделение памяти для массива элементов и инициализация их нулевыми
// значениями
void *AllocArray(
  size_t num,
  size_t size
  );
// Освобождение выделенного буфера памяти
void FreeMem(
  void *memblock
  );
// Обнуление буфера
void __fastcall ZeroMem(
  void *dest,
  size_t count
  );
// Копирование блока памяти
void*
#ifndef _WIN64
__stdcall
#endif  // _WIN64
CopyMem(
  void *dest,
  const void *src,
  size_t count
  );
// Перемещение блока памяти
void*
#ifndef _WIN64
__stdcall
#endif  // _WIN64
MoveMem(
  void *dest,
  const void *src,
  size_t count
  );
// Поиск цепочки байтов в блоке памяти
void*
#ifndef _WIN64
__stdcall
#endif  // _WIN64
SearchMem(
  const void *buf,
  size_t buflen,
  const void *s,
  size_t slen
  );

// Поиск в строке последнего символа
wchar_t *StrRCharW(
  const wchar_t *s,
  wchar_t ch
  );

// Получение имени файла
char *GetFileNameA(
  const char *pszFilePath
  );
// Получение имени файла
wchar_t *GetFileNameW(
  const wchar_t *pszFilePath
  );
#ifdef _UNICODE
#define GetFileName GetFileNameW
#else
#define GetFileName GetFileNameA
#endif  // _UNICODE
//---------------------------------------------------------------------------
#endif  // __STDUTILS_H__
