//---------------------------------------------------------------------------
#define WIN32_LEAN_AND_MEAN  // Exclude rarely-used stuff from Windows headers
#include <windows.h>
#include "StdUtils.h"
//---------------------------------------------------------------------------
/***************************************************************************/
/* AllocMem - Выделение буфера памяти                                      */
/***************************************************************************/
void *AllocMem(
  size_t size
  )
{
  return ::HeapAlloc(::GetProcessHeap(), 0, size);
}
/***************************************************************************/
/* ReAllocMem - Изменение размера буфера памяти                            */
/***************************************************************************/
void *ReAllocMem(
  void *memblock,
  size_t size
  )
{
  if (!memblock)
  {
    // Выделение буфера памяти
    return AllocMem(size);
  }
  return ::HeapReAlloc(::GetProcessHeap(), 0, memblock, size);
}
/***************************************************************************/
/* AllocArray - Выделение памяти для массива элементов и инициализация их  */
/*              нулевыми значениями                                        */
/***************************************************************************/
void *AllocArray(
  size_t num,
  size_t size
  )
{
  return ::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, num * size);
}
/***************************************************************************/
/* FreeMem - Освобождение выделенного буфера памяти                        */
/***************************************************************************/
void FreeMem(
  void *memblock
  )
{
  if (memblock)
    ::HeapFree(::GetProcessHeap(), 0, memblock);
}
/***************************************************************************/
/* ZeroMem - Обнуление буфера                                              */
/***************************************************************************/
#ifndef _WIN64
__declspec(naked)
#endif  // _WIN64
void __fastcall ZeroMem(
  void *dest,
  size_t count
  )
{
#ifdef _WIN64
  while (count != 0)
  {
    *(unsigned char *)dest = 0;
    dest = (unsigned char *)dest + 1;
    count--;
  }
#else
  __asm
  {
    push  edi
    mov   edi,ecx
    mov   ecx,edx
    xor   eax,eax
    shr   ecx,2
    rep   stosd
    mov   ecx,edx
    and   ecx,3
    rep   stosb
    pop   edi
    ret
  }
#endif  // _WIN64
}
/***************************************************************************/
/* CopyMem - Копирование блока памяти                                      */
/***************************************************************************/
#ifndef _WIN64
__declspec(naked)
#endif  // _WIN64
void*
#ifndef _WIN64
__stdcall
#endif  // _WIN64
CopyMem(
  void *dest,
  const void *src,
  size_t count
  )
{
#ifdef _WIN64
  while (count != 0)
  {
    *(unsigned char *)dest = *(unsigned char *)src;
    dest = (unsigned char *)dest + 1;
    src = (unsigned char *)src + 1;
    count--;
  }
  return dest;
#else
  __asm
  {
    push  esi
    push  edi
    mov   esi,[esp+10h]         // ESI = src
    mov   edi,[esp+0Ch]         // EDI = dest
    mov   ecx,[esp+14h]         // ECX = count
    mov   edx,ecx               // EDX = count
    shr   ecx,2
    rep   movsd
    mov   ecx,edx
    and   ecx,3
    rep   movsb
    mov   eax,[esp+0Ch]         // EAX = dest
    pop   edi
    pop   esi
    ret   12
  }
#endif  // _WIN64
}
/***************************************************************************/
/* MoveMem - Перемещение блока памяти                                      */
/***************************************************************************/
#ifndef _WIN64
__declspec(naked)
#endif  // _WIN64
void*
#ifndef _WIN64
__stdcall
#endif  // _WIN64
MoveMem(
  void *dest,
  const void *src,
  size_t count
  )
{
#ifdef _WIN64
  if ((dest <= src) ||
      ((unsigned char *)dest >= ((unsigned char *)src + count)))
  {
    while (count != 0)
    {
      *(unsigned char *)dest = *(unsigned char *)src;
      dest = (unsigned char *)dest + 1;
      src = (unsigned char *)src + 1;
      count--;
    }
  }
  else
  {
    dest = (unsigned char *)dest + count - 1;
    src = (unsigned char *)src + count - 1;
    while (count != 0)
    {
      *(unsigned char *)dest = *(unsigned char *)src;
      dest = (unsigned char *)dest - 1;
      src = (unsigned char *)src - 1;
      count--;
    }
  }
  return dest;
#else
  __asm
  {
    push  esi
    push  edi
    mov   ecx,[esp+14h]         // ECX = count
    jecxz Done
    mov   edx,ecx               // EDX = count
    mov   esi,[esp+10h]         // ESI = src
    mov   edi,[esp+0Ch]         // EDI = dest
    cmp   edi,esi               // dest < src?
    jb    Copy
    je    Done

    lea   eax,[esi+ecx-1]
    cmp   edi,eax
    ja    Copy
    mov   esi,eax
    lea   edi,[edi+ecx-1]
    std
    and   ecx,3
    rep   movsb
    mov   ecx,edx
    shr   ecx,2
    sub   esi,3
    sub   edi,3
    rep   movsd
    cld
    jmp   Done

Copy:
    shr   ecx,2
    rep   movsd
    mov   ecx,edx
    and   ecx,3
    rep   movsb

Done:
    mov   eax,[esp+0Ch]         // EDI = dest
    pop   edi
    pop   esi
    ret   12
  }
#endif  // _WIN64
}
/***************************************************************************/
/* SearchMem - Поиск цепочки байтов в блоке памяти                         */
/***************************************************************************/
#ifndef _WIN64
__declspec(naked)
#endif  // _WIN64
void*
#ifndef _WIN64
__stdcall
#endif  // _WIN64
SearchMem(
  const void *buf,
  size_t buflen,
  const void *s,
  size_t slen
  )
{
#ifdef _WIN64
  size_t i;
  size_t j;
  unsigned char *pb;
  unsigned char *ps;

  if ((slen == 0) || (slen > buflen))
    return NULL;
  i = buflen - slen + 1;
  do
  {
    j = slen;
    pb = (unsigned char *)buf;
    ps = (unsigned char *)s;
    while (*pb == *ps)
    {
      j--;
      if (j == 0)
        return (void *)buf;
      pb++;
      ps++;
    }
    buf = (unsigned char *)buf + 1;
    i--;
  } while (i != 0);
  return NULL;
#else
  __asm
  {
    push  ebp
    push  ebx
    push  esi
    push  edi

    mov   ebx,[esp+14h]         // EBX = buf
    mov   ebp,[esp+1Ch]         // EBP = s
    mov   edx,[esp+18h]         // EDX = buflen
    mov   eax,[esp+20h]         // EAX = slen
    or    eax,eax
    jz    NotFound
    sub   edx,eax
    jb    NotFound
    inc   edx                   // EDX = число циклов

SearchLoop:
    mov   esi,ebp               // ESI = s
    mov   edi,ebx               // EDI = текущий указатель в буфере
    mov   ecx,eax               // ECX = slen
    shr   ecx,2
    repe  cmpsd
    jne   NextByte
    mov   ecx,eax
    and   ecx,3
    repe  cmpsb
    je    Done
NextByte:
    inc   ebx
    dec   edx
    jnz   SearchLoop

NotFound:
    xor   ebx,ebx

Done:
    mov   eax,ebx

    pop   edi
    pop   esi
    pop   ebx
    pop   ebp
    ret   16
  }
#endif  // _WIN64
}
/***************************************************************************/
/* StrRCharW - Поиск в строке последнего символа                           */
/***************************************************************************/
wchar_t *StrRCharW(
  const wchar_t *s,
  wchar_t ch
  )
{
  wchar_t *pch = NULL;
  while (*s != L'\0')
  {
    if (*s == ch) pch = (wchar_t *)s;
    s++;
  }
  return pch;
}
/***************************************************************************/
/* GetFileNameA - Получение имени файла                                    */
/***************************************************************************/
char *GetFileNameA(
  const char *pszFilePath
  )
{
  if (!pszFilePath || !pszFilePath[0])
    return NULL;
  const char *pchDelim = NULL;
  const char *pch = pszFilePath;
  while (*pch)
  {
    if ((*pch == ':') || (*pch == '\\') || (*pch == '/'))
      pchDelim = pch;
    pch++;
  }
  if (!pchDelim)
    return (char *)pszFilePath;
  return (char *)(pchDelim + 1);
}
/***************************************************************************/
/* GetFileNameW - Получение имени файла                                    */
/***************************************************************************/
wchar_t *GetFileNameW(
  const wchar_t *pszFilePath
  )
{
  if (!pszFilePath || !pszFilePath[0])
    return NULL;
  const wchar_t *pchDelim = NULL;
  const wchar_t *pch = pszFilePath;
  while (*pch)
  {
    if ((*pch == L':') || (*pch == L'\\') || (*pch == L'/'))
      pchDelim = pch;
    pch++;
  }
  if (!pchDelim)
    return (wchar_t *)pszFilePath;
  return (wchar_t *)(pchDelim + 1);
}
//---------------------------------------------------------------------------
