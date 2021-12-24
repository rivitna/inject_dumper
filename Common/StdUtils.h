//---------------------------------------------------------------------------
#ifndef __STDUTILS_H__
#define __STDUTILS_H__
//---------------------------------------------------------------------------
// ��������� ������ ������
void *AllocMem(
  size_t size
  );
// ��������� ������� ������ ������
void *ReAllocMem(
  void *memblock,
  size_t size
  );
// ��������� ������ ��� ������� ��������� � ������������� �� ��������
// ����������
void *AllocArray(
  size_t num,
  size_t size
  );
// ������������ ����������� ������ ������
void FreeMem(
  void *memblock
  );
// ��������� ������
void __fastcall ZeroMem(
  void *dest,
  size_t count
  );
// ����������� ����� ������
void*
#ifndef _WIN64
__stdcall
#endif  // _WIN64
CopyMem(
  void *dest,
  const void *src,
  size_t count
  );
// ����������� ����� ������
void*
#ifndef _WIN64
__stdcall
#endif  // _WIN64
MoveMem(
  void *dest,
  const void *src,
  size_t count
  );
// ����� ������� ������ � ����� ������
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

// ����� � ������ ���������� �������
wchar_t *StrRCharW(
  const wchar_t *s,
  wchar_t ch
  );

// ��������� ����� �����
char *GetFileNameA(
  const char *pszFilePath
  );
// ��������� ����� �����
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
