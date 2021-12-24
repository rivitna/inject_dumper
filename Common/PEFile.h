//---------------------------------------------------------------------------
#ifndef __PEFILE_H__
#define __PEFILE_H__
//---------------------------------------------------------------------------
// Коды возврата
#define PE_FILE_OK         0
#define PE_FILE_ERROR      (~(unsigned long)PE_FILE_OK)

#define PE_FILE_CORRUPTED  0x80000000
#define PE_FILE_MZ         0x00000001
#define PE_FILE_PE         0x00000002
#define PE_FILE_EXEC       0x00000004
#define PE_FILE_DLL        0x00000008
#define PE_FILE_64BIT      0x00000010
#define PE_FILE_DOTNET     0x00000020
#define PE_FILE_OVERLAY    0x40000000
//---------------------------------------------------------------------------
// Детектирование PE-файла
unsigned long DetectPEFile(
  HANDLE hFile
  );
// Детектирование PE-файла
unsigned long DetectPEFile(
  const TCHAR *pszFileName
  );
//---------------------------------------------------------------------------
#endif // __PEFILE_H__
