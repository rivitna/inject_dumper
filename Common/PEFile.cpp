//---------------------------------------------------------------------------
#define WIN32_LEAN_AND_MEAN  // Exclude rarely-used stuff from Windows headers
#include <windows.h>
#include <winnt.h>
#include "StdUtils.h"
#include "PEFile.h"
//---------------------------------------------------------------------------
// Сигнатура метаданных .NET
#define DOTNET_METADATA_SIGN  0x424A5342  // 'BSJB'
//---------------------------------------------------------------------------
/***************************************************************************/
/* ReadFileData - Чтение данных файла                                      */
/***************************************************************************/
BOOL ReadFileData(
  HANDLE hFile,
  unsigned int nPos,
  unsigned int nSize,
  void *pBuf
  )
{
  if (INVALID_SET_FILE_POINTER == ::SetFilePointer(hFile, (DWORD)nPos, NULL,
                                                   FILE_BEGIN))
    return FALSE;
  DWORD dwBytesRead;
  if (!::ReadFile(hFile, pBuf, nSize, &dwBytesRead, NULL))
    return FALSE;
  if (dwBytesRead != nSize)
    return ::SetLastError(ERROR_INVALID_DATA), FALSE;
  return TRUE;
}
/***************************************************************************/
/* RVAToFilePos - Преобразование RVA в позицию в файле                     */
/***************************************************************************/
unsigned int RVAToFilePos(
  const IMAGE_NT_HEADERS *pPEHdr,
  const IMAGE_SECTION_HEADER *pSectionHdrs,
  unsigned int rva,
  unsigned int size
  )
{
  if (!pPEHdr || !pSectionHdrs)
    return (unsigned int)-1;

  unsigned int nNumSections = pPEHdr->FileHeader.NumberOfSections;
  if (nNumSections == 0)
    return (unsigned int)-1;

  const IMAGE_SECTION_HEADER *pSectionHdr = pSectionHdrs;

  unsigned int nMaxSize;

  nMaxSize = min(pSectionHdr->VirtualAddress, pSectionHdr->PointerToRawData);
  if (rva < nMaxSize)
  {
    if (size <= nMaxSize - rva)
      return rva;
    return (unsigned int)-1;
  }

  unsigned int nSectionAlignment = pPEHdr->OptionalHeader.SectionAlignment;
  unsigned int nFileAlignment = pPEHdr->OptionalHeader.FileAlignment;

  for (unsigned int i = 0; i < nNumSections; i++, pSectionHdr++)
  {
    if ((pSectionHdr->PointerToRawData == 0) ||
        (rva < pSectionHdr->VirtualAddress))
      continue;

    unsigned int nOffset = rva - pSectionHdr->VirtualAddress;
    unsigned int nVirtSize = pSectionHdr->Misc.VirtualSize;
    if (nVirtSize == 0)
      nVirtSize = pSectionHdr->SizeOfRawData;
    nVirtSize = ((nVirtSize + (nSectionAlignment - 1)) / nSectionAlignment) *
                nSectionAlignment;
    unsigned int nPhysSize;
    nPhysSize = ((pSectionHdr->SizeOfRawData + (nFileAlignment - 1)) /
                 nFileAlignment) *
                nFileAlignment;
    nMaxSize = min(nVirtSize, nPhysSize);
    if (nOffset < nMaxSize)
    {
      if (size <= nMaxSize - nOffset)
        return (pSectionHdr->PointerToRawData + nOffset);
      return (unsigned int)-1;
    }
  }

  return (unsigned int)-1;
}
/***************************************************************************/
/* DetectPEDotNETFile - Детектирование PE-файла .NET                       */
/***************************************************************************/
unsigned long DetectPEDotNETFile(
  HANDLE hFile,
  const IMAGE_NT_HEADERS *pPEHdr,
  const IMAGE_SECTION_HEADER *pSectionHdrs
  )
{
  unsigned int nNumRvaAndSizes;
  const IMAGE_DATA_DIRECTORY *pDataDirectory;

  unsigned long res = PE_FILE_OK;

  if (pPEHdr->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
  {
    nNumRvaAndSizes =
      ((PIMAGE_OPTIONAL_HEADER64)&pPEHdr->OptionalHeader)->NumberOfRvaAndSizes;
    pDataDirectory =
      ((PIMAGE_OPTIONAL_HEADER64)&pPEHdr->OptionalHeader)->DataDirectory;
  }
  else
  {
    nNumRvaAndSizes =
      ((PIMAGE_OPTIONAL_HEADER32)&pPEHdr->OptionalHeader)->NumberOfRvaAndSizes;
    pDataDirectory =
      ((PIMAGE_OPTIONAL_HEADER32)&pPEHdr->OptionalHeader)->DataDirectory;
  }

  if (nNumRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)
    return res;

  unsigned int nCLRHdrRVA =
    pDataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress;
  unsigned int cbCLRHdr =
    pDataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size;

  if (nCLRHdrRVA == 0)
    return res;

  struct
  {
    unsigned long   cb;
    unsigned short  wMajorVersion;
    unsigned short  wMinorVersion;
    unsigned long   dwMetadataRVA;
    unsigned long   cbMetadata;
  } clrHdr;

  if (cbCLRHdr < sizeof(clrHdr))
    return (res | PE_FILE_CORRUPTED);

  unsigned int nCLRHdrPos;
  nCLRHdrPos = RVAToFilePos(pPEHdr, pSectionHdrs, nCLRHdrRVA, cbCLRHdr);
  if (nCLRHdrPos == (unsigned int)-1)
    return (res | PE_FILE_CORRUPTED);

  // Чтение части заголовка CLR
  if (!ReadFileData(hFile, nCLRHdrPos, sizeof(clrHdr), &clrHdr))
    return PE_FILE_ERROR;

  if ((cbCLRHdr != clrHdr.cb) ||
      (clrHdr.dwMetadataRVA == 0) ||
      (clrHdr.cbMetadata < sizeof(DWORD)))
    return (res | PE_FILE_CORRUPTED);

  unsigned int nMetadataPos;
  nMetadataPos = RVAToFilePos(pPEHdr, pSectionHdrs, clrHdr.dwMetadataRVA,
                              clrHdr.cbMetadata);
  if (nMetadataPos == (unsigned int)-1)
    return (res | PE_FILE_CORRUPTED);

  // Чтение сигнатуры метаданных
  DWORD dwSign;
  if (!ReadFileData(hFile, nMetadataPos, sizeof(dwSign), &dwSign))
    return PE_FILE_ERROR;

  // Проверка сигнатуры метаданных
  if (dwSign == DOTNET_METADATA_SIGN)
    res |= PE_FILE_DOTNET;

  return res;
}
/***************************************************************************/
/* DetectPEFile - Детектирование PE-файла                                  */
/***************************************************************************/
unsigned long DetectPEFile(
  HANDLE hFile
  )
{
  union
  {
    IMAGE_DOS_HEADER dosHdr;
    IMAGE_NT_HEADERS peHdr;
    IMAGE_NT_HEADERS64 peHdr64;
  };

#pragma pack(push, 1)
  union
  {
    unsigned __int64 nFileSize;
    struct
    {
      unsigned long  dwFileSizeLow;
      unsigned long  dwFileSizeHigh;
    };
  };
#pragma pack(pop)

  dwFileSizeLow = ::GetFileSize(hFile, &dwFileSizeHigh);
  if ((dwFileSizeLow == INVALID_FILE_SIZE) && (::GetLastError() != NO_ERROR))
    return PE_FILE_ERROR;

  // Чтение DOS-заголовка
  if (!ReadFileData(hFile, 0, sizeof(dosHdr), &dosHdr))
    return PE_FILE_ERROR;

  unsigned long res = PE_FILE_OK;

  if (dosHdr.e_magic != IMAGE_DOS_SIGNATURE)
    return res;

  res |= PE_FILE_MZ;

  unsigned int nPEHdrPos = dosHdr.e_lfanew;

  // Чтение PE-заголовка
  if (!ReadFileData(hFile, nPEHdrPos, sizeof(IMAGE_NT_HEADERS64), &peHdr))
    return PE_FILE_ERROR;
  if (peHdr.Signature != IMAGE_NT_SIGNATURE)
    return res;

  res |= PE_FILE_PE;

  if (peHdr.FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)
    res |= PE_FILE_EXEC;
  if (peHdr.FileHeader.Characteristics & IMAGE_FILE_DLL)
    res |= PE_FILE_DLL;
  if (peHdr.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    res |= PE_FILE_64BIT;

  unsigned int nNumSections = peHdr.FileHeader.NumberOfSections;
  if ((nNumSections == 0) ||
      (peHdr.OptionalHeader.SectionAlignment < 2) ||
      (peHdr.OptionalHeader.FileAlignment < 2))
    return (res | PE_FILE_CORRUPTED);

  unsigned int cbSectionHdrs = nNumSections * sizeof(IMAGE_SECTION_HEADER);

  PIMAGE_SECTION_HEADER pSectionHdrs;
  pSectionHdrs = (PIMAGE_SECTION_HEADER)AllocMem(cbSectionHdrs);
  if (!pSectionHdrs)
    return PE_FILE_ERROR;

  unsigned int cbPEHdr = (sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)) +
                         peHdr.FileHeader.SizeOfOptionalHeader;

  // Чтение заголовков секций
  if (ReadFileData(hFile, nPEHdrPos + cbPEHdr, cbSectionHdrs, pSectionHdrs))
  {
    size_t cbPEFileData = 0;

    // Определение размера PE-файла
    for (unsigned int i = 0; i < nNumSections; i++)
    {
      size_t cb = (size_t)pSectionHdrs[i].PointerToRawData +
                  pSectionHdrs[i].SizeOfRawData;
      if (cb > cbPEFileData)
        cbPEFileData = cb;
    }

    if (nFileSize < cbPEFileData)
      res |= PE_FILE_CORRUPTED;
    else if (nFileSize > cbPEFileData)
      res |= PE_FILE_OVERLAY;

    // Детектирование PE-файла .NET
    res |= DetectPEDotNETFile(hFile, &peHdr, pSectionHdrs);
  }
  else
  {
    res = PE_FILE_ERROR;
  }

  FreeMem(pSectionHdrs);

  return res;
}
/***************************************************************************/
/* DetectPEFile - Детектирование PE-файла                                  */
/***************************************************************************/
unsigned long DetectPEFile(
  const TCHAR *pszFileName
  )
{
  HANDLE hFile;

  hFile = ::CreateFile(pszFileName, GENERIC_READ, FILE_SHARE_READ,
                       NULL, OPEN_EXISTING, 0, NULL);
  if (hFile == INVALID_HANDLE_VALUE)
    return PE_FILE_ERROR;

  // Детектирование PE-файла
  unsigned long res = DetectPEFile(hFile);

  ::CloseHandle(hFile);

  return res;
}
//---------------------------------------------------------------------------
