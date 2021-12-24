//---------------------------------------------------------------------------
#define WIN32_LEAN_AND_MEAN  // Exclude rarely-used stuff from Windows headers
#include <windows.h>
#include <winnt.h>
#include <tchar.h>
#include "StdUtils.h"
#include "ProcInj.h"
//---------------------------------------------------------------------------
// Размер кода перехода на абсолютный адрес
// mov  eax, OFFSET NewProc / mov  rax, OFFSET NewProc
// jmp  eax / jmp  rax
#ifdef _WIN64
#define JMP_CODE_ADDR_OFFSET  sizeof(WORD)
#else
#define JMP_CODE_ADDR_OFFSET  1
#endif  // _WIN64
#define JMP_CODE_SIZE  \
  (JMP_CODE_ADDR_OFFSET + sizeof(INT_PTR) + sizeof(WORD))

// Размер кода внедрения DLL
#ifdef _WIN64
#ifdef _UNICODE
#define DLL_INJECT_CODE_SIZE  30
#else
#define DLL_INJECT_CODE_SIZE  29
#endif  // _UNICODE
#else
#ifdef _UNICODE
#define DLL_INJECT_CODE_SIZE  25
#else
#define DLL_INJECT_CODE_SIZE  23
#endif  // _UNICODE
#endif  // _WIN64
#define MAX_DLL_INJECT_CODE_SIZE  (DLL_INJECT_CODE_SIZE + \
                                   MAX_PATH * sizeof(TCHAR))
//---------------------------------------------------------------------------
/***************************************************************************/
/* GetTargetProcessImageInfo - Получение информации об образе целевого     */
/*                             процесса                                    */
/***************************************************************************/
BOOL GetTargetProcessImageInfo(
  INT_PTR pBaseAddress,
  HANDLE hProcess,
  PTARGET_PROCESS_IMAGE_INFO pProcImgInfo
  )
{
  if (!pBaseAddress || !pProcImgInfo)
    return FALSE;

  SIZE_T nBytesRead;

  union
  {
    IMAGE_DOS_HEADER dosHdr;
    IMAGE_NT_HEADERS peHdr;
  };

  // Чтение DOS-заголовка
  if (!::ReadProcessMemory(hProcess, (LPCVOID)pBaseAddress, &dosHdr,
                           sizeof(dosHdr), &nBytesRead) ||
      (nBytesRead != sizeof(dosHdr)) ||
      (dosHdr.e_magic != IMAGE_DOS_SIGNATURE))
    return FALSE;

  // Определение адреса PE-заголовка
  unsigned int nPEHdrRVA = (unsigned int)dosHdr.e_lfanew;
  INT_PTR pPEHdr = pBaseAddress + nPEHdrRVA;

  // Чтение PE-заголовка
  if (!::ReadProcessMemory(hProcess, (LPCVOID)pPEHdr, &peHdr, sizeof(peHdr),
                           &nBytesRead) ||
      (nBytesRead != sizeof(peHdr)) ||
      (peHdr.Signature != IMAGE_NT_SIGNATURE))
    return FALSE;

  unsigned int nEntryPointRVA = peHdr.OptionalHeader.AddressOfEntryPoint;
  if (nEntryPointRVA == 0)
    return FALSE;

  unsigned int nPEHdrSize = (sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)) +
                            peHdr.FileHeader.SizeOfOptionalHeader;
  unsigned int nNumSections = peHdr.FileHeader.NumberOfSections;

  IMAGE_SECTION_HEADER sectionHdr;

  unsigned int i = nNumSections;
  INT_PTR pSectionHdr = pPEHdr + nPEHdrSize;
  while (i != 0)
  {
    // Чтение секции
    if (!::ReadProcessMemory(hProcess, (LPCVOID)pSectionHdr, &sectionHdr,
                             sizeof(sectionHdr), &nBytesRead) ||
        (nBytesRead != sizeof(sectionHdr)))
      return FALSE;
    if ((sectionHdr.Characteristics & (IMAGE_SCN_MEM_EXECUTE)) &&
        (nEntryPointRVA >= sectionHdr.VirtualAddress) &&
        (nEntryPointRVA - sectionHdr.VirtualAddress <
           sectionHdr.Misc.VirtualSize))
      break;
    i--;
    pSectionHdr += sizeof(IMAGE_SECTION_HEADER);
  }
  if (i == 0)
    return FALSE;

  pProcImgInfo->nPEHdrRVA = nPEHdrRVA;
  pProcImgInfo->nPEHdrSize = nPEHdrSize;
  pProcImgInfo->nEntryPointRVA = nEntryPointRVA;
  pProcImgInfo->nNumSections = nNumSections;
  pProcImgInfo->nCodeSectionFreeAreaRVA = sectionHdr.VirtualAddress +
                                          sectionHdr.Misc.VirtualSize;
  unsigned int nSectionAlignment = peHdr.OptionalHeader.SectionAlignment;
  pProcImgInfo->nCodeSectionEndRVA = sectionHdr.VirtualAddress +
                                     (((sectionHdr.Misc.VirtualSize +
                                        (nSectionAlignment - 1)) /
                                       nSectionAlignment) *
                                      nSectionAlignment);

  return TRUE;
}
/***************************************************************************/
/* InjectCodeToProcess - Внедрение кода в процесс                          */
/***************************************************************************/
BOOL InjectCodeToProcess(
  HANDLE hProcess,
  HANDLE hThread,
  const void *pCode,
  size_t cbCode
  )
{
  if (!pCode || (cbCode == 0))
    return FALSE;

  CONTEXT ctx;

  // Получение контекста потока для определения адреса PEB
  ctx.ContextFlags = CONTEXT_FULL;
  if (!::GetThreadContext(hThread, &ctx))
    return FALSE;

  INT_PTR pBaseAddress;

  INT_PTR p;
#ifdef _WIN64
  p = ctx.Rdx + 0x10;
#else
  p = ctx.Ebx + 8;
#endif  // _WIN64

  // Получение базового адреса
  SIZE_T nBytesRead;
  if (!::ReadProcessMemory(hProcess, (LPCVOID)p, &pBaseAddress,
                           sizeof(INT_PTR), &nBytesRead) ||
      (nBytesRead != sizeof(INT_PTR)))
    return FALSE;

  TARGET_PROCESS_IMAGE_INFO procImgInfo;

  // Получение информации об образе процесса
  if (!GetTargetProcessImageInfo(pBaseAddress, hProcess, &procImgInfo))
    return FALSE;

  INT_PTR pEntryPoint = pBaseAddress + procImgInfo.nEntryPointRVA;

  SIZE_T cbInjectCode = cbCode + JMP_CODE_SIZE;
  INT_PTR pInjectCode;

  void *pMem = NULL;

  DWORD flOldProtect;

  // Выравнивание кода по границе двойного слова
  unsigned int nInjectCodeRVA =
    (procImgInfo.nCodeSectionFreeAreaRVA + (4 - 1)) & (~(4 - 1));

  if ((nInjectCodeRVA < procImgInfo.nCodeSectionEndRVA) &&
      (cbInjectCode <= procImgInfo.nCodeSectionEndRVA - nInjectCodeRVA))
  {
    // Использование свободной области кодовой секции для внедряемого кода
    pInjectCode = pBaseAddress + nInjectCodeRVA;
    if (!::VirtualProtectEx(hProcess, (LPVOID)pInjectCode, cbInjectCode,
                            PAGE_READWRITE, &flOldProtect))
      return FALSE;
  }
  else
  {
    // Выделение памяти в процессе для внедряемого кода
    pMem = ::VirtualAllocEx(hProcess, NULL, cbInjectCode,
                            MEM_RESERVE | MEM_COMMIT,
                            PAGE_EXECUTE_READWRITE);
    if (!pMem)
      return FALSE;
    pInjectCode = (INT_PTR)pMem;
  }

  BOOL bError = FALSE;

  unsigned char jmpCode[JMP_CODE_SIZE];
#ifdef _WIN64
  // mov rax, OFFSET EntryPoint
  *((WORD *)&jmpCode[0]) = 0xB848;
#else
  // mov eax, OFFSET EntryPoint
  jmpCode[0] = 0xB8;
#endif  // _WIN64
  *((INT_PTR *)&jmpCode[JMP_CODE_ADDR_OFFSET]) = pEntryPoint;
  // jmp rax
  *((WORD *)&jmpCode[JMP_CODE_ADDR_OFFSET + sizeof(INT_PTR)]) = 0xE0FF;

  // Копирование внедряемого кода и кода перехода на оригинальную точку входа
  SIZE_T nBytesWritten;
  if (!(::WriteProcessMemory(hProcess, (LPVOID)pInjectCode, pCode, cbCode,
                             &nBytesWritten) &&
        (nBytesWritten == cbCode)) ||
      !(::WriteProcessMemory(hProcess,
                             (LPVOID)((INT_PTR)pInjectCode + cbCode),
                             jmpCode, JMP_CODE_SIZE, &nBytesWritten) &&
        (nBytesWritten == JMP_CODE_SIZE)))
  {
    bError = TRUE;
  }

  if (!pMem)
  {
    if (!::VirtualProtectEx(hProcess, (LPVOID)pInjectCode, cbInjectCode,
                            flOldProtect, &flOldProtect))
      bError = TRUE;
  }

  if (!bError)
  {
    // Изменение адреса точки входа процесса
#ifdef _WIN64
    ctx.Rax = pInjectCode;
#else
    ctx.Eax = pInjectCode;
#endif  // _WIN64
    if (!::SetThreadContext(hThread, &ctx))
      bError = TRUE;
  }

  if (bError)
  {
    if (pMem)
    {
      // Освобождение выделенной памяти
      ::VirtualFreeEx(hProcess, pMem, 0, MEM_RELEASE);
    }
    return FALSE;
  }

  return TRUE;
}
/***************************************************************************/
/* InjectCodeToProcessAsRemoteThread - Внедрение кода в процесс в виде     */
/*                                     удаленного потока                   */
/***************************************************************************/
BOOL InjectCodeToProcessAsRemoteThread(
  HANDLE hProcess,
  const void *pCode,
  size_t cbCode,
  BOOL bWait,
  DWORD *pdwExitCode
  )
{
  if (!pCode || (cbCode == 0))
    return FALSE;

  LPVOID pInjectCode;

  // Выделение памяти в процессе для внедряемого кода
  pInjectCode = ::VirtualAllocEx(hProcess, NULL, cbCode,
                                 MEM_RESERVE | MEM_COMMIT,
                                 PAGE_EXECUTE_READWRITE);
  if (!pInjectCode)
    return FALSE;

  BOOL bSuccess = FALSE;

  // Копирование внедряемого кода
  SIZE_T nBytesWritten;
  if (::WriteProcessMemory(hProcess, pInjectCode, pCode, cbCode,
                           &nBytesWritten) &&
      (nBytesWritten == cbCode))
  {
    // Выполнение кода
    HANDLE hThread;
    hThread = ::CreateRemoteThread(hProcess, NULL, 0,
                                   (LPTHREAD_START_ROUTINE)pInjectCode,
                                   NULL, 0, NULL);
    if (hThread)
    {
      if (bWait)
        ::WaitForSingleObject(hThread, INFINITE);
      if (pdwExitCode)
        ::GetExitCodeThread(hThread, pdwExitCode);
      ::CloseHandle(hThread);
      bSuccess = TRUE;
    }
  }

  if (!bSuccess || bWait)
  {
    // Освобождение выделенной памяти
    ::VirtualFreeEx(hProcess, pInjectCode, 0, MEM_RELEASE);
  }

  return bSuccess;
}
/***************************************************************************/
/* CreateProcessAndInjectCode - Запуск процесса и внедрение в него кода    */
/***************************************************************************/
BOOL CreateProcessAndInjectCode(
  const TCHAR *pszAppName,
  TCHAR *pszCmdLine,
  const void *pCode,
  size_t cbCode,
  BOOL bUseRemoteThread,
  BOOL bWait,
  DWORD *pdwExitCode
  )
{
  if (((!pszAppName || !pszAppName[0]) && (!pszCmdLine || !pszCmdLine[0])) ||
      !pCode || (cbCode == 0))
    return FALSE;

  STARTUPINFO si;
  PROCESS_INFORMATION pi;
  ZeroMem(&si, sizeof(si));

  si.cb = sizeof(STARTUPINFO);
  si.dwFlags = STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;
  if (!::CreateProcess(pszAppName, pszCmdLine, NULL, NULL, FALSE,
                       CREATE_SUSPENDED, NULL, NULL, &si, &pi))
    return FALSE;

  BOOL bError = FALSE;

  if (bUseRemoteThread)
  {
    // Внедрение кода в процесс в виде удаленного потока
    DWORD dwExitCode = 0;
    if (!InjectCodeToProcessAsRemoteThread(pi.hProcess, pCode, cbCode, TRUE,
                                           &dwExitCode) ||
        (dwExitCode == 0))
      bError = TRUE;
  }
  else
  {
    // Внедрение кода в процесс
    if (!InjectCodeToProcess(pi.hProcess, pi.hThread, pCode, cbCode))
      bError = TRUE;
  }

  if (!bError)
  {
    // Возобновление основного потока
    if (::ResumeThread(pi.hThread))
    {
      if (bWait)
        ::WaitForSingleObject(pi.hProcess, INFINITE);
      if (pdwExitCode)
        ::GetExitCodeProcess(pi.hProcess, pdwExitCode);
    }
    else
    {
      bError = TRUE;
    }
  }

  if (bError)
  {
    // Завершение процесса
    ::TerminateProcess(pi.hProcess, 0);
  }

  ::CloseHandle(pi.hProcess);
  ::CloseHandle(pi.hThread);

  return !bError;
}
/***************************************************************************/
/* CreateProcessAndInjectDll - Запуск процесса и внедрение в него DLL      */
/***************************************************************************/
BOOL CreateProcessAndInjectDll(
  const TCHAR *pszAppName,
  TCHAR *pszCmdLine,
  const TCHAR *pszDllName,
  BOOL bUseRemoteThread,
  BOOL bWait
  )
{
  if (((!pszAppName || !pszAppName[0]) && (!pszCmdLine || !pszCmdLine[0])) ||
      !pszDllName || !pszDllName[0])
    return FALSE;

  HMODULE hKernel32Lib = ::GetModuleHandle(_T("KERNEL32.DLL"));
  if (!hKernel32Lib)
    return FALSE;

  INT_PTR pfnLoadLibrary;
#ifdef _UNICODE
  pfnLoadLibrary = (INT_PTR)::GetProcAddress(hKernel32Lib, "LoadLibraryW");
#else
  pfnLoadLibrary = (INT_PTR)::GetProcAddress(hKernel32Lib, "LoadLibraryA");
#endif  // _UNICODE
  if (!pfnLoadLibrary)
    return FALSE;

  unsigned char injectCode[MAX_DLL_INJECT_CODE_SIZE];

  unsigned char *p = injectCode;

#ifdef _WIN64
  // mov   rax, OFFSET LoadLibrary
  *((WORD *)p) = 0xB848;
  p += sizeof(WORD);
#else
  // mov   eax, OFFSET LoadLibrary
  *p++ = 0xB8;
#endif  // _WIN64
  *((INT_PTR *)p) = pfnLoadLibrary;
  p += sizeof(INT_PTR);

#ifdef _UNICODE
  // Выравнивание строки с именем библиотеки
#ifdef _WIN64
  // nop
  *p++ = 0x90;
#else
  // nop
  // nop
  *((WORD *)p) = 0x9090;
  p += sizeof(WORD);
#endif  // _WIN64
#endif  // _UNICODE

  // call  $ + LEN dll_path
  *p++ = 0xE8;
  unsigned int cbDllName = (::lstrlen(pszDllName) + 1) * sizeof(TCHAR);
  *((DWORD *)p) = (DWORD)cbDllName;
  p += sizeof(DWORD);
  CopyMem(p, pszDllName, cbDllName);
  p += cbDllName;

#ifdef _WIN64
  // pop   rcx
  // call  rax
  // or    rax, rax
  *((DWORD *)p) = 0x48D0FF59;
  p += sizeof(DWORD);
  if (bUseRemoteThread)
  {
    // or    rax, rax
    // setnz al
    // movzx eax, al
    // retn
    *((DWORD *)p) = 0x950FC009;
    p += sizeof(DWORD);
    *((DWORD *)p) = 0xC0B60FC0;
    p += sizeof(DWORD);
    *p++ = 0xC3;
  }
  else
  {
    // or    rax, rax
    // jnz   $+6
    // mov   eax, 0DEADBEEFh
    // retn
    *((DWORD *)p) = 0x0675C009;
    p += sizeof(DWORD);
    *((DWORD *)p) = 0xADBEEFB8;
    p += sizeof(DWORD);
    *((WORD *)p) = 0xC3DE;
    p += sizeof(WORD);
  }
#else
  // call  eax
  // or    eax, eax
  *((DWORD *)p) = 0xC009D0FF;
  p += sizeof(DWORD);
  if (bUseRemoteThread)
  {
    // setnz al
    // movzx eax, al
    // retn  4
    *((DWORD *)p) = 0x0FC0950F;
    p += sizeof(DWORD);
    *((DWORD *)p) = 0x04C2C0B6;
    p += sizeof(DWORD);
    *p++ = 0x00;
  }
  else
  {
    // jnz   $+6
    // mov   eax, 0DEADBEEFh
    // retn
    *((DWORD *)p) = 0xEFB80675;
    p += sizeof(DWORD);
    *((DWORD *)p) = 0xC3DEADBE;
    p += sizeof(DWORD);
  }
#endif  // _WIN64

  // Запуск процесса и внедрение в него кода
  DWORD dwExitCode;
  if (CreateProcessAndInjectCode(pszAppName, pszCmdLine, &injectCode,
                                 p - injectCode, bUseRemoteThread, bWait,
                                 &dwExitCode) &&
      (bUseRemoteThread || (dwExitCode != 0xDEADBEEF)))
    return TRUE;
  return FALSE;
}
//---------------------------------------------------------------------------
