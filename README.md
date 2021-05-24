# inject_dumper  
  
**PE deobfuscator/dumper**  
  
Hook and log API functions:  
NtResumeThread  
NtGetContextThread  
NtSetContextThread  
NtSetInformationThread  
NtAllocateVirtualMemory  
NtFreeVirtualMemory  
NtWriteVirtualMemory  
NtProtectVirtualMemory  
NtCreateSection  
NtMapViewOfSection  
NtUnmapViewOfSection  
NtCreateUserProcess  
NtTerminateProcess  
LdrLoadDll  
CreateProcessInternalW  
WriteProcessMemory  
GetAdaptersInfo  
ShellExecuteExW  
  
Get memory dumps process injection:  
Portable Executable Injection (T1055.002), Process Hollowing (T1055.012)  

Usage:  
injector_dump target_file \[command line arguments\]

**Run only in VM!**  
