//#define LYCOSIDAE_LOG
#define SCYLLAHIDE_DETECTOR_LOG
#include "utils/ScyllaHideDetector.hpp"
#include "utils/Lycosidae.hpp"

int main()
{
  /* Settings */
  const auto enable_scyllahide_detector = 1;
  const auto enable_debug_checks = 1;
  /* ScyllaHide bypass */
  if (enable_scyllahide_detector)
  {
    ntdll_restore((LPCSTR)PRINT_HIDE_STR("NtYieldExecution"));
    ntdll_restore((LPCSTR)PRINT_HIDE_STR("NtSetInformationThread"));
    ntdll_restore((LPCSTR)PRINT_HIDE_STR("NtSetInformationProcess"));
    ntdll_restore((LPCSTR)PRINT_HIDE_STR("NtQuerySystemInformation"));
    ntdll_restore((LPCSTR)PRINT_HIDE_STR("NtQueryInformationProcess"));
    ntdll_restore((LPCSTR)PRINT_HIDE_STR("NtQueryObject"));
    ntdll_restore((LPCSTR)PRINT_HIDE_STR("NtCreateThreadEx"));
    ntdll_restore((LPCSTR)PRINT_HIDE_STR("NtSetDebugFilterState"));
    ntdll_restore((LPCSTR)PRINT_HIDE_STR("NtClose"));
    ntdll_restore((LPCSTR)PRINT_HIDE_STR("NtQueryPerformanceCounter"));
    ntdll_restore((LPCSTR)PRINT_HIDE_STR("NtGetContextThread"));
    ntdll_restore((LPCSTR)PRINT_HIDE_STR("NtSetContextThread"));
    //TODO: make this workable
    //ntdll_restore("NtQuerySystemTime");
    kernelbase_restore((LPCSTR)PRINT_HIDE_STR("GetTickCount"));
    kernelbase_restore((LPCSTR)PRINT_HIDE_STR("GetTickCount64"));
    kernelbase_restore((LPCSTR)PRINT_HIDE_STR("OutputDebugStringA"));
    kernelbase_restore((LPCSTR)PRINT_HIDE_STR("GetLocalTime"));
    kernelbase_restore((LPCSTR)PRINT_HIDE_STR("GetSystemTime"));
    kernelbase_restore((LPCSTR)PRINT_HIDE_STR("GetSystemTimeAsFileTime"));
    user32_restore((LPCSTR)PRINT_HIDE_STR("NtUserBlockInput"));
    user32_restore((LPCSTR)PRINT_HIDE_STR("NtUserQueryWindow"));
    user32_restore((LPCSTR)PRINT_HIDE_STR("NtUserFindWindowEx"));
    user32_restore((LPCSTR)PRINT_HIDE_STR("NtUserBuildHwndList"));
    // additional
    user32_restore((LPCSTR)PRINT_HIDE_STR("BlockInput"));
    kernelbase_restore((LPCSTR)PRINT_HIDE_STR("CheckRemoteDebuggerPresent"));
    kernelbase_restore((LPCSTR)PRINT_HIDE_STR("OutputDebugString"));
    kernelbase_restore((LPCSTR)PRINT_HIDE_STR("OutputDebugStringW"));
  }
  /* Debugger Detection */
  if (enable_debug_checks)
  {
    if (nt_close_invalide_handle() != FALSE)
    {
#ifndef LYCOSIDAE_LOG
      log((LPCSTR)PRINT_HIDE_STR("CloseHandle with an invalide handle detected\r\n"));
#endif
    }
    if (set_handle_informatiom_protected_handle() != FALSE)
    {
#ifndef LYCOSIDAE_LOG
      log((LPCSTR)PRINT_HIDE_STR("CloseHandle protected handle trick  detected\r\n"));
#endif
    }
    if (check_remote_debugger_present_api() != FALSE)
    {
#ifndef LYCOSIDAE_LOG
      log((LPCSTR)PRINT_HIDE_STR("CheckRemoteDebuggerPresent detected\r\n"));
#endif
    }
    if (nt_query_information_process_process_debug_flags() != FALSE)
    {
#ifndef LYCOSIDAE_LOG
      log((LPCSTR)PRINT_HIDE_STR("NtQueryInformationProcess with ProcessDebugFlags detected\r\n"));
#endif
    }
    if (nt_query_information_process_process_debug_object() != FALSE)
    {
#ifndef LYCOSIDAE_LOG
      log((LPCSTR)PRINT_HIDE_STR("NtQueryInformationProcess with ProcessDebugObject detected\r\n"));
#endif
    }
    if (nt_query_object_object_all_types_information() != FALSE)
    {
#ifndef LYCOSIDAE_LOG
      log((LPCSTR)PRINT_HIDE_STR("NtQueryObject with ObjectAllTypesInformation detected\r\n"));
#endif
    }
    if (process_job() != FALSE)
    {
#ifndef LYCOSIDAE_LOG
      log((LPCSTR)PRINT_HIDE_STR("If process is in a job detected\r\n"));
#endif
    }
    // TitanHide detection
    if (titan_hide_check() != FALSE)
    {
#ifndef LYCOSIDAE_LOG
      log((LPCSTR)PRINT_HIDE_STR("TitanHide detected\r\n"));
#endif
    }
    if (NtQuerySystemInformation_SystemKernelDebuggerInformation() != FALSE)
    {
#ifndef LYCOSIDAE_LOG
      log((LPCSTR)PRINT_HIDE_STR("NtQuerySystemInformation_SystemKernelDebuggerInformation detected\r\n"));
#endif
    }
    if (SharedUserData_KernelDebugger() != FALSE)
    {
#ifndef LYCOSIDAE_LOG
      log((LPCSTR)PRINT_HIDE_STR("SharedUserData_KernelDebugger detected\r\n"));
#endif
    }
  }
  log((LPCSTR)PRINT_HIDE_STR("Foo program. Check source code.\r\n"));
  getchar();
  return 0;
}
