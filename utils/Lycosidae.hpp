#pragma once
#include <iostream>
#include <windows.h>
#include <libloaderapi.h>
#include <winternl.h>
#include <Psapi.h>
#include <xstring>
#include <cassert>

#define DEBUG_READ_EVENT 0x0001
#define DEBUG_PROCESS_ASSIGN 0x0002
#define DEBUG_SET_INFORMATION 0x0004
#define DEBUG_QUERY_INFORMATION 0x0008
#define DEBUG_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | \
    DEBUG_READ_EVENT | DEBUG_PROCESS_ASSIGN | DEBUG_SET_INFORMATION | \
    DEBUG_QUERY_INFORMATION)

typedef struct object_type_information
{
  UNICODE_STRING type_name;
  ULONG total_number_of_handles;
  ULONG total_number_of_objects;
} object_type_information, *pobject_type_information;

typedef struct object_all_information
{
  ULONG number_of_objects;
  object_type_information object_type_information[1];
} object_all_information, *pobject_all_information;

typedef NTSTATUS(NTAPI *p_nt_close)(HANDLE);
typedef NTSTATUS(NTAPI *p_nt_query_information_process)(IN HANDLE, IN UINT, OUT PVOID, IN ULONG, OUT PULONG);
typedef NTSTATUS(WINAPI *p_nt_query_object)(IN HANDLE, IN UINT, OUT PVOID, IN ULONG, OUT PULONG);
typedef NTSTATUS(__stdcall *t_nt_query_system_information)(IN ULONG, OUT PVOID, IN ULONG, OUT PULONG);

BOOL check_remote_debugger_present_api()
{
  auto b_is_dbg_present = FALSE;
  hash_CheckRemoteDebuggerPresent(hash_GetCurrentProcess(), &b_is_dbg_present);
  return b_is_dbg_present;
}

BOOL nt_close_invalide_handle()
{
  const auto nt_close = reinterpret_cast<p_nt_close>(hash_GetProcAddress(hash_GetModuleHandleW(L"ntdll.dll"), "NtClose"));
  __try
  {
    nt_close(reinterpret_cast<HANDLE>(0x99999999ULL));
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    return TRUE;
  }
  return FALSE;
}

BOOL nt_query_information_process_process_debug_flags()
{
  const auto process_debug_flags = 0x1f;
  const auto nt_query_info_process = reinterpret_cast<p_nt_query_information_process>(hash_GetProcAddress(
                                       hash_GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
  unsigned long no_debug_inherit = 0;
  const auto status = nt_query_info_process(hash_GetCurrentProcess(), process_debug_flags, &no_debug_inherit, sizeof(DWORD),
                      nullptr);
  if (status == 0x00000000 && no_debug_inherit == 0)
    return TRUE;
  return FALSE;
}

BOOL nt_query_information_process_process_debug_object()
{
  // ProcessDebugFlags
  const auto process_debug_object_handle = 0x1e;
  const auto nt_query_info_process = reinterpret_cast<p_nt_query_information_process>(hash_GetProcAddress(
                                       hash_GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
  HANDLE h_debug_object = nullptr;
  const unsigned long d_process_information_length = sizeof(ULONG) * 2;
  const auto status = nt_query_info_process(hash_GetCurrentProcess(), process_debug_object_handle, &h_debug_object,
                      d_process_information_length,
                      nullptr);
  if (status == 0x00000000 && h_debug_object)
    return TRUE;
  return FALSE;
}

int FORCEINLINE str_cmp(const wchar_t *x, const wchar_t *y)
{
  while (*x)
  {
    if (*x != *y)
      break;
    x++;
    y++;
  }
  return *static_cast<const wchar_t *>(x) - *static_cast<const wchar_t *>(y);
}

BOOL nt_query_object_object_all_types_information()
{
  //NOTE this check is unreliable, a debugger present on the system doesn't mean it's attached to you
  const auto nt_query_object = reinterpret_cast<p_nt_query_object>(hash_GetProcAddress(
                                 hash_GetModuleHandleW(L"ntdll.dll"), "NtQueryObject"));
  // Some vars
  ULONG size;
  // Get the size of the information needed
  auto status = nt_query_object(nullptr, 3, &size, sizeof(ULONG), &size);
  // Alocate memory for the list
  const auto p_memory = hash_VirtualAlloc(nullptr, (size_t)size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  if (p_memory == nullptr)
    return FALSE;
  // Now we can actually retrieve the list
  status = nt_query_object(reinterpret_cast<HANDLE>(-1), 3, p_memory, size, nullptr);
  // Status != STATUS_SUCCESS
  if (status != 0x00000000)
  {
    hash_VirtualFree(p_memory, 0, MEM_RELEASE);
    return FALSE;
  }
  // We have the information we need
  const auto p_object_all_info = static_cast<pobject_all_information>(p_memory);
  auto p_obj_info_location = reinterpret_cast<UCHAR *>(p_object_all_info->object_type_information);
  const auto num_objects = p_object_all_info->number_of_objects;
  for (UINT i = 0; i < num_objects; i++)
  {
    const auto pObjectTypeInfo = reinterpret_cast<pobject_type_information>(p_obj_info_location);
    // The debug object will always be present
    if (str_cmp((const wchar_t *)(L"DebugObject"),
                (const wchar_t *)(pObjectTypeInfo->type_name.Buffer)) == 0)
    {
      // Are there any objects?
      if (pObjectTypeInfo->total_number_of_objects > 0)
      {
        hash_VirtualFree(p_memory, 0, MEM_RELEASE);
        return TRUE;
      }
      hash_VirtualFree(p_memory, 0, MEM_RELEASE);
      return FALSE;
    }
    // Get the address of the current entries
    // string so we can find the end
    p_obj_info_location = reinterpret_cast<unsigned char *>(pObjectTypeInfo->type_name.Buffer);
    // Add the size
    p_obj_info_location += pObjectTypeInfo->type_name.MaximumLength;
    // Skip the trailing null and alignment bytes
    auto tmp = reinterpret_cast<ULONG_PTR>(p_obj_info_location) & -static_cast<int>(sizeof(void *));
    // Not pretty but it works
    if (static_cast<ULONG_PTR>(tmp) != reinterpret_cast<ULONG_PTR>(p_obj_info_location))
      tmp += sizeof(void *);
    p_obj_info_location = reinterpret_cast<unsigned char *>(tmp);
  }
  hash_VirtualFree(p_memory, 0, MEM_RELEASE);
  return FALSE;
}

BOOL process_job()
{
  auto found_problem = FALSE;
  const DWORD job_process_struct_size = sizeof(JOBOBJECT_BASIC_PROCESS_ID_LIST) + sizeof(ULONG_PTR) * 1024;
  auto job_process_id_list = static_cast<JOBOBJECT_BASIC_PROCESS_ID_LIST *>(malloc(
                               job_process_struct_size));
  if (job_process_id_list)
  {
    SecureZeroMemory(job_process_id_list, job_process_struct_size);
    job_process_id_list->NumberOfProcessIdsInList = 1024;
    if (hash_QueryInformationJobObject(nullptr, JobObjectBasicProcessIdList, job_process_id_list, job_process_struct_size,
                                       nullptr))
    {
      auto ok_processes = 0;
      for (DWORD i = 0; i < job_process_id_list->NumberOfAssignedProcesses; i++)
      {
        const auto process_id = job_process_id_list->ProcessIdList[i];
        // is this the current process? if so that's ok
        if (process_id == static_cast<ULONG_PTR>(hash_GetCurrentProcessId()))
        {
          ok_processes++;
        }
        else
        {
          // find the process name for this job process
          const auto h_job_process = hash_OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, static_cast<DWORD>(process_id));
          if (h_job_process != nullptr)
          {
            const auto process_name_buffer_size = 4096;
            const auto process_name = static_cast<LPTSTR>(malloc(sizeof(TCHAR) * process_name_buffer_size));
            if (process_name)
            {
              RtlSecureZeroMemory(process_name, sizeof(TCHAR) * process_name_buffer_size);
              if (hash_K32GetProcessImageFileNameW(h_job_process, process_name, process_name_buffer_size) > 0)
              {
                std::wstring pnStr(process_name);
                // ignore conhost.exe (this hosts the al-khaser executable in a console)
                if (pnStr.find(static_cast<std::wstring>(L"\\Windows\\System32\\conhost.exe")) != std::string::npos)
                {
                  ok_processes++;
                }
              }
              free(process_name);
            }
            hash_CloseHandle(h_job_process);
          }
        }
      }
      // if we found other processes in the job other than the current process and conhost, report a problem
      found_problem = ok_processes != static_cast<int>(job_process_id_list->NumberOfAssignedProcesses);
    }
    free(job_process_id_list);
  }
  return found_problem;
}

BOOL set_handle_informatiom_protected_handle()
{
  /* Create a mutex so we can get a handle */
  const auto h_mutex = hash_CreateMutexW(nullptr, FALSE, L"923482934823948");
  if (h_mutex)
  {
    /* Protect our handle */
    hash_SetHandleInformation(h_mutex, HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_PROTECT_FROM_CLOSE);
    __try
    {
      /* Then, let's try close it */
      hash_CloseHandle(h_mutex);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
      return TRUE;
    }
  }
  return FALSE;
}

BOOL titan_hide_check()
{
  const auto ntdll = hash_GetModuleHandleW(L"ntdll.dll");
  const auto nt_query_system_information = reinterpret_cast<t_nt_query_system_information>(hash_GetProcAddress(
        ntdll, "NtQuerySystemInformation"));
  SYSTEM_CODEINTEGRITY_INFORMATION c_info;
  c_info.Length = sizeof c_info;
  nt_query_system_information(SystemCodeIntegrityInformation, &c_info, sizeof c_info, nullptr);
  const int ret = c_info.CodeIntegrityOptions & CODEINTEGRITY_OPTION_TESTSIGN || c_info.CodeIntegrityOptions &
                  CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED;
  return ret;
}