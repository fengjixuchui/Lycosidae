#include <Windows.h>
#include <winternl.h>
#include <iostream>

// Super Hide String
#include "hidestr/hide_str.hpp"

#include "Native.hpp"
#include "Hash.hpp"
#include "Helpers.hpp"
#include "crc32.hpp"
#include "LengthDisasm.hpp"
#include <vector>

void ntdll_restore(const char *func_name)
{
  const auto ntdll = GET_MODULE_BASE_ADDRESS(L"ntdll.dll");
  PVOID ntdll_mapped = nullptr;
  MAP_NATIVE_MODULE("ntdll.dll", &ntdll_mapped);
  const auto hooked_func_adress = resolve_jmp(get_proc_address(ntdll, HASHSTR(func_name)), 1);
  const auto hooked_func_size = static_cast<size_t>(get_size_of_proc(hooked_func_adress, 1));
  const auto crc_hooked = crc32(hooked_func_adress, static_cast<unsigned int>(hooked_func_size));
  const auto original_func_adress = resolve_jmp(get_proc_address(ntdll_mapped, HASHSTR(func_name)), 1);
  const auto original_func_size = static_cast<size_t>(get_size_of_proc(original_func_adress, 1));
  const auto crc_original = crc32(original_func_adress, static_cast<unsigned int>(original_func_size));
  // detect hook and restore bytes
  if (crc_original != crc_hooked)
  {
#ifndef SCYLLAHIDE_DETECTOR_LOG
    log("[Detect] " + static_cast<std::string>(func_name) + "\r\n");
#endif
    DWORD oldprotect = 0;
    hash_VirtualProtect(hooked_func_adress, hooked_func_size, PAGE_EXECUTE_READWRITE, &oldprotect);
    memcpy(hooked_func_adress, original_func_adress, hooked_func_size);
    hash_VirtualProtect(hooked_func_adress, hooked_func_size, oldprotect, &oldprotect);
  }
  else
  {
#ifndef SCYLLAHIDE_DETECTOR_LOG
    log("[Ok] " + static_cast<std::string>(func_name) + "\r\n");
#endif
  }
}

void kernelbase_restore(const char *func_name)
{
  const auto kernelbase = GET_MODULE_BASE_ADDRESS("kernelbase.dll");
  PVOID kernelbase_mapped = nullptr;
  MAP_NATIVE_MODULE("kernelbase.dll", &kernelbase_mapped);
  const auto hooked_func_adress = resolve_jmp(get_proc_address(kernelbase, HASHSTR(func_name)), 1);
  const auto hooked_func_size = static_cast<size_t>(get_size_of_proc(hooked_func_adress, 1));
  const auto crc_hooked = crc32(hooked_func_adress, static_cast<unsigned int>(hooked_func_size));
  const auto original_func_adress = resolve_jmp(get_proc_address(kernelbase_mapped, HASHSTR(func_name)), 1);
  const auto original_func_size = static_cast<size_t>(get_size_of_proc(original_func_adress, 1));
  const auto crc_original = crc32(original_func_adress, static_cast<unsigned int>(original_func_size));
  // detect hook and restore bytes
  if (crc_original != crc_hooked)
  {
#ifndef SCYLLAHIDE_DETECTOR_LOG
    log("[Detect] " + static_cast<std::string>(func_name) + "\r\n");
#endif
    DWORD oldprotect = 0;
    hash_VirtualProtect(hooked_func_adress, hooked_func_size, PAGE_EXECUTE_READWRITE, &oldprotect);
    memcpy(hooked_func_adress, original_func_adress, hooked_func_size);
    hash_VirtualProtect(hooked_func_adress, hooked_func_size, oldprotect, &oldprotect);
  }
  else
  {
#ifndef SCYLLAHIDE_DETECTOR_LOG
    log("[Ok] " + static_cast<std::string>(func_name) + "\r\n");
#endif
  }
}

void user32_restore(const char *func_name)
{
  // TODO: Test on Win7,8
  if (getSysOpType() == 10)
  {
    const auto h_module = hash_LoadLibraryAA((LPCSTR)PRINT_HIDE_STR("user32.dll"));
    const auto win32_u = GET_MODULE_BASE_ADDRESS("win32u.dll");
    PVOID win32_u_mapped = nullptr;
    MAP_NATIVE_MODULE("win32u.dll", &win32_u_mapped);
    const auto hooked_func_adress = resolve_jmp(get_proc_address(win32_u, HASHSTR(func_name)), 1);
    const auto hooked_func_size = static_cast<size_t>(get_size_of_proc(hooked_func_adress, 1));
    const auto crc_hooked = crc32(hooked_func_adress, static_cast<unsigned int>(hooked_func_size));
    const auto original_func_adress = resolve_jmp(get_proc_address(win32_u_mapped, HASHSTR(func_name)), 1);
    const auto original_func_size = static_cast<size_t>(get_size_of_proc(original_func_adress, 1));
    const auto crc_original = crc32(original_func_adress, static_cast<unsigned int>(original_func_size));
    // detect hook and restore bytes
    if (crc_original != crc_hooked)
    {
#ifndef SCYLLAHIDE_DETECTOR_LOG
      log("[Detect] " + static_cast<std::string>(func_name) + "\r\n");
#endif
      DWORD oldprotect = 0;
      hash_VirtualProtect(hooked_func_adress, hooked_func_size, PAGE_EXECUTE_READWRITE, &oldprotect);
      memcpy(hooked_func_adress, original_func_adress, hooked_func_size);
      hash_VirtualProtect(hooked_func_adress, hooked_func_size, oldprotect, &oldprotect);
    }
    else
    {
#ifndef SCYLLAHIDE_DETECTOR_LOG
      log("[Ok] " + static_cast<std::string>(func_name) + "\r\n");
#endif
    }
    hash_FreeLibrary(h_module);
  }
  else
  {
    const auto h_module = hash_LoadLibraryAA((LPCSTR)PRINT_HIDE_STR("user32.dll"));
    const auto user_32 = GET_MODULE_BASE_ADDRESS(L"user32.dll");
    PVOID user32_mapped = nullptr;
    MAP_NATIVE_MODULE("user32.dll", &user32_mapped);
    const auto hooked_func_adress = resolve_jmp(get_proc_address(user_32, HASHSTR(func_name)), 1);
    const auto hooked_func_size = static_cast<size_t>(get_size_of_proc(hooked_func_adress, 1));
    const auto crc_hooked = crc32(hooked_func_adress, static_cast<unsigned int>(hooked_func_size));
    const auto original_func_adress = resolve_jmp(get_proc_address(user32_mapped, HASHSTR(func_name)), 1);
    const auto original_func_size = static_cast<size_t>(get_size_of_proc(original_func_adress, 1));
    const auto crc_original = crc32(original_func_adress, static_cast<unsigned int>(original_func_size));
    // detect hook and restore bytes
    if (crc_original != crc_hooked)
    {
#ifndef SCYLLAHIDE_DETECTOR_LOG
      log("[Detect] " + static_cast<std::string>(func_name) + "\r\n");
#endif
      DWORD oldprotect = 0;
      hash_VirtualProtect(hooked_func_adress, hooked_func_size, PAGE_EXECUTE_READWRITE, &oldprotect);
      memcpy(hooked_func_adress, original_func_adress, hooked_func_size);
      hash_VirtualProtect(hooked_func_adress, hooked_func_size, oldprotect, &oldprotect);
    }
    else
    {
#ifndef SCYLLAHIDE_DETECTOR_LOG
      log("[Ok] " + static_cast<std::string>(func_name) + "\r\n");
#endif
    }
    hash_FreeLibrary(h_module);
  }
}