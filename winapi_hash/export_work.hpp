#pragma once
#include <windows.h>

struct LDR_MODULE
{
  LIST_ENTRY e[3];
  HMODULE base;
  void *entry;
  UINT size;
  UNICODE_STRING dllPath;
  UNICODE_STRING dllname;
};

// Super Hide String
#include "../utils/hidestr/hide_str.hpp"
#include "../t1ha/t1ha.h"
#include "hash_work.hpp"
#define STRONG_SEED 10376313370251892926
#include "export_work.hpp"

#define RAND_DWORD1		0x03EC7B5E
#define ROR(x,n) (((x) >> (n)) | ((x) << (32-(n))))

typedef struct _PEB_LDR_DATA_
{
  BYTE Reserved1[8];
  PVOID Reserved2[3];
  LIST_ENTRY *InMemoryOrderModuleList;
} PEB_LDR_DATA_, *PPEB_LDR_DATA_;

#ifdef _WIN64
typedef struct _PEB_c
{
  BYTE Reserved1[2];
  BYTE BeingDebugged;
  BYTE Reserved2[21];
  PPEB_LDR_DATA_ Ldr;
} PEB_c;
#else

typedef struct _PEB
{
  /*0x000*/     UINT8        InheritedAddressSpace;
  /*0x001*/     UINT8        ReadImageFileExecOptions;
  /*0x002*/     UINT8        BeingDebugged;
  /*0x003*/     UINT8        SpareBool;
  /*0x004*/     VOID        *Mutant;
  /*0x008*/     VOID        *ImageBaseAddress;
  /*0x00C*/     struct _PEB_LDR_DATA *Ldr;
  /*.....*/
} PEB_c;

#endif

#pragma warning (disable : 4996)
__forceinline const wchar_t *GetWC_(const char *c)
{
  const size_t cSize = strlen(c) + 1;
  wchar_t *wc = new wchar_t[cSize];
  mbstowcs(wc, c, cSize);
  return wc;
}

__forceinline HMODULE _getKernel32Handle(void)
{
  HMODULE dwResult = NULL;
  PEB_c *lpPEB = NULL;
  SIZE_T *lpFirstModule = NULL;
#if defined _WIN64
  lpPEB = *(PEB_c **)(__readgsqword(0x30) + 0x60); //get a pointer to the PEB
#else
  lpPEB = *(PEB_c **)(__readfsdword(0x18) + 0x30); //get a pointer to the PEB
#endif
  // PEB->Ldr->LdrInMemoryOrderModuleList
  // PEB->Ldr = 0x0C
  // Ldr->LdrInMemoryOrderModuleList = 0x14
  lpFirstModule = (SIZE_T *)lpPEB->Ldr->InMemoryOrderModuleList;
  SIZE_T *lpCurrModule = lpFirstModule;
  do
  {
    PWCHAR szwModuleName = (PWCHAR)lpCurrModule[10]; // 0x28 - module name in unicode
    DWORD i = 0;
    DWORD dwHash = 0;
    while (szwModuleName[i])
    {
      BYTE zByte = (BYTE)szwModuleName[i];
      if (zByte >= 'a' && zByte <= 'z')
        zByte -= 0x20; // Uppercase
      dwHash = ROR(dwHash, 13) + zByte;
      i++;
    }
    if ((dwHash ^ RAND_DWORD1) == (0x6E2BCA17 ^ RAND_DWORD1)) // KERNEL32.DLL hash
    {
      dwResult = (HMODULE)lpCurrModule[4];
      return dwResult;
    }
    lpCurrModule = (SIZE_T *)lpCurrModule[0]; // next module in linked list
  }
  while (lpFirstModule != (SIZE_T *)lpCurrModule[0]);
  return dwResult;
}

static HMODULE (WINAPI *temp_LoadLibraryA)(__in LPCSTR file_name) = nullptr;
static int (*temp_lstrcmpiW)(LPCWSTR lpString1, LPCWSTR lpString2) = nullptr;

static __forceinline HMODULE hash_LoadLibraryA(__in LPCSTR file_name)
{
  return temp_LoadLibraryA(file_name);
}

static __forceinline int hash_lstrcmpiW(LPCWSTR lpString1,
                                        LPCWSTR lpString2)
{
  return temp_lstrcmpiW(lpString1,
                        lpString2);
}

__forceinline LPVOID parse_export_table(HMODULE module, uint64_t api_hash, uint64_t len, const uint64_t seed)
{
  PIMAGE_DOS_HEADER img_dos_header;
  PIMAGE_NT_HEADERS img_nt_header;
  PIMAGE_EXPORT_DIRECTORY in_export;
  img_dos_header = (PIMAGE_DOS_HEADER)module;
  img_nt_header = (PIMAGE_NT_HEADERS)((DWORD_PTR)img_dos_header + img_dos_header->e_lfanew);
  in_export = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)img_dos_header + img_nt_header->OptionalHeader.DataDirectory[
                                         IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
  PDWORD rva_name;
  PWORD rva_ordinal;
  rva_name = (PDWORD)((DWORD_PTR)img_dos_header + in_export->AddressOfNames);
  rva_ordinal = (PWORD)((DWORD_PTR)img_dos_header + in_export->AddressOfNameOrdinals);
  UINT ord = -1;
  char *api_name;
  unsigned int i;
  for (i = 0; i < in_export->NumberOfNames - 1; i++)
  {
    api_name = (PCHAR)((DWORD_PTR)img_dos_header + rva_name[i]);
    const uint64_t get_hash = t1ha0(api_name, len, seed);
    //if (strcmp("CreateFileA", (const char*)api_name) == 0)
    //{
    //	int debug_me = 3;
    //}
    if (api_hash == get_hash)
    {
      ord = static_cast<UINT>(rva_ordinal[i]);
      break;
    }
  }
  const auto func_addr = (PDWORD)((DWORD_PTR)img_dos_header + in_export->AddressOfFunctions);
  const auto func_find = (LPVOID)((DWORD_PTR)img_dos_header + func_addr[ord]);
  return func_find;
}


__forceinline LPVOID get_api(uint64_t api_hash, LPCSTR module, uint64_t len, const uint64_t seed)
{
  HMODULE krnl32, hDll;
  LPVOID api_func;
#ifdef _WIN64
  const auto ModuleList = 0x18;
  const auto ModuleListFlink = 0x18;
  const auto KernelBaseAddr = 0x10;
  const INT_PTR peb = __readgsqword(0x60);
#else
  int ModuleList = 0x0C;
  int ModuleListFlink = 0x10;
  int KernelBaseAddr = 0x10;
  INT_PTR peb = __readfsdword(0x30);
#endif
  // Теперь получим адрес kernel32.dll
  const auto mdllist = *(INT_PTR *)(peb + ModuleList);
  const auto mlink = *(INT_PTR *)(mdllist + ModuleListFlink);
  auto krnbase = *(INT_PTR *)(mlink + KernelBaseAddr);
  auto mdl = (LDR_MODULE *)mlink;
  HMODULE hKernel32 = NULL;
  hKernel32 = _getKernel32Handle();
  const char *lstrcmpiW_ = (LPCSTR)PRINT_HIDE_STR("lstrcmpiW");
  const uint64_t api_hash_lstrcmpiW = t1ha0(lstrcmpiW_, strlen(lstrcmpiW_), STRONG_SEED);
  temp_lstrcmpiW = static_cast<int(*)(LPCWSTR, LPCWSTR)>(parse_export_table(
                     hKernel32, api_hash_lstrcmpiW, strlen(lstrcmpiW_), STRONG_SEED));
  do
  {
    mdl = (LDR_MODULE *)mdl->e[0].Flink;
    if (mdl->base != nullptr)
    {
      if (!hash_lstrcmpiW(mdl->dllname.Buffer, GetWC_((LPCSTR)PRINT_HIDE_STR("kernel32.dll"))))
        //сравниваем имя библиотеки в буфере с необходимым
      {
        break;
      }
    }
  }
  while (mlink != (INT_PTR)mdl);
  krnl32 = static_cast<HMODULE>(mdl->base);
  //Получаем адрес функции LoadLibraryA
  const char *LoadLibraryA_ = (LPCSTR)PRINT_HIDE_STR("LoadLibraryA");
  const uint64_t api_hash_LoadLibraryA = t1ha0(LoadLibraryA_, strlen(LoadLibraryA_), STRONG_SEED);
  temp_LoadLibraryA = static_cast<HMODULE(WINAPI *)(LPCSTR)>(parse_export_table(
                        krnl32, api_hash_LoadLibraryA, strlen(LoadLibraryA_), STRONG_SEED));
  hDll = hash_LoadLibraryA(module);
  api_func = static_cast<LPVOID>(parse_export_table(hDll, api_hash, len, seed));
  return api_func;
}
