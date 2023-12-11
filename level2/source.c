#include <stdio.h>
#include <stdlib.h>
#include <string.h>
    
char * p()
{
    // 0x80484e7
    char buffer[64];
    void *saved_eip
    
    // 0x80484e2
    fflush(stdout);
    
    // 0x80484ed
    gets(buffer);
    
    // 0x80484f2 - 0x80484f5
    saved_eip = __builtin_return_address(0);
    if ((saved_eip & 0xb0000000) == 0xb0000000)
    {
        printf("%x\n", saved_eip);
        exit(1);
    }
    
    // 0x8048500
    if (((unsigned long)saved_eip & 0xb0000000) ==  0xb0000000)
	{
        // 0x8048516
		printf("(%p)\n", saved_eip);
		exit(1);
	}
        
    // 0x804852d
    puts(buffer);
    
    // 0x8048538
    return strdup(buffer);
}

int main()
{
    p();
}