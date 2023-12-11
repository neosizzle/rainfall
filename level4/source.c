#include <stdio.h>
#include <stdlib.h>

static int    g_var = 0;

void p(char *buffer)
{    
    printf(buffer);
}

void n()
{
    // 804845a
    char buf[512]; // 0x200
    
    // 804847a
    fgets(buf, 512, stdin);
    
    // 804847a
    p(buf);
    
    if (g_var + 12 != 0x1025544)
        return;
    system("/bin/sh");
    
}
    
int main()
{
    n()
}