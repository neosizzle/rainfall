#include <stdio.h>
#include <stdlib.h>

static int	g_var = 0;
void v()
{
    // 80484a7
    char buf[512];
    
    // 80484c7
    fgets(buf, 512, stdin);
    
    // 80484d5
    printf(buf);
    if (g_var != 0x40)
        return;
    
    // 8048507
    fwrite("Wait what?!", 0xc, 0x1, stdout);
    system("/bin/sh");
}

int main()
{
    v();
}