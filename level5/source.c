#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
    
void o()
{
    // 80484b1
    system("/bin/sh");
}

void n()
{
    char buf[512];
    
    // 80484e5
    fgets(buf, 512, stdin);
    
    // 80484f3
    printf(buf);
    
    exit(1);
}

int main()
{
    // 804850a
    n();
}