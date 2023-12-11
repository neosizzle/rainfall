#include <stdio.h>
#include <stdlib.h>

# define MSG "Good... Wait what?"
# define SHELL "/bin/sh"
    
//0x8048444 
void run()
{
    // 0x804846d
    fwrite(MSG , 0x1, 0x13, stdout);
    
    // 0x8048479
    system(SHELL);
}
    
int main()
{
    // 0x8048486
    char buff[64];
    
    // 0x8048490
    gets(buff);
}