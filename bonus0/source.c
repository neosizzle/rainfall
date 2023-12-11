#include <stdio.h>
#include <string.h>

// 080484b4 
void p(char* str1, char* str2)
{
    char p_buf[4104];
    char *newline;
    
    puts(str2);
    
    // 80484e1
    read(0, p_buf, 4096);
    
    // 80484f7
    newline = strchr(p_buf, '\n');
    
    // 80484fc
    *newline = 0;
    
    // 8048517
    strncpy(str1, p_buf, 20);
}

// 0804851e 
void pp(char *str)
{
    char ppbuf1[20];
    char ppbuf2[20];
    
    p(ppbuf1, " - ");
    p(ppbuf2, " - ");
    
    // 8048559
    strcpy(str, pp_buf1);
    
    // 8048579 
    str[strlen(str)] = 32;
    
    // 8048598
    strcat(str, ppbuf2);
    return ;
}

int main()
{
    char res[42];
    pp(res);
    puts(res);
    return 0;
}