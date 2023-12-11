#include <time.h>
#include <stdio.h>
    
// 080484f4
void m()
{
    int num_of_sec = time(0);
    printf("%s - %d\n", g_fgets_buf, num_of_sec);
}
// 08048521
void main()
{
    // 8048527
    void *ptr1;
    void *ptr2;
    FILE *file;
    
    // 804854b
    ptr1 = malloc(8);
    ptr1[0] = 0x1;
    
    // 804857a
    ptr1[1] = malloc(8);
    
    // 8048560
    ptr2 = malloc(8);
    ptr2[0] = 0x2;
    
    // 804857a
    ptr2[1] = malloc(8);
    
    // 80485a0
    strcpy(ptr1[1], argv[1]);
    
    // 80485bd
    strcpy(ptr2[1], argv[2]);
    
    file = fopen("/home/user/level8/.pass","r");
    fgets(pass, 68, fs);
    puts("~~");
    return 0;
}