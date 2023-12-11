#include <stdio.h>

int main()
{
    FILE *passfile;
    char buf[132]; // 156 - 24
    int idx;
    
    // 8048513
    passfile = fopen("r", "/home/user/end/.pass");
    
    // 8048531
    memset(buf, 0, 33);
    
    if (!passfile || argc != 2)
        return -1;
    
    // 804856f
    fread(buf, 1, 66, passfile);
    
    // 8048584
    idx = atoi(argv[1]);
    
    // 8048589
    buf[idx] = 0;
    
    // 80485b3
    fread(buf + 66, 65, passfile);
    
    // 80485c2
    fclose(passfile);
    
    // 80485da
    if (strcmp(argv[2], buf) == 0)
        execl("/bin/sh", "sh");
    else
        puts(buf + 66);
    return 0;
}
