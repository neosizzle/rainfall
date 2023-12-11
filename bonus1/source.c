#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    int atoi_ret;
    char buf[40]; // we allocated 64 bytes at 804842a, - atoi_res size (4) - esp offset (20)
    
    // 8048438
    atoi_ret = atoi(argv[1]);
    if (atoi_ret <= 9)
    {
        int len;
        
        // 8048453
        len = atoi_res * 4;
        
        // 8048473
        memcpy(buf, argv[2], len);
        
        if (atoi_ret != 1464814662) // or 0x574f4c46
            return 1;
        else
            execl("/bin/sh", "sh");
    }
    else
        return 1;
}