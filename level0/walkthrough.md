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
