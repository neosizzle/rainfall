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