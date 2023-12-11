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