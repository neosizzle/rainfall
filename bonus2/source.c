#include <string.h>
#include <stdio.h>
    
static int language;

// 08048484 
void greetuser(char *name)
{
    // 80484a2
    char greeting[72]; 
    
    if (language == 1)
        strcpy(greeting, "Hyvää päivää ");
    else if (language == 2)
        strcpy(greeting, "Goedemiddag! ");
    else if (language == 0)
        strcpy(greeting, "Hello! ");

    // 8048370
    strcat(greeting, name);
    
    // 8048522
    puts(greeting);    
}

int main(int argc, char **argv)
{    
    if (argc == 3)
    {
        char buf[76];// 9c - 50
        char *lang_str;
        
        // 804855a
        memset(buf, 0, (19 * 4));
        
        // 8048577
        strncpy(buf, argv[1], 40);
        
        // 804859a
        strncpy(buf + 40, argv[2], 32);
        
        // 80485a6
        lang_str = getenv("LANG");
        if (!lang_str)
        {
            greetuser(buf);
            return 0;
        }
        else
        {
            if (memcmp(lang_str, "fi", 2) == 0)
                language = 1;
            else if (memcmp(lang_str, "nl", 2) == 0)
                language = 2;
            greetuser(buf);
            return 0;
        }
    }
    else 
        return 1;
}