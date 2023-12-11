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