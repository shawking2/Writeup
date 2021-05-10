#include <stdlib.h>
#include <stdio.h>

/* gcc  -m32 -fno-stack-protector --static -o ROPbasic ROPbasic.c */

int main()
{

    char buffer[128] = {0};

    printf("Insert ROP chain here:\n");
    gets(buffer);

    return EXIT_SUCCESS;
}
