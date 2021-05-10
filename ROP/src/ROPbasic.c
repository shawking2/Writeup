#include <stdlib.h>
#include <stdio.h>



int main()
{

    char buffer[128] = {0};

    printf("Insert ROP chain here:\n");
    gets(buffer);

    return EXIT_SUCCESS;
}
