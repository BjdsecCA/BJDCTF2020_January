/*gcc -fstack-protector-all -o pwn ret2libc_can.c*/

#include<stdlib.h>
#include<stdio.h>

void init()
{
    setvbuf(stdout,0,2,0);
    setvbuf(stdin,0,1,0);
    puts("Can u return to libc ?");
    puts("Try u best!");
}

void gift()
{
    puts("I'll give u some gift to help u!");
    char buffer[6];
    scanf("%6s",&buffer);
    printf(&buffer);
    puts("");
    fflush(0);
}

void vuln()
{
    char message[20];
    puts("Pull up your sword and tell me u story!");
    read(0,&message,100);
}

int main()
{
    init();
    gift();
    vuln();
    return 0;
}