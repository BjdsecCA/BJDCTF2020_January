/*gcc -fno-stack-protector ret2libc.c -o pwn*/
#include<stdlib.h>
#include<stdio.h>

void init()
{
    setvbuf(stdout,0,2,0);
    setvbuf(stdin,0,1,0);
    puts("Can u return to libc ?");
    puts("Try u best!");
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
    vuln();
    return 0;
}