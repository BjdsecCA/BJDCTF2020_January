#include<stdio.h>
#include<stdlib.h>

int backdoor()
{
    system("/bin/sh");
    return 1;
}

int main()
{
    setvbuf(stdout,0,2,0);
    setvbuf(stdin,0,1,0);    
    unsigned int length=0;
    char name[10];
    puts("**********************************");
    puts("*     Welcome to the BJDCTF!     *");
    puts("* And Welcome to the bin world!  *");
    puts("*  Let's try to pwn the world!   *");
    puts("* Please told me u answer loudly!*");
    puts("[+]Are u ready?");
    puts("[+]Please input the length of your name:");
    scanf("%d",&length);
    if(length>10)
    {
        puts("Oops,u name is too long!");
        exit(-1);
    }
    puts("[+]What's u name?");
    read(0,name,length);
    return 0;
}