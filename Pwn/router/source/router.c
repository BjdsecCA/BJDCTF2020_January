#include<stdio.h>
#include<stdlib.h>
#include <string.h>

int menu()
{
    puts("1.ping");
    puts("2.test");
    puts("3.leave comments");
    puts("4.root");
    puts("5.exit");

}


int main()
{
    setvbuf(stdout,0,2,0);
    setvbuf(stdin,0,1,0);
    char ip[16];
    char command[21]="ping ";
    int choose=0;
    puts("Welcome to BJDCTF router test program! ");
    while (1)
    {
        menu();
        puts("Please input u choose:");
        choose=0;
        scanf("%d",&choose);
        switch (choose)
        {
        case 1 :
            puts("Please input the ip address:");
            read(0,ip,16);
            strcat(command,ip);
            system(command);
            puts("done!");
            break;
        case 2:
            puts("bibibibbibibib~~~");
            sleep(3);
            puts("ziziizzizi~~~");
            sleep(3);
            puts("something wrong!");
            puts("Test done!");
            break;
        case 3:
            puts("Please input what u want to say");
            puts("Your suggest will help us to do better!");
            char suggest[50];
            read(0,suggest,58);
            printf("Dear ctfer,your suggest is :%s",&suggest);
            break;
        case 4:
            puts("Hey guys,u think too much!");
            break;
        case 5:
            puts("Good Bye!");
            exit(-1);
            break;
        default:
            puts("Functional development!");
            break;
        }
    }
}