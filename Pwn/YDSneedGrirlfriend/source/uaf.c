#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

struct girlfriend {
	void (*showgirlfriend)();
	char *name ;
};

struct girlfriend *girlfriendlist[10];
int count = 0; 

void myinit()
{
    setvbuf(stdout,0,2,0);
    setvbuf(stdout,0,1,0);
    puts("YDS need a grilfriend!,can u help him?");
}

void print_girlfriend_name(struct girlfriend *her){
	puts(her->name);
}
void add_girlfriend(){
	int i ;
	char buf[8];
	int size ;
	if(count > 10){
		puts("Full");
		return ;
	}
	for(i = 0 ; i < 10 ; i ++){
		if(!girlfriendlist[i]){
			girlfriendlist[i] = (struct girlfriend*)malloc(sizeof(struct girlfriend));
			if(!girlfriendlist[i]){
				puts("Alloca Error");
				exit(-1);
			}
			girlfriendlist[i]->showgirlfriend = print_girlfriend_name;
			printf("Her name size is :");
			read(0,buf,8);
			size = atoi(buf);
			girlfriendlist[i]->name = (char *)malloc(size);
			if(!girlfriendlist[i]->name){
				puts("Alloca Error");
				exit(-1);
			}
			printf("Her name is :");
			read(0,girlfriendlist[i]->name,size);
			puts("Success !Wow YDS get a girlfriend!");
			count++;
			break;
		}
	}
}

void del_girlfriend(){
	char buf[4];
	int idx ;
	printf("Index :");
	read(0,buf,4);
	idx = atoi(buf);
	if(idx < 0 || idx >= count){
		puts("Out of bound!");
		return;
	}
	if(girlfriendlist[idx]){
		free(girlfriendlist[idx]->name);
		free(girlfriendlist[idx]);
		puts("Success");
	}
}

void print_girlfriend(){
	char buf[4];
	int idx ;
	printf("Index :");
	read(0,buf,4);
	idx = atoi(buf);
	if(idx < 0 || idx >= count){
		puts("Out of bound!");
		return;
	}
	if(girlfriendlist[idx]){
		girlfriendlist[idx]->showgirlfriend(girlfriendlist[idx]);
	}
}

void backdoor(){
    puts("YDS get N+ girlfriend!");
	system("/bin/sh");
}


void menu(){
	puts("------------------------");
	puts(" 1. Add a girlfriend    ");
	puts(" 2. Delete a girlfriend ");
	puts(" 3. show her name       ");
	puts(" 4. give up             ");
	puts("------------------------");
	printf("Your choice :");
};

int main(){
    myinit();
	char buf[4];
	while(1){
		menu();
		read(0,&buf,4);
		switch(atoi(buf)){
			case 1 :
				add_girlfriend();
				break ;
			case 2 :
				del_girlfriend();
				break ;
			case 3 :
				print_girlfriend();
				break ;
			case 4 :
				exit(0);
				break ;
			default :
				puts("Invalid choice");
				break ;
		}
	}
	return 0;
}