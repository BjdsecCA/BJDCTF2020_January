//gcc -fno-stack-protector -D_FORTIFY_SOURCE=0 -no-pie -O2 -s -o encrypted_stack encrypted_stack.c
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#define LL long long
#define LLL __int128

LL E = 65537;
LL N = 94576960329497431;

LL powmod(LL a, LL b, LL mod)
{
	if (a == 0)
	{
		return 0;
	}
	if (b == 0)
	{
		return 1 % mod;
	}
	LLL val = powmod(a, b/2, mod);
	val *= val;
	val %= mod;
	if (b&1)
	{
		val *= a;
		val %= mod;
	}
	return val;
}

inline LL rsaenc(LL  m, LL n, LLL e)
{
	return powmod(m, e, n);
}

void vlun()
{
	rewind(stdin);
	char ch[64];
	puts("P1z inpu1t you name:");
	read(STDIN_FILENO, ch, 0x100);
//puts(ch);
}

void init()
{
	//memset(inbuf, 0, sizeof(inbuf));
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);
	srand(time(NULL));
}

int main(void)
{
	init();
	LL m;
	puts("Welcome! Please press enter to continue");
	//getchar();
	puts("To verify your ID. I will give you some message.");
	puts("Please use your key to encrypt it");
	for (int i = 0;i < 20;i++)
	{
		int m = rand();
		printf("%d\n", m);
		fflush(stdout);
		long long c;
		scanf("%lld", &c);
		printf("Your input is %lld\n", c);
		getchar();
		if (rsaenc(c,N,E) != m)
		{
			puts("Wrong Answer!\nBye");
			exit(1);
		}
	}
	puts("Welcome. Agent. ");
	vlun();
	puts("Maybe you just miss something. Bye~");
	return 0;
}
