//gcc -fstack-protector-all -O2 -fPIE -pie -s -z now -o dizzy dizzy.c 
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int arr[41];

char pattern[] = "PvvN| 1S S0 GREAT!";

int main(void)
{
	memset(&arr, 0x7f, sizeof(arr));
	arr[0]= 0xbfffff;
	arr[40] = 0xfede00af;
	arr[4] += arr[1];
	printf("Let's play this!");
	for (int i = 0;i < 20;i++)
	{
		scanf("%d", &arr[i]);
	}
	for (int i = 0;i < 40;i++)
	{
		arr[i] += 114514;
	}
	const char *str1 = (char *)&arr;
	const char *str2 = pattern;
	while(*str1 != '\0' && *str2 != '\0' && (*str1) == (*str2))
	{
		str1++;
		str2++;
	}
	if(*str2 != '\0')
    {
        exit(1);     
    }
    puts("U G0T 1T! N0W 1 W1LL G1V3 Y0U THE SHELL");
    system((char*)arr);
	return 0;
}
