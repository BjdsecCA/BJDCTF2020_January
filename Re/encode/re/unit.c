#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<unistd.h>
#include"RC4.h"

unsigned char *base64_encode(unsigned char *str);

int main(void)
{   unsigned char key[] = "Flag{This_a_Flag}";
    unsigned int len0 = strlen((const char *)key);
	unsigned int i;
    unsigned char res[]="E8D8BD91871A1E56F53F4889682F96142AF2AB8FED7ACFD5E";
	// unsigned char buf[]="BJD{0v0_Y0u_g07_1T!}";
    unsigned char buf[128];
    printf("Please input your flag:\n");
    read(STDIN_FILENO,buf,256);
    if(strlen(buf)!=21)
        exit(0);
    else
    {
        unsigned char inputs[30];
        strcpy(inputs,base64_encode(buf));
        unsigned int len=strlen((const char*)inputs);
        for(i=0;i<len;i++)
            inputs[i]^=key[i%len0];
        rc4_crypt(inputs,len,key,len0);
        if(!strcmp(inputs,res))
            exit(0);
        else
            puts("right!");       
    }
	return 0;
}

unsigned char *base64_encode(unsigned char *str)  
{  
    long len;  
    long str_len;  
    unsigned char *res;  
    int i,j;  
    unsigned char *base64_table="0123456789+/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"; 
 
    str_len=strlen(str);  
    if(str_len % 3 == 0)  
        len=str_len/3*4;  
    else  
        len=(str_len/3+1)*4;  
  
    res=malloc(sizeof(unsigned char)*len+1);  
    res[len]='\0';  
  
  
    for(i=0,j=0;i<len-2;j+=3,i+=4)  
    {  
        res[i]=base64_table[str[j]>>2];
        res[i+1]=base64_table[(str[j]&0x3)<<4 | (str[j+1]>>4)];
        res[i+2]=base64_table[(str[j+1]&0xf)<<2 | (str[j+2]>>6)];
        res[i+3]=base64_table[str[j+2]&0x3f];
    }  
  
    switch(str_len % 3)  
    {  
        case 1:  
            res[i-2]='=';  
            res[i-1]='=';  
            break;  
        case 2:  
            res[i-1]='=';  
            break;  
    }  
  
    return res;  
}  
