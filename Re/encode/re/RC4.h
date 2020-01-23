#ifndef RC4_H
#define RC4_H
 
/*
导出rc4_crypt函数，参数为要加密的数据、数据长度、密码、密码长度
*/
void rc4_crypt(unsigned char* data, unsigned int data_len, unsigned char* key, unsigned int key_len);
 
#endif