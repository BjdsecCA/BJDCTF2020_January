#include <string.h>
 
static void rc4_init(unsigned char* s_box, unsigned char* key, unsigned int key_len)
{
    unsigned char Temp[256];
    int i;
    for (i = 0; i < 256; i++)
    {
        s_box[i] = i;//顺序填充S盒
        Temp[i] = key[i%key_len];//生成临时变量T
    }
    int j = 0;
    for (i = 0; i < 256; i++)//打乱S盒
    {
        j = (j + s_box[i] + Temp[i]) % 256;
        unsigned char tmp = s_box[i];
        s_box[i] = s_box[j];
        s_box[j] = tmp;
    }
}
 
void rc4_crypt(unsigned char* data, unsigned int data_len, unsigned char* key, unsigned int key_len)
{
    unsigned char s_box[256];
    rc4_init(s_box, key, key_len);
    unsigned int i = 0, j = 0, t = 0;
    unsigned int Temp;
    for (Temp = 0; Temp < data_len; Temp++)
    {
        i = (i + 1) % 256;
        j = (j + s_box[i]) % 256;
        unsigned char tmp = s_box[i];
        s_box[i] = s_box[j];
        s_box[j] = tmp;
        t = (s_box[i] + s_box[j]) % 256;
        data[Temp] ^= s_box[t];
    }
}