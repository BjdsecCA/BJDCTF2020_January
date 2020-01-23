gcc -static -m32 -o re1 unit.c RC4.c RC4.h
strip re1
upx -1 re1

// ubuntu.16.04