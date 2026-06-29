#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <link.h>
#include <err.h>

#define N_LEAK 3

uintptr_t libc_sample = 0;
uintptr_t ld_sample = 0;

__attribute__((constructor))
void init(){	
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

	libc_sample = (uintptr_t)&puts;
	ld_sample = (uintptr_t)_r_debug.r_ldbase;
}

void win() {
    __asm__ volatile (
        ".intel_syntax noprefix;"        
        "mov rax, 0x68732f6e69622f;" 
        "push rax;"
        "mov rdi, rsp;"
        "xor rsi, rsi;"
        "xor rdx, rdx;"
        "mov rax, 59;"
        "syscall;"       
        ".att_syntax;"
    );

    exit(0);
}

int main(){
	uint64_t addr;
	uint64_t value;

	puts("Here's a little gift");
	printf("%#016lx\n", ld_sample);
	
	puts("I'll give you a gift, enter a number");
	for(int i = 0; i < N_LEAK; i++){
		scanf("%ld", &addr);
		printf("%#016lx\n", *(uint64_t *)addr);
	}
	puts("No more gifts now!");

	scanf("%ld", &addr);
	scanf("%ld", &value);
	
	__asm__ volatile (
        ".intel_syntax noprefix;"
        "mov QWORD PTR [%0], %1;"
        ".att_syntax;"
        : 
        : "r" (addr), "r" (value)
        : "memory"
    );
	
	exit(0);
}
