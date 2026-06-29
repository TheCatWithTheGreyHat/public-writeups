TARGET = chall

CC = gcc
CFLAGS = -no-pie -fstack-protector-all -D_FORTIFY_SOURCE=2 -Wl,-z,relro,-z,now

all: $(TARGET)

$(TARGET): chall.c
	$(CC) $(CFLAGS) chall.c -o ../$(TARGET)
	
clean:
	rm -f ../$(TARGET)
