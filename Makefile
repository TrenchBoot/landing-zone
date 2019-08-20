CFLAGS = -ffreestanding -fPIE -fno-exceptions -fshort-wchar
CFLAGS += -Iinclude -Wall
AFLAGS = -D__ASSEMBLY__ $(patsubst -std=gnu%,,$(CFLAGS))
LDFLAGS = -nostdlib -pie -N
ASM = lz_header.S # must be in order
SRC = $(wildcard *.c)
OBJ = $(ASM:.S=.o) # must be first
OBJ += $(SRC:.c=.o)

.PHONY: all
all: lz_header.bin

lz_header.bin: lz_header
	$(PWD)/mkbin.sh

lz_header: link.lds $(OBJ)
	$(LD) -T link.lds $(LDFLAGS) $(OBJ) -o $@

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

%.o: %.S
	$(CC) $(AFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -f lz_header.bin lz_header *.dsm *.hex *.elf *.o
