CFLAGS = -ffreestanding -fPIE -fno-exceptions -fshort-wchar
CFLAGS += -Iinclude
AFLAGS = -D__ASSEMBLY__ $(patsubst -std=gnu%,,$(CFLAGS))
#LDFLAGS = -nostdlib -Wl,-pie -Wl,--no-seh -Wl,--subsystem,10 -e efi_main
LDFLAGS = -nostdlib -pie -e _entry -N
ASM = lz_header.S # must be in order
SRC = $(wildcard *.c)
OBJ = $(ASM:.S=.o) # must be first
OBJ += $(SRC:.c=.o)

.PHONY: all
all: lz_header.bin

lz_header.bin: lz_header
	$(PWD)/mkbin.sh

lz_header: $(OBJ)
	$(LD) -T lz_header.lds $(LDFLAGS) $^ -o $@

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

%.o: %.S
	$(CC) $(AFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -f lz_header.bin lz_header *.dsm *.hex *.elf *.o
