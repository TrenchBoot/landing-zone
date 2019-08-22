CFLAGS = -ffreestanding -fPIE -fno-exceptions -fshort-wchar
CFLAGS += -Iinclude -Wall -g -MMD -MP
AFLAGS = -D__ASSEMBLY__ $(patsubst -std=gnu%,,$(CFLAGS))
LDFLAGS = -nostdlib -no-pie
ASM = lz_header.S # must be in order
SRC = $(wildcard *.c)
OBJ = $(ASM:.S=.o) # must be first
OBJ += $(SRC:.c=.o)

.PHONY: all
all: lz_header.bin

# Generate a flat binary
#
# As a sanity check, look for the LZ UUID at its expected offset in the binary
# image.  One reason this might fail is if the linker decides to put an
# unreferenced section ahead of .text, in which case link.lds needs adjusting.
lz_header.bin: lz_header Makefile
	objcopy -O binary -S --pad-to 0x10000 $< $@
	@od --format=x8 --skip-bytes=4 --read-bytes=16 $@ | \
		grep "0000004 e91192048e26f178 02ccc4765bc82a83" > /dev/null || \
		{ echo "ERROR: LZ UUID missing or misplaced in $@" >&2; false; }

lz_header: link.lds $(OBJ) Makefile
	$(LD) -T link.lds $(LDFLAGS) $(OBJ) -o $@

%.o: %.c Makefile
	$(CC) $(CFLAGS) -o $@ -c $<

%.o: %.S Makefile
	$(CC) $(AFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -f lz_header.bin lz_header *.d *.o

# Compiler-generated header dependencies.  Should be last.
-include $(OBJ:.o=.d)
