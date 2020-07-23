# Start with empty flags
CFLAGS  :=
LDFLAGS :=

ifeq ($(DEBUG),y)
CFLAGS  += -DDEBUG
endif

ifeq ($(LTO),y)
CFLAGS  += -flto
LDFLAGS += -flto
endif

ifeq ($(32),y)
CFLAGS  += -m32 -mregparm=3 -fno-plt -freg-struct-return
LDFLAGS += -m32
else
CFLAGS  += -m64
LDFLAGS += -m64
endif

# There is a 64k total limit, so optimise for size.  The binary may be loaded
# at an arbitray location, so build it as position independent, but link as
# non-pie as all relocations are internal and there is no dynamic loader to
# help.
CFLAGS  += -Os -g -MMD -MP -march=btver2 -mno-sse -mno-mmx -fpie -fomit-frame-pointer
CFLAGS  += -Iinclude -ffreestanding -fno-common -Wall -Werror
LDFLAGS += -nostdlib -no-pie -Wl,--build-id=none

CFLAGS_TPMLIB := -include boot.h -include errno-base.h -include byteswap.h -DEBADRQC=EINVAL

# Derive AFLAGS from CFLAGS
AFLAGS := -D__ASSEMBLY__ $(filter-out -std=%,$(CFLAGS))

ALL_SRC := $(wildcard *.c) $(wildcard tpmlib/*.c)
TESTS := $(filter test-%,$(ALL_SRC:.c=))

# Collect objects for building.  For simplicity, we take all ASM/C files except tests
ASM := $(wildcard *.S)
SRC := $(filter-out test-%,$(ALL_SRC))
OBJ := $(ASM:.S=.o) $(SRC:.c=.o)

.PHONY: all
all: lz_header.bin

-include Makefile.local

# Generate a flat binary
#
# As a sanity check, look for the LZ UUID at its expected offset in the binary
# image.  One reason this might fail is if the linker decides to put an
# unreferenced section ahead of .text, in which case link.lds needs adjusting.
lz_header.bin: lz_header Makefile
	objcopy -O binary -S $< $@
	@./sanity_check.sh

lz_header: link.lds $(OBJ) Makefile
	$(CC) -Wl,-T,link.lds $(LDFLAGS) $(OBJ) -o $@

tpmlib/%.o: tpmlib/%.c Makefile
	$(CC) $(CFLAGS) $(CFLAGS_TPMLIB) -o $@ -c $<

%.o: %.c Makefile
	$(CC) $(CFLAGS) -o $@ -c $<

%.o: %.S Makefile
	$(CC) $(AFLAGS) -c $< -o $@

# Helpers for debugging.  Preprocess and/or compile only.
%.E: %.c Makefile
	$(CC) $(CFLAGS) -E $< -o $@
%.S: %.c Makefile
	$(CC) $(CFLAGS) -S $< -o $@

# Helpers for building and running tests on the current host
test-%: test-%.c Makefile
	$(CC) $(filter-out -ffreestanding -march%,$(CFLAGS)) $< -o $@

.PHONY: run-test-%
.SECONDARY:
run-test-%: test-% Makefile
	./$<

# Wrapper for building and running every test-*.c we find.
.PHONY: tests
tests: $(addprefix run-,$(TESTS))

.PHONY: cscope
cscope:
	find . -name "*.[hcsS]" > cscope.files
	cscope -b -q -k

.PHONY: clean
clean:
	rm -f lz_header.bin lz_header $(TESTS) *.d *.o tpmlib/*.d tpmlib/*.o cscope.*

# Compiler-generated header dependencies.  Should be last.
-include $(OBJ:.o=.d) $(TESTS:=.d)
