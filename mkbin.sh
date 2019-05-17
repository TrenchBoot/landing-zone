#! /bin/sh
#
# Copyright (c) 2019 Oracle and/or its affiliates. All rights reserved.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

cp -f lz_header lz_header.elf

objcopy -j .text -j .rodata -j .bss lz_header

# Make flat binary image
objcopy -O binary --pad-to 0x10000 lz_header lz_header.bin

# Plus some debug files
objdump -d lz_header.elf > lz_header.dsm
hexdump -C lz_header.bin > lz_header.hex
