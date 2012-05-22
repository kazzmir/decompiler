#!/usr/bin/env python

import disassembler.read_elf;
import disassembler.read_pecoff;
import disassembler.read_macho;

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        f = open(sys.argv[1], 'r')
        try:
            disassembler.read_elf.read(f)
        except disassembler.read_elf.NotElf:
            try:
                f.seek(0)
                disassembler.read_pecoff.read(f)
            except disassembler.read_pecoff.NotPeCoff:
                try:
                    f.seek(0)
                    disassembler.read_macho.read(f)
                except disassembler.read_macho.NotMacho:
                    print "%s is not ELF, PE/COFF or MACH-O" % (sys.argv[1])
