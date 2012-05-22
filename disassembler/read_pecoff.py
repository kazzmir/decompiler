from utils import num_lsb, num_msb

class Coff:
    pass

Coff.machine_unknown = 0
Coff.machine_am33 = 0x1d3
Coff.machine_amd64 = 0x8664
Coff.machine_arm = 0x1c0
Coff.machine_ebc = 0xebc
Coff.machine_i386 = 0x14c
Coff.machine_ia64 = 0x200
Coff.machine_m32r = 0x9041
Coff.machine_mips16 = 0x266
Coff.machine_mipsfpu = 0x366
Coff.machine_mipsfpu16 = 0x466
Coff.machine_powerpc = 0x1f0
Coff.machine_powerpcfp = 0x1f1
Coff.machine_r4000 = 0x166
Coff.machine_sh3 = 0x1a2
Coff.machine_sh3dsp = 0x1a3
Coff.machine_sh4 = 0x1a6
Coff.machine_sh5 = 0x1a8
Coff.machine_thumb = 0x1c2
Coff.machine_wcemipsv2 = 0x169

class PeCoffException(Exception):
    def __init__(self, str):
        Exception.__init__(self, str)

class NotPeCoff(PeCoffException):
    def __init__(self, str):
        PeCoffException.__init__(self, str)

def verifyMagic(stuff):
    pe = 'PE' + chr(0) + chr(0)
    if stuff != pe:
        raise NotPeCoff("invalid magic number %s" % stuff)

def machineType(machine):
    if machine == Coff.machine_i386:
        return "I386"
    raise PeCoffException("invalid machine type %x" % machine)

def read(file):
    # skip msdos stub
    file.seek(0x3c)
    # lsb or msb??
    nummer = num_lsb
    offset = nummer(file.read(4))
    file.seek(offset)
    magic = file.read(4)
    verifyMagic(magic)
    print "Detected PE/COFF file"

    machine = nummer(file.read(2))
    print "Machine type is %s" % machineType(machine)
