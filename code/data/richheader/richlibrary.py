#!/usr/bin/env python3

HAVE_PIDS = True

import struct
try:
    import prodids
except:
    print("[.] Could not find product ID database.")
    HAVE_PIDS = False

class FileSizeError(Exception):
    pass

class MZSignatureError(Exception):
    pass

class MZPointerError(Exception):
    pass

class PESignatureError(Exception):
    pass

class RichSignatureError(Exception):
    pass

class DanSSignatureError(Exception):
    pass

class HeaderPaddingError(Exception):
    pass

class RichLengthError(Exception):
    pass

class FileReadError(Exception):
    pass

def err2str(code):
    return{
        -1: "Could not open file.",
        -2: "File too small to contain required headers.",
        -3: "MZ signature not found.",
        -4: "MZ Header pointing beyond end of file.",
        -5: "PE signature not found",
        -6: "Rich signature not found. This file probably has no Rich header.",
        -7: "DanS signature not found. Rich header corrupt.",
        -8: "Wrong header padding behind DanS signature. Rich header corrupt.",
        -9: "Rich data length not a multiple of 8. Rich header corrupt.",
        }[code]

class RichLibrary:

    def __u32(self, x):
        return struct.unpack("<I", x)[0]

    def __p32(self, x):
        return struct.pack("<I", x)

    def __rol32(self, v, n):
        return ((v << (n & 0x1f)) & 0xffffffff) | (v >> (32 - (n & 0x1f)))

    def generate_csum(self, raw_dat, compids, off):
        csum = off

        for i in range(off):
            ## Mask out the e_lfanew field as it's not initialized yet
            if i in range(0x3c, 0x40):
                continue
            csum += self.__rol32(raw_dat[i], i)

        for c in compids:
            csum += self.__rol32(c['pid'] << 16 | c['mcv'], c['cnt'])

        ## Truncate calculated checksum to 32 bit
        return csum & 0xffffffff

    def parse(self):
        dat = bytearray(open(self.fname, 'rb').read()[:0x1000])

        ## Do basic sanity checks on the PE
        dat_len = len(dat)
        if dat_len < self.SIZE_DOS_HEADER:
            raise FileSizeError()

        if dat[0:][:2] != b'MZ':
            raise MZSignatureError()

        e_lfanew = self.__u32(dat[self.POS_E_LFANEW:][:4])

        if e_lfanew + 1 > dat_len:
            raise MZPointerError()

        if dat[e_lfanew:][:2] != b'PE':
            raise PESignatureError()

        ## IMPORTANT: Do not assume the data to start at 0x80, this is not always
        ## the case (modified DOS stub). Instead, start searching backwards for
        ## 'Rich', stop at beginning of DOS header.
        rich = 0
        for rich in range(e_lfanew, self.SIZE_DOS_HEADER, -1):
            if dat[rich:][:4] == b'Rich':
                break

        if rich == self.SIZE_DOS_HEADER:
            raise RichSignatureError()

        ## We found a valid 'Rich' signature in the header from here on
        csum = self.__u32(dat[rich + 4:][:4])

        ## xor backwards with csum until either 'DanS' or end of the DOS header,
        ## invert the result to get original order
        upack = [ self.__u32(dat[i:][:4]) ^ csum for i in range(rich - 4, self.SIZE_DOS_HEADER, -4) ][::-1]
        if self.__u32(b'DanS') not in upack:
            raise DanSSignatureError()

        upack = upack[upack.index(self.__u32(b'DanS')):]
        dans = e_lfanew - len(upack) * 4 - (e_lfanew - rich)

        ## DanS is _always_ followed by three zero dwords
        if not all([upack[i] == 0 for i in range(1, 4)]):
            raise HeaderPaddingError()

        upack = upack[4:]

        if len(upack) & 1:
            raise RichLengthError()

        cmpids = []
        for i in range(0, len(upack), 2):
            cmpids.append({
                'mcv': (upack[i + 0] >>  0) & 0xffff,
                'pid': (upack[i + 0] >> 16) & 0xffff,
                'cnt': (upack[i + 1] >>  0)
            })
        ## Bonus feature: Calculate and check the check sum csum
        chk = self.generate_csum(dat, cmpids, dans)

        res = [dans, chk, csum]
        for x in cmpids:
            res.extend([x['cnt'], x['mcv'], x['pid']])

        return res + [0] * (66 - len(res))
        # return {'error': 0, 'cmpids': cmpids, 'csum_calc': chk, 'csum_file': csum, 'offset': dans}

    def __pprint_cmpids(self, cmpids):
        print("-" * (20 + 16 + 16 + 32 + 39))
        print("{:>20s}{:>16s}{:>16s}{:>32s}{:>39s}".format("Compiler Patchlevel", "Product ID",
            "Count", "MS Internal Name", "Visual Studio Release"))
        print("-" * (20 + 16 + 16 + 32 + 39))

        for e in cmpids:
            if HAVE_PIDS:
                try:
                    int_name = prodids.int_names[e['pid']]
                except:
                    int_name = '<unknown>'
                vs_version = prodids.vs_version(e['pid'])

            print("{:>20s}{:>16s}{:>16s}{:>32s}{:>39s}".format(
                "{:5d}".format(e['mcv']),
                "0x{:04x}".format(e['pid']),
                "0x{:08x}".format(e['cnt']),
                "{}".format(int_name),
                "{:18s} ({})".format(*vs_version)))
        print("-" * (20 + 16 + 16 + 32 + 39))

    def pprint_header(self, data):
        self.__pprint_cmpids(data['cmpids'])
        if data['csum_calc'] == data['csum_file']:
            print("\x1b[32mChecksums match! (0x{:08x})".format(data['csum_calc']))
        else:
            print("\x1b[33mChecksum corrupt! (calc 0x{:08x}, file "
            "0x{:08x})".format(data['csum_calc'], data['csum_file']))
        print("\x1b[39m" + "-" * (20 + 16 + 16 + 32 + 39))

    def __init__(self, path):
        self.data = {}
        self.SIZE_DOS_HEADER = 0x40
        self.POS_E_LFANEW = 0x3c

        self.fname = path
