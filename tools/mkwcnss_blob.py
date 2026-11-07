#!/usr/bin/env python3
"""Pack the vince Wi-Fi (Pronto / WCNSS) firmware for patch 0189 (boot-arg vincepronto=1).

Inputs: the phone's modem partition IMAGE/WCNSS.MDT + WCNSS.Bnn (split PIL image) and the persist partition's
WCNSS_qcom_wlan_nv.bin. Output: a blob the kernel reads from the "boot" partition at 40 MiB, or (--boot) a
boot image padded to 40 MiB with the blob behind it, ready to dd to the boot partition.

Blob layout (all little endian, every item sector aligned):
  sector 0..1: "VWCNSS01", mdt_sect, mdt_len, nv_sect, nv_len, fw_span, nchunks, then nchunks x
               {sect, len, dst, memsz}; dst is relative to the start of wcnss_fw_region (0x8E800000), where the
               firmware is relocated from its lowest load address (0x8E600000), as Linux PIL does
  then the .mdt (ELF + program headers + hash segment, what TrustZone INIT_IMAGE gets), the NV, the segments
"""
import argparse
import os
import struct
import sys

BLOB_OFFSET = 40 << 20
FW_REGION = 0x700000
META_OFF = 0x6C0000
MAX_CHUNKS = 32


def pad(b, n=512):
    return b + b'\0' * (-len(b) % n)


def build(fwdir, nv_path):
    def find(name):
        for f in os.listdir(fwdir):
            if f.lower() == name.lower():
                return os.path.join(fwdir, f)
        return None

    mdt = open(find('wcnss.mdt'), 'rb').read()
    if mdt[:4] != b'\x7fELF' or mdt[4] != 1:
        sys.exit('WCNSS.MDT is not a 32-bit ELF')
    phoff, = struct.unpack_from('<I', mdt, 28)
    phent, phnum = struct.unpack_from('<HH', mdt, 42)
    segs = []
    for i in range(phnum):
        p_type, p_off, p_va, p_pa, p_filesz, p_memsz, p_flags, _ = struct.unpack_from('<8I', mdt, phoff + i * phent)
        if p_type != 1 or p_memsz == 0 or (p_flags >> 24) & 7 == 2:   # PT_LOAD, not the hash segment
            continue
        segs.append((i, p_pa, p_filesz, p_memsz))
    base = min(s[1] for s in segs)
    span = max(s[1] + s[3] for s in segs) - base
    if span > META_OFF:
        sys.exit(f'firmware span {span:#x} does not fit below the metadata copy at {META_OFF:#x}')

    chunks = []
    for i, pa, filesz, memsz in segs:
        if filesz == 0:
            continue
        f = find(f'wcnss.b{i:02d}')
        if not f:
            sys.exit(f'missing WCNSS.B{i:02d}')
        data = open(f, 'rb').read()
        if len(data) != filesz:
            sys.exit(f'WCNSS.B{i:02d} is {len(data)} bytes, program header says {filesz}')
        chunks.append((pa - base, memsz, data))
    if len(chunks) > MAX_CHUNKS:
        sys.exit('too many segments')

    nv = open(nv_path, 'rb').read() if nv_path else b''
    body = b''
    sect = 2
    mdt_sect = sect
    body += pad(mdt)
    sect = 2 + len(body) // 512
    nv_sect = sect
    body += pad(nv)
    entries = []
    for dst, memsz, data in chunks:
        sect = 2 + len(body) // 512
        entries.append((sect, len(data), dst, memsz))
        body += pad(data)
    hdr = b'VWCNSS01' + struct.pack('<6I', mdt_sect, len(mdt), nv_sect, len(nv), span, len(entries))
    for e in entries:
        hdr += struct.pack('<4I', *e)
    hdr = hdr.ljust(1024, b'\0')
    print(f'firmware: {len(chunks)} segments, load {base:#x} -> 0x8e800000, span {span:#x} '
          f'({span >> 10} KiB); mdt {len(mdt)} bytes; NV {len(nv)} bytes; blob {len(hdr) + len(body)} bytes')
    return hdr + body


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('fwdir', help='folder with WCNSS.MDT and WCNSS.Bnn')
    ap.add_argument('out', help='output: the blob, or with --boot the combined boot image')
    ap.add_argument('--nv', help='WCNSS_qcom_wlan_nv.bin (persist partition)')
    ap.add_argument('--boot', help='boot image to put in front (padded to 40 MiB)')
    a = ap.parse_args()
    blob = build(a.fwdir, a.nv)
    if a.boot:
        img = open(a.boot, 'rb').read()
        if len(img) > BLOB_OFFSET:
            sys.exit('boot image larger than 40 MiB')
        blob = img.ljust(BLOB_OFFSET, b'\0') + blob
    open(a.out, 'wb').write(blob)
    print(f'wrote {a.out}: {len(blob)} bytes')


if __name__ == '__main__':
    main()
