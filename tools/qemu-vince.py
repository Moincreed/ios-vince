#!/usr/bin/env python3
"""Boot a VINCEXNU payload (tools/mkpayload_vince.py) in QEMU's virt board.

Adapted from ios-sweet tools/qemu-sweet.py for Xiaomi Redmi 5 Plus (MSM8953):
- accepts both VINCEXNU and SWEETXNU payload magics
- framebuffer @ 0x90001000, 1080x2160, 24-bpp RGB888, stride 3240
- 4 KiB page alignment for boot_args placement (vince kernel is 4K)
- QEMU virt with GICv2 (matches the phone's GIC-400)
- default CPU cortex-a53

  qemu-vince.py PAYLOAD OUTDIR [--secs N] [--cpu CPU]

Writes into OUTDIR: fb.png (what the phone screen would show), regs.txt,
serial.txt, qemu.log, result.json.
"""
import argparse, json, os, struct, subprocess, sys, time, zlib

FB_BASE, FB_W, FB_H = 0x90001000, 1080, 2160
FB_STRIDE = FB_W * 3          # 24-bpp RGB888
PAGE = 0x1000                 # vince kernel uses 4 KiB granule
STUB_PA = 0x40200000
BOOT_LINE_LENGTH = 608


def build_image(payload):
    """Return (phys_base, ram_image, boot_args_pa, entry_pa)."""
    magic, ver, nsegs = struct.unpack_from('<8sII', payload, 0)
    if magic not in (b'VINCEXNU', b'SWEETXNU') or ver != 1:
        raise SystemExit('not a VINCEXNU/SWEETXNU v1 payload')
    virt_base, entry_va, adt_off, adt_size, kernel_end, phys_base, mem_size = \
        struct.unpack_from('<7Q', payload, 0x10)
    cmdline = payload[0x48:0x48 + BOOT_LINE_LENGTH]
    delta = phys_base - virt_base
    adt_pa = kernel_end + delta
    ba_pa = (adt_pa + adt_size + PAGE - 1) & ~(PAGE - 1)
    top = ba_pa + PAGE
    img = bytearray(top - phys_base)
    for i in range(nsegs):
        vmaddr, vmsize, foff, fsize = struct.unpack_from('<4Q', payload, 0x2a8 + 32 * i)
        o = vmaddr + delta - phys_base
        img[o:o + fsize] = payload[foff:foff + fsize]
    img[adt_pa - phys_base:adt_pa - phys_base + adt_size] = payload[adt_off:adt_off + adt_size]
    ba = struct.pack('<HH4x4Q6QI4xQI', 2, 2, virt_base, phys_base, mem_size, top,
                     FB_BASE, 1, FB_STRIDE, FB_W, FB_H, 24, 0, adt_pa - delta, adt_size)
    ba += cmdline + b'\0' * 4 + struct.pack('<QQ', 0, mem_size)
    assert len(ba) == 736
    img[ba_pa - phys_base:ba_pa - phys_base + len(ba)] = ba
    return phys_base, bytes(img), ba_pa, entry_va + delta


def stub(ba_pa, entry_pa):
    return struct.pack('<4I2Q', 0x58000080, 0x580000a1, 0xd61f0020, 0xd503201f, ba_pa, entry_pa)


def write_png(path, raw):
    rows = []
    for y in range(FB_H):
        line = raw[y * FB_STRIDE:(y + 1) * FB_STRIDE]
        rows.append(b'\0' + line)  # assume RGB888 in memory
    chunk = lambda t, d: struct.pack('>I', len(d)) + t + d + struct.pack('>I', zlib.crc32(t + d))
    png = b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', FB_W, FB_H, 8, 2, 0, 0, 0))
    png += chunk(b'IDAT', zlib.compress(b''.join(rows), 6)) + chunk(b'IEND', b'')
    open(path, 'wb').write(png)


def qmp(sock_path, *cmds, pmemsave=None):
    s = socket.socket(socket.AF_UNIX)
    s.connect(sock_path)
    f = s.makefile('rw')
    f.readline()

    def call(execute, **args):
        f.write(json.dumps({'execute': execute, 'arguments': args}) + '\n')
        f.flush()
        while True:
            r = json.loads(f.readline())
            if 'return' in r or 'error' in r:
                return r

    call('qmp_capabilities')
    out = []
    for c in cmds:
        r = call('human-monitor-command', **{'command-line': c})
        if 'error' in r:
            print(f'qmp {c!r}: {r["error"]}', file=sys.stderr)
        out.append(r.get('return', ''))
    if pmemsave:
        r = call('pmemsave', val=pmemsave[0], size=pmemsave[1], filename=pmemsave[2])
        if 'error' in r:
            print(f'qmp pmemsave: {r["error"]}', file=sys.stderr)
    s.close()
    return out


import socket  # noqa: E402  (kept late to mirror upstream layout)


def main():
    ap = argparse.ArgumentParser(description="Boot a VINCEXNU payload in QEMU's virt board.")
    ap.add_argument('payload')
    ap.add_argument('outdir')
    ap.add_argument('--secs', type=float, default=45)
    ap.add_argument('--cpu', default='cortex-a53')
    a = ap.parse_args()

    payload = open(a.payload, 'rb').read()
    os.makedirs(a.outdir, exist_ok=True)
    out = os.path.abspath(a.outdir)

    phys_base, img, ba_pa, entry_pa = build_image(payload)
    open(f'{out}/ram.bin', 'wb').write(img)
    open(f'{out}/stub.bin', 'wb').write(stub(ba_pa, entry_pa))
    print(f'phys_base={phys_base:#x} boot_args={ba_pa:#x} entry={entry_pa:#x}', file=sys.stderr)

    mon = f'{out}/mon.sock'
    if os.path.exists(mon):
        os.unlink(mon)
    mem_size = struct.unpack_from('<Q', payload, 0x40)[0]
    ram_gib = max(4, -(-(phys_base + mem_size - 0x40000000) // (1 << 30)))
    cmd = ['qemu-system-aarch64', '-M', 'virt,gic-version=2', '-cpu', a.cpu, '-smp', '1', '-m', f'{ram_gib}G',
           '-nographic', '-serial', f'file:{out}/serial.txt', '-qmp', f'unix:{mon},server,nowait',
           '-d', 'int,guest_errors,unimp', '-D', f'{out}/qemu.log', '-no-reboot',
           '-device', f'loader,file={out}/ram.bin,addr={phys_base:#x},force-raw=on',
           '-device', f'loader,file={out}/stub.bin,addr={STUB_PA:#x},force-raw=on',
           '-device', f'loader,addr={STUB_PA:#x},cpu-num=0']

    p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL)
    t0 = time.time()
    while p.poll() is None and time.time() - t0 < a.secs:
        time.sleep(0.2)

    if p.poll() is None:
        _, regs, = qmp(mon, 'stop', 'info registers', pmemsave=(FB_BASE, FB_STRIDE * FB_H, f'{out}/fb.raw'))
        open(f'{out}/regs.txt', 'w').write(regs)
        p.kill()
        p.wait()
        raw = open(f'{out}/fb.raw', 'rb').read()
        write_png(f'{out}/fb.png', raw)
        os.unlink(f'{out}/fb.raw')
        result = {'status': 'captured', 'fb_bytes': len(raw)}
    else:
        print(f'qemu exited early: {p.returncode}', file=sys.stderr)
        result = {'status': 'qemu_exited', 'qemu_returncode': p.returncode}

    open(f'{out}/result.json', 'w').write(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result), file=sys.stderr)
    return 0 if result.get('status') == 'captured' else 1


if __name__ == '__main__':
    sys.exit(main())
