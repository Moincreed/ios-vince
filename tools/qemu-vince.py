#!/usr/bin/env python3
"""Boot a VINCEXNU payload in QEMU's virt board - sampling edition.

qemu-vince.py PAYLOAD OUTDIR [--secs N] [--cpu CPU] [--sample N]

Every --sample seconds: QMP stop -> info registers -> stack+fb dumps -> cont.
Outputs: fb.png (final), regs.txt, samples.json, stack_t*.bin, fb_t*.png.
"""
import argparse, json, os, re, socket, struct, subprocess, sys, time, zlib

FB_BASE, FB_W, FB_H = 0x90001000, 1080, 2160
FB_STRIDE = FB_W * 3
PAGE = 0x1000
STUB_PA = 0x40200000
BOOT_LINE_LENGTH = 608


class QMP:
    def __init__(self, path, timeout=10):
        self.s = socket.socket(socket.AF_UNIX)
        self.s.settimeout(timeout)
        self.s.connect(path)
        self.f = self.s.makefile('rw')
        self.f.readline()

    def call(self, execute, **args):
        self.f.write(json.dumps({'execute': execute, 'arguments': args}) + '\n')
        self.f.flush()
        while True:
            line = self.f.readline()
            if not line:
                raise TimeoutError('QMP connection closed')
            r = json.loads(line)
            if 'return' in r or 'error' in r:
                return r

    def hmp(self, cmdline):
        r = self.call('human-monitor-command', **{'command-line': cmdline})
        if 'error' in r:
            print(f'HMP {cmdline!r} error: {r["error"]}', file=sys.stderr)
            return ''
        return r.get('return', '')


def build_image(payload):
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
        rows.append(b'\0' + raw[y * FB_STRIDE:(y + 1) * FB_STRIDE])
    chunk = lambda t, d: struct.pack('>I', len(d)) + t + d + struct.pack('>I', zlib.crc32(t + d))
    png = b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', FB_W, FB_H, 8, 2, 0, 0, 0))
    png += chunk(b'IDAT', zlib.compress(b''.join(rows), 6)) + chunk(b'IEND', b'')
    open(path, 'wb').write(png)


def parse_regs(text):
    regs = {}
    for m in re.finditer(r'(PC|X\d+|SP)=([0-9a-fA-F]+)', text):
        regs[m.group(1)] = int(m.group(2), 16)
    return regs


def sample(q, out, t, samples):
    q.call('stop')
    regs_txt = q.hmp('info registers')
    regs = parse_regs(regs_txt)
    if not regs:
        print(f'info registers EMPTY raw[:160]={regs_txt[:160]!r}', file=sys.stderr)
    fp = regs.get('X29', 0)
    stack = b''
    if fp and fp > 0x40000000:
        q.hmp(f'pmemsave {fp:#x} 4096 {out}/stack_{t}.bin')
        stack_path = f'{out}/stack_{t}.bin'
        if os.path.exists(stack_path):
            stack = open(stack_path, 'rb').read()
    q.hmp(f'pmemsave {FB_BASE:#x} {FB_STRIDE * FB_H} {out}/fbsnap.bin')
    fb_path = f'{out}/fbsnap.bin'
    if os.path.exists(fb_path):
        write_png(f'{out}/fb_t{t}.png', open(fb_path, 'rb').read())
        os.unlink(fb_path)
    q.call('cont')
    entry = {'t': t, 'pc': regs.get('PC', 0), 'x30': regs.get('X30', 0),
             'x29': fp, 'sp': regs.get('SP', 0)}
    chain = []
    cur = fp
    while stack and 0 <= cur - fp < len(stack) - 16:
        off = cur - fp
        next_fp, lr = struct.unpack_from('<2Q', stack, off)
        chain.append(hex(lr))
        if not next_fp or next_fp <= cur:
            break
        cur = next_fp
    entry['chain'] = chain
    samples.append(entry)
    print(f'sample t={t}s pc={entry["pc"]:#x} fp={fp:#x} frames={len(chain)}', file=sys.stderr)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('payload')
    ap.add_argument('outdir')
    ap.add_argument('--secs', type=float, default=45)
    ap.add_argument('--cpu', default='cortex-a53')
    ap.add_argument('--sample', type=float, default=0)
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
    samples = []
    t0 = time.time()
    next_sample = a.sample if a.sample > 0 else None
    q = None
    fails = 0
    while p.poll() is None and time.time() - t0 < a.secs:
        el = time.time() - t0
        if next_sample is not None and el >= next_sample:
            try:
                if q is None:
                    q = QMP(mon)
                sample(q, out, int(el), samples)
                fails = 0
            except Exception as e:
                print(f'sample failed: {type(e).__name__}: {e}', file=sys.stderr)
                fails += 1
                try:
                    if q:
                        q.close()
                except Exception:
                    pass
                q = None
                if fails >= 3:
                    print('sampling disabled after repeated failures', file=sys.stderr)
                    next_sample = None
            if next_sample is not None:
                next_sample += a.sample
        time.sleep(0.2)

    result = {'status': 'qemu_exited', 'qemu_returncode': p.returncode}
    if p.poll() is None:
        try:
            if q is None:
                q = QMP(mon)
            q.call('stop')
            regs_txt = q.hmp('info registers')
            open(f'{out}/regs.txt', 'w').write(regs_txt)
            q.hmp(f'pmemsave {FB_BASE:#x} {out}/fb.raw {FB_STRIDE * FB_H}')
            p.kill()
            p.wait()
            raw = open(f'{out}/fb.raw', 'rb').read()
            write_png(f'{out}/fb.png', raw)
            os.unlink(f'{out}/fb.raw')
            result = {'status': 'captured', 'samples': len(samples)}
        except Exception as e:
            print(f'final capture failed: {e}', file=sys.stderr)
            p.kill()
            p.wait()
    else:
        print(f'qemu exited early: {p.returncode}', file=sys.stderr)

    open(f'{out}/result.json', 'w').write(json.dumps(result, indent=2) + '\n')
    open(f'{out}/samples.json', 'w').write(json.dumps(samples, indent=2) + '\n')
    print(json.dumps(result), file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main())

