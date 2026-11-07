#!/usr/bin/env python3
"""Build the Apple Device Tree (ADT) for Xiaomi Redmi 5 Plus (vince) Qualcomm MSM8953.

Adapted from ios-sweet/tools/mkadt.py for Snapdragon 625 (MSM8953):
- GICv2 Distributor @ 0x0b000000, CPU Interface @ 0x0b002000, virtual-timer-intid 20
- Framebuffer @ 0x90001000, 1080x2160, 24-bpp RGB888, stride 3240
- Physical RAM base @ 0xa0000000 (1.5 GB contiguous upper DRAM on MSM8953)
- SDHCI eMMC controller @ 0x07824900
- Synaptics RMI4 I2C touchscreen @ 0x20 on I2C-3
- iPhone X identity for iOS userland (display-scale 3, no-home-button)
"""
import hashlib
import os
import struct
import sys
import argparse

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "upstream", "ios-sweet", "tools"))
import adt  # noqa: E402

# Vince (MSM8953) Hardware Definitions:
# DRAM Base: 0xa0000000 (verified by live /proc/iomem: 0xa0000000-0xffffffff is 1.5 GB contiguous)
PHYS_BASE = 0xa0000000
MEM_SIZE = 0x58000000  # 1.375 GB contiguous (safe headroom below TZ/modem at top)

PANIC_LOG_SIZE = 0x100000  # 1 MB panic log buffer

# Non-zero SOC base for arm-io so pe_arm_get_soc_base_phys() returns non-zero
SOC_BASE = 0x01000000

# GICv2 (Qualcomm QGIC2) MMIO addresses
GICD, GICD_SIZE = 0x0b000000, 0x1000
GICC, GICC_SIZE = 0x0b002000, 0x1000

# Framebuffer: Continuous splash left by LK (24-bit RGB888, stride 3240)
FB, FB_SIZE = 0x90001000, 1080 * 2160 * 3
FB_W, FB_H, FB_STRIDE = 1080, 2160, 1080 * 3

# Storage: Qualcomm SDHCI eMMC 5.1 host controller
SDHCI, SDHCI_SIZE = 0x07824900, 0x1000

TIMEBASE = 19200000  # 19.2 MHz Qualcomm XO clock
VTIMER_INTID = 20    # Virtual timer PPI (DT index 4: 16 + 4 = 20)

VINCE_ECID = 0x56494e4345000001  # 'VINCE' + 1
BOOT_MANIFEST_HASH = hashlib.sha384(b'vince boot manifest').digest()

D22AP_ADT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../research/ipsw-x/d22ap.adt')

def d22ap_product(path=D22AP_ADT):
    """Fallback or extract /product properties from iPhone X device tree."""
    if os.path.exists(path):
        root, _ = adt.parse(open(path, 'rb').read())
        for c in root.children:
            if dict((k, v) for k, f, v in c.props).get('name') == b'product\0':
                return [(k, v) for k, f, v in c.props if not f and k not in ('name', 'AAPL,phandle')]
    return None

u32 = lambda *v: struct.pack('<%dI' % len(v), *v)
u64 = lambda *v: struct.pack('<%dQ' % len(v), *v)
cstr = lambda s: s.encode() + b'\0'

def node(name, props=(), children=()):
    n = adt.Node()
    n.props = [('name', 0, cstr(name))] + [(k, 0, v) for k, v in props]
    n.children = list(children)
    return n

def build_vince_adt(seed=None):
    phys_base = PHYS_BASE
    mem_size = MEM_SIZE

    panic_base = phys_base + mem_size - PANIC_LOG_SIZE
    mem_size -= PANIC_LOG_SIZE

    seed = seed if seed is not None else os.urandom(64)
    phandle = iter(range(1, 1000))
    ph = lambda: ('AAPL,phandle', u32(next(phandle)))

    chosen = node('chosen', [
        ph(),
        ('dram-base', u64(phys_base)),
        ('dram-size', u64(mem_size)),
        ('random-seed', seed),
        ('debug-enabled', u32(1)),
        ('display-scale', u32(3)),
        ('display-rotation', u32(0)),
        ('unique-chip-id', u64(VINCE_ECID)),
        ('chip-id', u32(0x8015)),  # Apple A11 Bionic (iPhone X)
        ('board-id', u32(0x16)),
        ('embedded-panic-log-size', u32(PANIC_LOG_SIZE)),
        ('firmware-version', cstr('vince-shim')),
        ('system-firmware-version', cstr('vince-shim')),
        ('boot-manifest-hash', BOOT_MANIFEST_HASH),
        ('crypto-hash-method', cstr('sha2-384')),
        ('certificate-production-status', u32(0)),
        ('effective-production-status-ap', u32(0)),
        ('certificate-security-mode', u32(1)),
        ('effective-security-mode-sep', u32(1)),
    ], [
        node('memory-map', [ph()]),
        node('asmb', [ph(), ('lp-sip0', u64(0x6f)), ('lp-sip1', u32(1))])
    ])

    # GICv2 interrupt controller node (named 'interrupt-controller' for pe_fiq.c)
    gic = node('interrupt-controller', [
        ph(),
        ('compatible', cstr('arm,cortex-a15-gic') + cstr('arm,gic-400') + b'\0'),
        ('reg', u64(GICD, GICD_SIZE, GICC, GICC_SIZE)),
        ('interrupt-controller', b''),
        ('#interrupt-cells', u32(3)),
        ('virtual-timer-intid', u32(VTIMER_INTID)),
    ])

    # Also add 'gic' alias node for any lookup of /arm-io/gic
    gic_alias = node('gic', [
        ph(),
        ('compatible', cstr('arm,cortex-a15-gic') + cstr('arm,gic-400') + b'\0'),
        ('reg', u64(GICD, GICD_SIZE, GICC, GICC_SIZE)),
        ('interrupt-controller', b''),
        ('#interrupt-cells', u32(3)),
        ('virtual-timer-intid', u32(VTIMER_INTID)),
    ])

    # Watchdog node with no-pmu flag to prevent watchdogd panic
    wdt = node('wdt', [
        ph(),
        ('no-pmu', u32(1)),
    ])

    # Display subsystem node for backboardd / IOMobileFramebuffer
    disp0 = node('disp0', [
        ph(),
        ('device_type', cstr('display-subsystem')),
        ('compatible', cstr('vince,display') + cstr('sweet,display') + b'\0'),
        # IOMobileFramebuffer reads the canvas from this node: the iPhone X size AppleCLCD presents (1125x2436,
        # 375x812 points @3x; the panel shows the centered 1080x2160 part), as sweet's ADT does.
        ('canvas-width', u32(1125)),
        ('canvas-height', u32(2436)),
    ])

    # SDHCI eMMC Storage Node
    sdhci_node = node('sdhci', [
        ph(),
        ('compatible', cstr('generic-sdhci') + cstr('qcom,sdhci-msm-v4') + b'\0'),
        ('reg', u64(SDHCI, SDHCI_SIZE)),
        # no 'interrupts': the vince MMC driver is polled PIO, and an interrupts property without
        # interrupt-parent sends IODTMapOneInterrupt into an endless loop at arm-io (IODeviceTreeSupport.cpp:579)
    ])

    # Synaptics RMI4 Touchscreen Node
    touch_node = node('touchscreen', [
        ph(),
        ('compatible', cstr('synaptics,rmi4') + b'\0'),
        ('i2c-address', u32(0x20)),
        ('i2c-bus', u32(3)),
        # no 'interrupts': touch is polled over QUP (0099-vince-input); GPIO 65 is not a GIC SPI
    ])

    # No Wi-Fi or Bluetooth driver: MobileGestalt's WifiAddress/BluetoothAddress (for the A11-style UniqueDeviceID)
    # look up IONameMatch wlan / bluetooth and read local-mac-address; with no such service it waits for an
    # IONetworkController, times out and retries forever (lsd's database seed hangs in GenerateBuiltInAppInstallSessionID,
    # SpringBoard and backboardd wait on lsd). Stub nubs with synthetic locally administered addresses, not the phone's.
    wlan = node('wlan', [
        ph(),
        ('device_type', cstr('wlan')),
        ('compatible', cstr('vince,wlan-stub')),
        ('local-mac-address', bytes([0x02, 0x56, 0x49, 0x4e, 0x43, 0x01])),
    ])
    bluetooth = node('bluetooth', [
        ph(),
        ('device_type', cstr('bluetooth')),
        ('compatible', cstr('vince,bluetooth-stub')),
        ('local-mac-address', bytes([0x02, 0x56, 0x49, 0x4e, 0x43, 0x02])),
    ])

    # arm-io with device_type and ranges so pe_arm_get_soc_base_phys() succeeds
    arm_io = node('arm-io', [
        ph(),
        ('device_type', cstr('vince-io')),
        ('compatible', cstr('vince-io') + cstr('arm-io') + b'\0'),
        ('#address-cells', u32(2)),
        ('#size-cells', u32(2)),
        ('ranges', u64(0, SOC_BASE, 0x100000000 - SOC_BASE)),
    ], [gic, gic_alias, wdt, disp0, sdhci_node, touch_node, wlan, bluetooth])

    # Vince Framebuffer console node for early kprintf
    fbcon = node('vince-fbcon', [
        ph(),
        ('reg', u64(FB, FB_SIZE)),
        ('width', u32(FB_W)),
        ('height', u32(FB_H)),
        ('stride', u32(FB_STRIDE)),
    ])

    # System defaults
    defaults = node('defaults', [
        ph(),
        ('no-effaceable-storage', u32(1)),
    ])

    # Buttons: Home button type 2 = iPhone X style (gestures, no physical home button)
    buttons = node('buttons', [
        ph(),
        ('button-names', cstr('volup') + cstr('voldown') + cstr('hold')),
        ('home-button-type', u32(2)),
        ('opposed-power-vol-buttons', u32(1)),
    ])

    # CPUs: Cortex-A53 x8 in two clusters (MPIDR 0x0-0x3, 0x100-0x103). CPU1 is left out: the shim's USB monitor
    # runs there for the whole session. cpu0 running, the rest started by SweetCPU through PSCI CPU_ON.
    cpu_nodes = []
    for core in (0, 2, 3, 4, 5, 6, 7):
        c = node(f'cpu{core}', [
            ph(),
            ('device_type', cstr('cpu')),
            ('compatible', cstr('qcom,cortex-a53') + cstr('ARM,v8') + b'\0'),
            ('reg', u32(core if core < 4 else 0x100 + core - 4)),
            ('cpu-id', u32(core)),
            ('cluster-id', u32(0 if core < 4 else 1)),
            ('cluster-type', u32(0)),
            ('die-cluster-id', u32(0)),
            ('cluster-core-id', u32(core % 4)),
            ('state', cstr('running' if core == 0 else 'stopped')),
            ('timebase-frequency', u32(TIMEBASE)),
            ('clock-frequency', u32(2016000000)),
            ('bus-frequency', u32(100000000)),
            ('memory-frequency', u32(1866000000)),
            ('peripheral-frequency', u32(TIMEBASE)),
            ('fixed-frequency', u32(TIMEBASE)),
            ('cpu-model', cstr('cortex-a53')),
        ])
        cpu_nodes.append(c)

    cpus = node('cpus', [ph(), ('#address-cells', u32(1)), ('#size-cells', u32(0))], cpu_nodes)

    # Product identity: iPhone X (iPhone10,3 / D22AP)
    product_props = d22ap_product()
    if product_props:
        product = [node('product', [ph()] + product_props)]
    else:
        product = [node('product', [
            ph(),
            ('product-id', u32(0x1003)),
            ('product-name', cstr('iPhone X')),
            ('model-number', cstr('D22AP')),
            ('device-class', cstr('iPhone')),
        ])]

    # Panic log region: /pram reg = <panic_base, PANIC_LOG_SIZE>
    pram = node('pram', [ph(), ('reg', u64(panic_base, PANIC_LOG_SIZE))])

    root = node('device-tree', [
        ph(),
        ('compatible', cstr('D22AP') + cstr('iPhone10,3') + cstr('xiaomi,vince') + cstr('qcom,msm8953') + cstr('AppleARM') + b'\0'),
        ('model', cstr('iPhone10,3')),
        ('target-type', cstr('vince')),
        ('target-sub-type', cstr('vince')),
        ('manufacturer', cstr('Apple Inc.')),
        ('device-id', u64(VINCE_ECID)),
        ('timebase-frequency', u32(TIMEBASE)),
        ('#address-cells', u32(2)),
        ('#size-cells', u32(2)),
    ], [chosen, defaults, cpus, arm_io, fbcon, buttons, pram] + product)

    return root

def find(n, name):
    if dict((k, v) for k, f, v in n.props).get('name') == cstr(name):
        return n
    for c in n.children:
        r = find(c, name)
        if r is not None:
            return r
    return None

def set_prop(n, key, value):
    for i, (k, f, v) in enumerate(n.props):
        if k == key:
            n.props[i] = (k, f, value)
            return
    n.props.append((key, 0, value))

def make_xr(root):
    """--xr: iOS draws an iPhone XR screen, 414x896 points @2x = 828x1792 (2.2x fewer pixels than 1125x2436 for the
    CPU renderer, same tall shape as the 1080x2160 panel, gestures and no red status bar, as herolte --scale2).
    Kernel boot-args to match: vincefb_lw=828 vincefb_lh=1792 (and mgreset=1 once, so MobileGestalt re-reads this)."""
    set_prop(find(root, 'chosen'), 'display-scale', u32(2))
    disp0 = find(root, 'disp0')
    set_prop(disp0, 'canvas-width', u32(828))
    set_prop(disp0, 'canvas-height', u32(1792))
    product = find(root, 'product')
    set_prop(product, 'artwork-device-subtype', u32(1792))
    set_prop(product, 'artwork-scale-factor', u32(2))
    return root

def main():
    parser = argparse.ArgumentParser(description="Generate Vince Apple Device Tree")
    parser.add_argument("output", help="Output .adt file path")
    parser.add_argument("--dump", action="store_true", help="Print human readable tree")
    parser.add_argument("--xr", action="store_true", help="iPhone XR screen 828x1792 @2x (faster; boot-args vincefb_lw=828 vincefb_lh=1792)")
    args = parser.parse_args()

    root = build_vince_adt()
    if args.xr:
        make_xr(root)
    data = adt.serialize(root)
    with open(args.output, "wb") as f:
        f.write(data)

    print(f"[+] Vince ADT successfully generated: {args.output} ({len(data)} bytes)")
    if args.dump:
        print(f"    Nodes serialized: {len(data)} bytes")

if __name__ == "__main__":
    main()
