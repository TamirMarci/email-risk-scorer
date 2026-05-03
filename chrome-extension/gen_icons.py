#!/usr/bin/env python3
"""Generate shield+checkmark icons for the Chrome extension (no external deps)."""
import struct, zlib, math, os

def write_png(path, w, h, pixels):
    def chunk(tag, data):
        c = struct.pack('>I', len(data)) + tag + data
        return c + struct.pack('>I', zlib.crc32(tag + data) & 0xFFFFFFFF)
    raw = bytearray()
    for y in range(h):
        raw.append(0)                       # filter type None
        for x in range(w):
            raw.extend(pixels[y * w + x])   # RGBA
    png = (
        b'\x89PNG\r\n\x1a\n'
        + chunk(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 6, 0, 0, 0))
        + chunk(b'IDAT', zlib.compress(bytes(raw)))
        + chunk(b'IEND', b'')
    )
    with open(path, 'wb') as f:
        f.write(png)

def in_shield(nx, ny):
    """True if normalised (nx, ny) falls inside the shield polygon."""
    r = 0.14                                # corner radius (normalised)
    in_rect = 0.08 <= nx <= 0.92 and 0.05 <= ny <= 0.63
    if in_rect and ny < 0.05 + r:
        lc = nx < 0.08 + r and (nx - 0.08 - r)**2 + (ny - 0.05 - r)**2 > r**2
        rc = nx > 0.92 - r and (nx - 0.92 + r)**2 + (ny - 0.05 - r)**2 > r**2
        if lc or rc:
            in_rect = False
    if in_rect:
        return True
    # Triangle bottom: narrows from y=0.63 to point at (0.5, 0.96)
    if 0.63 <= ny <= 0.96:
        t = (ny - 0.63) / (0.96 - 0.63)
        hw = 0.42 * (1.0 - t)
        return 0.5 - hw <= nx <= 0.5 + hw
    return False

def seg_dist(px, py, x1, y1, x2, y2):
    dx, dy = x2 - x1, y2 - y1
    dlen2 = dx * dx + dy * dy
    t = max(0.0, min(1.0, ((px - x1) * dx + (py - y1) * dy) / dlen2)) if dlen2 else 0.0
    return math.hypot(px - x1 - t * dx, py - y1 - t * dy)

def in_checkmark(nx, ny, sw):
    """True if (nx, ny) is within stroke-width sw of the checkmark."""
    # V-shape: (0.27, 0.51) → (0.43, 0.67) → (0.73, 0.33)
    d = min(
        seg_dist(nx, ny, 0.27, 0.51, 0.43, 0.67),
        seg_dist(nx, ny, 0.43, 0.67, 0.73, 0.33),
    )
    return d < sw

def make_pixels(size):
    LIGHT = (59,  130, 246)   # #3b82f6 – top of shield
    DARK  = (29,  78,  216)   # #1d4ed8 – bottom of shield
    WHITE = (255, 255, 255)

    # Stroke scales so it looks right at every size; ~3px at 48px
    sw = max(0.05, 0.13 - size * 0.0004)

    pixels = []
    for y in range(size):
        for x in range(size):
            nx = (x + 0.5) / size
            ny = (y + 0.5) / size
            if in_shield(nx, ny):
                blend = min(1.0, ny / 0.96)            # 0 = top (light), 1 = bottom (dark)
                r = int(LIGHT[0] + (DARK[0] - LIGHT[0]) * blend)
                g = int(LIGHT[1] + (DARK[1] - LIGHT[1]) * blend)
                b = int(LIGHT[2] + (DARK[2] - LIGHT[2]) * blend)
                if in_checkmark(nx, ny, sw):
                    pixels.append((WHITE[0], WHITE[1], WHITE[2], 255))
                else:
                    pixels.append((r, g, b, 255))
            else:
                pixels.append((0, 0, 0, 0))
    return pixels

out_dir = os.path.dirname(os.path.abspath(__file__))
for size in [16, 32, 48, 128]:
    path = os.path.join(out_dir, f'icon{size}.png')
    write_png(path, size, size, make_pixels(size))
    print(f'Created {path}')
