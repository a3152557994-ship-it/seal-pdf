import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");

function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i += 1) {
    c ^= buf[i];
    for (let k = 0; k < 8; k += 1) {
      c = (c >>> 1) ^ (c & 1 ? 0xedb88320 : 0);
    }
  }
  return (c ^ 0xffffffff) >>> 0;
}

function pngChunk(type, data) {
  const typeBuf = Buffer.from(type, "ascii");
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32BE(data.length, 0);
  const crcInput = Buffer.concat([typeBuf, data]);
  const crcBuf = Buffer.alloc(4);
  crcBuf.writeUInt32BE(crc32(crcInput), 0);
  return Buffer.concat([lenBuf, typeBuf, data, crcBuf]);
}

function encodePng(width, height, rgba) {
  const raw = Buffer.alloc(height * (1 + width * 4));
  for (let y = 0; y < height; y += 1) {
    const rowStart = y * (1 + width * 4);
    raw[rowStart] = 0;
    for (let x = 0; x < width; x += 1) {
      const src = (y * width + x) * 4;
      const dst = rowStart + 1 + x * 4;
      raw[dst] = rgba[src];
      raw[dst + 1] = rgba[src + 1];
      raw[dst + 2] = rgba[src + 2];
      raw[dst + 3] = rgba[src + 3];
    }
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;
  ihdr[9] = 6;
  return Buffer.concat([
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
    pngChunk("IHDR", ihdr),
    pngChunk("IDAT", zlib.deflateSync(raw, { level: 9 })),
    pngChunk("IEND", Buffer.alloc(0)),
  ]);
}

function renderSealIcon(size) {
  const rgba = new Uint8Array(size * size * 4);
  const rCorner = size * 0.22;
  const cx = size / 2;
  const cy = size / 2;

  for (let y = 0; y < size; y += 1) {
    for (let x = 0; x < size; x += 1) {
      const idx = (y * size + x) * 4;
      const qx = Math.abs(x + 0.5 - cx) - (cx - rCorner);
      const qy = Math.abs(y + 0.5 - cy) - (cy - rCorner);
      const dist = Math.hypot(Math.max(qx, 0), Math.max(qy, 0)) + Math.min(Math.max(qx, qy), 0) - rCorner;
      if (dist > 0.6) continue;
      const edgeAlpha = dist > -0.6 ? Math.max(0, Math.min(1, 0.5 - dist)) : 1;

      // Subtle checkerboard cream background + vermilion circular seal ring + center star dot
      const checker = ((Math.floor(x / (size * 0.1)) + Math.floor(y / (size * 0.1))) & 1) === 0;
      let r = checker ? 252 : 241;
      let g = checker ? 250 : 239;
      let b = checker ? 247 : 235;

      const nx = (x + 0.5 - cx) / (size * 0.5);
      const ny = (y + 0.5 - cy) / (size * 0.5);
      const rad = Math.hypot(nx, ny);

      if (Math.abs(rad - 0.66) < 0.075 || rad < 0.19) {
        r = 204;
        g = 31;
        b = 31;
      }

      // Diagonal pen nib stroke
      if (Math.abs(ny + nx * 0.65 - 0.18) < 0.045 && nx > -0.45 && nx < 0.45) {
        r = 17;
        g = 24;
        b = 39;
      }

      rgba[idx] = r;
      rgba[idx + 1] = g;
      rgba[idx + 2] = b;
      rgba[idx + 3] = Math.round(edgeAlpha * 255);
    }
  }
  return encodePng(size, size, rgba);
}

const iconsDir = path.join(ROOT, "docs", "icons");
fs.mkdirSync(iconsDir, { recursive: true });
for (const sz of [180, 192, 512]) {
  fs.writeFileSync(path.join(iconsDir, `icon-${sz}.png`), renderSealIcon(sz));
}
console.log("Generated Seal-PDF PWA icons (180, 192, 512px)");
