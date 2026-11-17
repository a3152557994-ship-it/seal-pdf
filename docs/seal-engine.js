/**
 * Seal-PDF — 100% Local Offline True-Alpha Signature, Compliant Seal & Perforation Stamp Engine
 * Works identically in Node.js (ESM) and modern browsers (<script type="module">).
 * Zero external dependencies. Zero server uploads.
 *
 * Compliance Notice: Strictly for authorized self-entity testing, internal workflow approval,
 * and personal handwritten signatures. Forging unauthorized third-party seals is strictly prohibited.
 */

export const PUBLIC_SPKI_BASE64 = "MCowBQYDK2VwAyEAP5NCVP7CT0tgaGLSGMe4r87SjYRWTM6gN6igBZYSXys=";
export const PRODUCT_SLUG = "seal-pdf";

export const INK_COLORS = {
  black: [17, 24, 39],
  blue: [15, 61, 145],
  red: [200, 30, 30],
};

// ---- Base64 & Pure-JS Ed25519 Fallback + WebCrypto Verifier ----

function base64ToBytes(b64) {
  const clean = String(b64).replace(/\s+/g, "");
  const bin = atob(clean);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

export function base64UrlToBytes(b64url) {
  const norm = String(b64url).replace(/-/g, "+").replace(/_/g, "/");
  const pad = (4 - (norm.length % 4)) % 4;
  return base64ToBytes(norm + "=".repeat(pad));
}

const SHA512_K = [
  0x428a2f98d728ae22n, 0x7137449123ef65cdn, 0xb5c0fbcfec4d3b2fn, 0xe9b5dba58189dbbcn,
  0x3956c25bf348b538n, 0x59f111f1b605d019n, 0x923f82a4af194f9bn, 0xab1c5ed5da6d8118n,
  0xd807aa98a3030242n, 0x12835b0145706fben, 0x243185be4ee4b28cn, 0x550c7dc3d5ffb4e2n,
  0x72be5d74f27b896fn, 0x80deb1fe3b1696b1n, 0x9bdc06a725c71235n, 0xc19bf174cf692694n,
  0xe49b69c19ef14ad2n, 0xefbe4786384f25e3n, 0x0fc19dc68b8cd5b5n, 0x240ca1cc77ac9c65n,
  0x2de92c6f592b0275n, 0x4a7484aa6ea6e483n, 0x5cb0a9dcbd41fbd4n, 0x76f988da831153b5n,
  0x983e5152ee66dfabn, 0xa831c66d2db43210n, 0xb00327c898fb213fn, 0xbf597fc7beef0ee4n,
  0xc6e00bf33da88fc2n, 0xd5a79147930aa725n, 0x06ca6351e003826fn, 0x142929670a0e6e70n,
  0x27b70a8546d22ffcn, 0x2e1b21385c26c926n, 0x4d2c6dfc5ac42aedn, 0x53380d139d95b3dfn,
  0x650a73548baf63den, 0x766a0abb3c77b2a8n, 0x81c2c92e47edaee6n, 0x92722c851482353bn,
  0xa2bfe8a14cf10364n, 0xa81a664bbc423001n, 0xc24b8b70d0f89791n, 0xc76c51a30654be30n,
  0xd192e819d6ef5218n, 0xd69906245565a910n, 0xf40e35855771202an, 0x106aa07032bbd1b8n,
  0x19a4c116b8d2d0c8n, 0x1e376c085141ab53n, 0x2748774cdf8eeb99n, 0x34b0bcb5e19b48a8n,
  0x391c0cb3c5c95a63n, 0x4ed8aa4ae3418acbn, 0x5b9cca4f7763e373n, 0x682e6ff3d6b2b8a3n,
  0x748f82ee5defb2fcn, 0x78a5636f43172f60n, 0x84c87814a1f0ab72n, 0x8cc702081a6439ecn,
  0x90befffa23631e28n, 0xa4506cebde82bde9n, 0xbef9a3f7b2c67915n, 0xc67178f2e372532bn,
  0xca273eceea26619cn, 0xd186b8c721c0c207n, 0xeada7dd6cde0eb1en, 0xf57d4f7fee6ed178n,
  0x06f067aa72176fban, 0x0a637dc5a2c898a6n, 0x113f9804bef90daen, 0x1b710b35131c471bn,
  0x28db77f523047d84n, 0x32caab7b40c72493n, 0x3c9ebe0a15c9bebcn, 0x431d67c49c100d4cn,
  0x4cc5d4becb3e42b6n, 0x597f299cfc657e2an, 0x5fcb6fab3ad6faecn, 0x6c44198c4a475817n,
];
const MASK64 = 0xffffffffffffffffn;
const ED_P = (1n << 255n) - 19n;
const ED_L = (1n << 252n) + 27742317777372353535851937790883648493n;

function rotr64(x, n) { return ((x >> n) | (x << (64n - n))) & MASK64; }

function sha512(msgBytes) {
  const H = [
    0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
    0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n,
  ];
  const len = msgBytes.length;
  const bitLen = BigInt(len) * 8n;
  const padLen = ((112 - ((len + 1) % 128)) + 128) % 128;
  const total = len + 1 + padLen + 16;
  const buf = new Uint8Array(total);
  buf.set(msgBytes, 0);
  buf[len] = 0x80;
  for (let i = 0; i < 8; i += 1) buf[total - 1 - i] = Number((bitLen >> BigInt(i * 8)) & 0xffn);
  const w = new Array(80);
  for (let offset = 0; offset < total; offset += 128) {
    for (let t = 0; t < 16; t += 1) {
      const idx = offset + t * 8;
      w[t] =
        (BigInt(buf[idx]) << 56n) | (BigInt(buf[idx + 1]) << 48n) |
        (BigInt(buf[idx + 2]) << 40n) | (BigInt(buf[idx + 3]) << 32n) |
        (BigInt(buf[idx + 4]) << 24n) | (BigInt(buf[idx + 5]) << 16n) |
        (BigInt(buf[idx + 6]) << 8n) | BigInt(buf[idx + 7]);
    }
    for (let t = 16; t < 80; t += 1) {
      const s0 = rotr64(w[t - 15], 1n) ^ rotr64(w[t - 15], 8n) ^ (w[t - 15] >> 7n);
      const s1 = rotr64(w[t - 2], 19n) ^ rotr64(w[t - 2], 61n) ^ (w[t - 2] >> 6n);
      w[t] = (w[t - 16] + s0 + w[t - 7] + s1) & MASK64;
    }
    let [a, b, c, d, e, f, g, h] = H;
    for (let t = 0; t < 80; t += 1) {
      const S1 = rotr64(e, 14n) ^ rotr64(e, 18n) ^ rotr64(e, 41n);
      const ch = (e & f) ^ ((~e & MASK64) & g);
      const temp1 = (h + S1 + ch + SHA512_K[t] + w[t]) & MASK64;
      const S0 = rotr64(a, 28n) ^ rotr64(a, 34n) ^ rotr64(a, 39n);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) & MASK64;
      h = g; g = f; f = e; e = (d + temp1) & MASK64;
      d = c; c = b; b = a; a = (temp1 + temp2) & MASK64;
    }
    H[0] = (H[0] + a) & MASK64; H[1] = (H[1] + b) & MASK64;
    H[2] = (H[2] + c) & MASK64; H[3] = (H[3] + d) & MASK64;
    H[4] = (H[4] + e) & MASK64; H[5] = (H[5] + f) & MASK64;
    H[6] = (H[6] + g) & MASK64; H[7] = (H[7] + h) & MASK64;
  }
  const out = new Uint8Array(64);
  for (let j = 0; j < 8; j += 1) {
    for (let k = 0; k < 8; k += 1) out[j * 8 + (7 - k)] = Number((H[j] >> BigInt(k * 8)) & 0xffn);
  }
  return out;
}

function modP(a) { const r = a % ED_P; return r >= 0n ? r : r + ED_P; }
function modPow(base, exp, mod) {
  let result = 1n, b = base % mod, e = exp;
  while (e > 0n) { if (e & 1n) result = (result * b) % mod; b = (b * b) % mod; e >>= 1n; }
  return result;
}
const ED_D = modP(-121665n * modPow(121666n, ED_P - 2n, ED_P));
function leBytesToBigInt(bytes) {
  let x = 0n;
  for (let i = bytes.length - 1; i >= 0; i -= 1) x = (x << 8n) | BigInt(bytes[i]);
  return x;
}
function decodeEdPoint(bytes) {
  if (bytes.length !== 32) return null;
  const copy = new Uint8Array(bytes);
  const xSign = (copy[31] >> 7) & 1;
  copy[31] &= 0x7f;
  const y = leBytesToBigInt(copy);
  if (y >= ED_P) return null;
  const y2 = modP(y * y);
  const u = modP(y2 - 1n);
  const v = modP(ED_D * y2 + 1n);
  const v3 = modP(v * v * v);
  const v7 = modP(v3 * v3 * v);
  let x = modP(modP(u * v3) * modPow(modP(u * v7), (ED_P - 5n) / 8n, ED_P));
  const vx2 = modP(v * modP(x * x));
  if (vx2 === u) { /* ok */ }
  else if (vx2 === modP(-u)) x = modP(x * modPow(2n, (ED_P - 1n) / 4n, ED_P));
  else return null;
  if (x === 0n && xSign === 1) return null;
  if (Number(x & 1n) !== xSign) x = ED_P - x;
  return [x, y, 1n, modP(x * y)];
}
function edAdd(P, Q) {
  const [X1, Y1, Z1, T1] = P;
  const [X2, Y2, Z2, T2] = Q;
  const A = modP((Y1 - X1) * (Y2 - X2));
  const B = modP((Y1 + X1) * (Y2 + X2));
  const C = modP(T1 * 2n * ED_D * T2);
  const D = modP(Z1 * 2n * Z2);
  const E = modP(B - A), F = modP(D - C), G = modP(D + C), H = modP(B + A);
  return [modP(E * F), modP(G * H), modP(F * G), modP(E * H)];
}
function edScalarMul(P, scalar) {
  let R = [0n, 1n, 1n, 0n], Q = P, s = scalar;
  while (s > 0n) { if (s & 1n) R = edAdd(R, Q); Q = edAdd(Q, Q); s >>= 1n; }
  return R;
}
const ED_BASE = (() => {
  const enc = new Uint8Array(32);
  let y = modP(4n * modPow(5n, ED_P - 2n, ED_P));
  for (let i = 0; i < 32; i += 1) { enc[i] = Number(y & 0xffn); y >>= 8n; }
  return decodeEdPoint(enc);
})();
function verifyEd25519Pure(sigBytes, msgBytes, rawPub32) {
  if (!sigBytes || sigBytes.length !== 64 || !rawPub32 || rawPub32.length !== 32) return false;
  const RBytes = sigBytes.subarray(0, 32), SBytes = sigBytes.subarray(32, 64);
  const s = leBytesToBigInt(SBytes);
  if (s >= ED_L) return false;
  const R = decodeEdPoint(RBytes), A = decodeEdPoint(rawPub32);
  if (!R || !A) return false;
  const hInput = new Uint8Array(64 + msgBytes.length);
  hInput.set(RBytes, 0); hInput.set(rawPub32, 32); hInput.set(msgBytes, 64);
  const h = leBytesToBigInt(sha512(hInput)) % ED_L;
  const left = edScalarMul(ED_BASE, s), right = edAdd(R, edScalarMul(A, h));
  return (
    modP(left[0] * right[2] - right[0] * left[2]) === 0n &&
    modP(left[1] * right[2] - right[1] * left[2]) === 0n
  );
}

export async function verifyLicenseToken(token, options = {}) {
  const {
    expectedProduct = PRODUCT_SLUG,
    publicSpkiBase64 = PUBLIC_SPKI_BASE64,
    nowSec = Math.floor(Date.now() / 1000),
  } = options;

  if (typeof token !== "string" || !token.trim()) {
    return { valid: false, reason: "EMPTY_TOKEN" };
  }
  const parts = token.trim().split(".");
  if (parts.length !== 3 || parts[0] !== "OPC1" || !parts[1] || !parts[2]) {
    return { valid: false, reason: "BAD_FORMAT" };
  }

  try {
    const [, payloadB64, sigB64] = parts;
    const spkiBytes = base64ToBytes(publicSpkiBase64);
    const sigBytes = base64UrlToBytes(sigB64);
    const signedBytes = new TextEncoder().encode(`OPC1.${payloadB64}`);

    let verified = false;
    const subtle = globalThis.crypto?.subtle;
    if (subtle && typeof subtle.importKey === "function") {
      try {
        const key = await subtle.importKey("spki", spkiBytes, { name: "Ed25519" }, false, ["verify"]);
        verified = Boolean(await subtle.verify("Ed25519", key, sigBytes, signedBytes));
      } catch {
        const rawPub = spkiBytes.length === 44 ? spkiBytes.subarray(12, 44) : spkiBytes;
        verified = verifyEd25519Pure(sigBytes, signedBytes, rawPub);
      }
    } else {
      const rawPub = spkiBytes.length === 44 ? spkiBytes.subarray(12, 44) : spkiBytes;
      verified = verifyEd25519Pure(sigBytes, signedBytes, rawPub);
    }

    if (!verified) return { valid: false, reason: "BAD_SIGNATURE" };

    const payload = JSON.parse(new TextDecoder().decode(base64UrlToBytes(payloadB64)));
    const prod = payload.p ?? payload.product ?? payload.slug;
    if (expectedProduct && prod !== expectedProduct && prod !== "*") {
      return { valid: false, reason: "PRODUCT_MISMATCH", payload };
    }
    if (typeof payload.exp === "number" && payload.exp > 0 && nowSec > payload.exp) {
      return { valid: false, reason: "EXPIRED", payload };
    }
    return { valid: true, payload, token: token.trim() };
  } catch (err) {
    return { valid: false, reason: "VERIFY_ERROR", message: err?.message };
  }
}

// ---- 1. Adaptive Local Thresholding: Shadowed Paper Signature -> True Alpha PNG ----

function smoothstep(edge0, edge1, x) {
  if (edge1 <= edge0) return x >= edge1 ? 1 : 0;
  const t = Math.max(0, Math.min(1, (x - edge0) / (edge1 - edge0)));
  return t * t * (3 - 2 * t);
}

/**
 * Extract handwritten signature from an unevenly lit / shadowed camera photo into a
 * 100% pure Alpha-transparent RGBA buffer (Alpha = 0 on shadowed paper background).
 *
 * Uses an O(N) Summed-Area Table (Integral Image) local background estimator so dark shadows
 * across paper corners are cleanly separated from pen strokes.
 *
 * @param {Uint8ClampedArray|Uint8Array} srcRgba
 * @param {number} width
 * @param {number} height
 * @param {object} [options]
 * @param {'original'|'black'|'blue'|'red'} [options.inkColor='black']
 * @param {number} [options.shadowThreshold=18] - Minimum contrast below local paper to register ink
 * @param {number} [options.inkSolidThreshold=46] - Contrast level reaching 100% solid alpha (255)
 * @param {number} [options.windowRadius] - Adaptive window radius in pixels
 * @param {boolean} [options.despeckle=true] - Strip 1px isolated camera noise specks
 */
export function extractTransparentSignature(srcRgba, width, height, options = {}) {
  const w = Math.max(1, Math.floor(width));
  const h = Math.max(1, Math.floor(height));
  const totalPixels = w * h;
  const out = new Uint8ClampedArray(totalPixels * 4);

  const inkMode = options.inkColor || "black";
  const shadowFloor = Number(options.shadowThreshold ?? 18);
  const solidCeil = Math.max(shadowFloor + 4, Number(options.inkSolidThreshold ?? 46));
  const radius = Math.max(
    6,
    Math.floor(options.windowRadius ?? Math.max(12, Math.round(Math.min(w, h) / 12)))
  );
  const despeckle = options.despeckle !== false;

  // Step 1: Compute pixel luminance & chroma + build 2D Integral Image (width+1) x (height+1)
  const lumArr = new Float32Array(totalPixels);
  const chromaArr = new Float32Array(totalPixels);
  const stride = w + 1;
  const integral = new Float64Array((w + 1) * (h + 1));

  for (let y = 0; y < h; y += 1) {
    let rowSum = 0;
    const intRowOffset = (y + 1) * stride;
    const prevIntRowOffset = y * stride;
    for (let x = 0; x < w; x += 1) {
      const idx = y * w + x;
      const p = idx * 4;
      const r = srcRgba[p];
      const g = srcRgba[p + 1];
      const b = srcRgba[p + 2];
      const a = srcRgba[p + 3];

      // Transparent input pixels count as bright white paper
      const lum = a < 16 ? 255 : 0.299 * r + 0.587 * g + 0.114 * b;
      const maxC = Math.max(r, g, b);
      const minC = Math.min(r, g, b);
      lumArr[idx] = lum;
      chromaArr[idx] = a < 16 ? 0 : maxC - minC;

      rowSum += lum;
      integral[intRowOffset + x + 1] = integral[prevIntRowOffset + x + 1] + rowSum;
    }
  }

  // Step 2: Compute adaptive local background mean & derive smooth ink Alpha
  const alphaBuf = new Uint8Array(totalPixels);
  for (let y = 0; y < h; y += 1) {
    const y0 = Math.max(0, y - radius);
    const y1 = Math.min(h - 1, y + radius);
    const rTop = y0 * stride;
    const rBot = (y1 + 1) * stride;
    const boxH = y1 - y0 + 1;

    for (let x = 0; x < w; x += 1) {
      const idx = y * w + x;
      if (srcRgba[idx * 4 + 3] < 16) {
        alphaBuf[idx] = 0;
        continue;
      }

      const x0 = Math.max(0, x - radius);
      const x1 = Math.min(w - 1, x + radius);
      const area = (x1 - x0 + 1) * boxH;
      const sum =
        integral[rBot + x1 + 1] -
        integral[rTop + x1 + 1] -
        integral[rBot + x0] +
        integral[rTop + x0];

      const localBg = sum / area;
      const lum = lumArr[idx];
      // Boost colored ink (red/blue pen strokes have strong RGB channel separation vs gray shadows)
      const chromaBoost = Math.max(0, chromaArr[idx] - 26) * 0.7;
      const contrast = localBg - lum + chromaBoost;

      if (contrast <= shadowFloor) {
        alphaBuf[idx] = 0;
      } else {
        const aNorm = smoothstep(shadowFloor, solidCeil, contrast);
        alphaBuf[idx] = Math.round(aNorm * 255);
      }
    }
  }

  // Step 3: Despeckle isolated 1-pixel camera noise while keeping fine pen tips intact
  let inkPixelCount = 0;
  const presetRgb = INK_COLORS[inkMode] || null;

  for (let y = 0; y < h; y += 1) {
    for (let x = 0; x < w; x += 1) {
      const idx = y * w + x;
      let alpha = alphaBuf[idx];

      if (alpha > 0 && despeckle && x > 0 && x < w - 1 && y > 0 && y < h - 1) {
        let activeNeighbors = 0;
        for (let dy = -1; dy <= 1; dy += 1) {
          for (let dx = -1; dx <= 1; dx += 1) {
            if (dx === 0 && dy === 0) continue;
            if (alphaBuf[(y + dy) * w + (x + dx)] > 28) activeNeighbors += 1;
          }
        }
        if (activeNeighbors === 0) alpha = 0;
      }

      const p = idx * 4;
      if (alpha === 0) {
        out[p] = 0;
        out[p + 1] = 0;
        out[p + 2] = 0;
        out[p + 3] = 0;
      } else {
        inkPixelCount += 1;
        if (presetRgb) {
          out[p] = presetRgb[0];
          out[p + 1] = presetRgb[1];
          out[p + 2] = presetRgb[2];
        } else {
          // Reconstruct original ink hue with shadow cast normalized out
          const scale = Math.min(1.35, 195 / Math.max(65, lumArr[idx] + 40));
          out[p] = Math.min(240, Math.round(srcRgba[p] * scale * 0.85));
          out[p + 1] = Math.min(240, Math.round(srcRgba[p + 1] * scale * 0.85));
          out[p + 2] = Math.min(240, Math.round(srcRgba[p + 2] * scale * 0.85));
        }
        out[p + 3] = alpha;
      }
    }
  }

  const transparentPixelCount = totalPixels - inkPixelCount;
  return {
    rgba: out,
    width: w,
    height: h,
    inkPixelCount,
    transparentPixelCount,
    transparencyRatio: totalPixels > 0 ? transparentPixelCount / totalPixels : 1,
  };
}

// ---- 2. Trackpad / Apple Pencil Pressure-Sensitive Stroke Smoothing ----

export function smoothSignatureStrokes(points, options = {}) {
  const minWidth = Number(options.minWidth ?? 1.8);
  const maxWidth = Number(options.maxWidth ?? 6.2);
  if (!Array.isArray(points) || points.length === 0) return [];
  if (points.length === 1) {
    const p = points[0];
    const w = minWidth + (maxWidth - minWidth) * (p.pressure ?? 0.5);
    return [{ x0: p.x, y0: p.y, cx: p.x, cy: p.y, x1: p.x + 0.1, y1: p.y + 0.1, width: w }];
  }

  const segments = [];
  for (let i = 1; i < points.length; i += 1) {
    const prev = points[i - 1];
    const curr = points[i];
    const next = points[Math.min(points.length - 1, i + 1)];

    const x0 = i === 1 ? prev.x : (prev.x + curr.x) / 2;
    const y0 = i === 1 ? prev.y : (prev.y + curr.y) / 2;
    const x1 = i === points.length - 1 ? curr.x : (curr.x + next.x) / 2;
    const y1 = i === points.length - 1 ? curr.y : (curr.y + next.y) / 2;

    let pressure = typeof curr.pressure === "number" && curr.pressure > 0 && curr.pressure !== 0.5
      ? curr.pressure
      : null;

    if (pressure === null) {
      const dist = Math.hypot(curr.x - prev.x, curr.y - prev.y);
      const dt = Math.max(4, (curr.time || i * 16) - (prev.time || (i - 1) * 16));
      const velocity = dist / dt;
      pressure = Math.max(0.2, Math.min(0.92, 0.85 - velocity * 0.35));
    }

    const strokeWidth = Math.round((minWidth + (maxWidth - minWidth) * pressure) * 100) / 100;
    segments.push({
      x0,
      y0,
      cx: curr.x,
      cy: curr.y,
      x1,
      y1,
      width: strokeWidth,
    });
  }
  return segments;
}

// ---- 3. Compliant Seal Geometry & Ink Texture Engine ----

export function computeStarVertices(cx, cy, outerRadius, innerRadius = outerRadius * 0.382) {
  const pts = [];
  for (let i = 0; i < 10; i += 1) {
    const r = i % 2 === 0 ? outerRadius : innerRadius;
    const angle = -Math.PI / 2 + (i * Math.PI) / 5;
    pts.push({
      x: cx + Math.cos(angle) * r,
      y: cy + Math.sin(angle) * r,
    });
  }
  return pts;
}

export function computeArcCharPlacements(text, cx, cy, rx, ry, spanDeg = 220, isBottom = false) {
  const chars = Array.from(String(text || "").trim());
  if (chars.length === 0) return [];
  const spanRad = (Math.min(310, Math.max(30, spanDeg)) * Math.PI) / 180;
  const centerAngle = isBottom ? Math.PI / 2 : -Math.PI / 2;

  return chars.map((ch, idx) => {
    const t = chars.length === 1 ? 0 : idx / (chars.length - 1) - 0.5;
    const theta = isBottom ? centerAngle - t * spanRad : centerAngle + t * spanRad;
    const x = cx + Math.cos(theta) * rx;
    const y = cy + Math.sin(theta) * ry;
    // Tangent rotation so character upright points outward (top arc) or inward-readable (bottom arc)
    const dx = -Math.sin(theta) * rx;
    const dy = Math.cos(theta) * ry;
    const tangent = Math.atan2(dy, dx);
    const rotationRad = isBottom ? tangent + Math.PI : tangent;
    return { char: ch, x, y, theta, rotationRad };
  });
}

export function computeCircularSealLayout(config = {}) {
  const size = Number(config.size ?? 360);
  const cx = size / 2;
  const cy = size / 2;
  const outerRadius = size * 0.44;
  const borderWidth = Number(config.borderWidth ?? Math.round(size * 0.026));
  const mainText = String(config.mainText || "星辰创意工作室内部测试专用");
  const subText = String(config.subText || "测试流转章");
  const codeText = String(config.codeText || "0102030405068");
  const showStar = config.showStar !== false;

  return {
    shape: "circular",
    size,
    cx,
    cy,
    outerRadius,
    borderWidth,
    starVertices: showStar ? computeStarVertices(cx, cy, outerRadius * 0.28) : [],
    topArcChars: computeArcCharPlacements(
      mainText,
      cx,
      cy,
      outerRadius * 0.74,
      outerRadius * 0.74,
      Math.min(255, Math.max(120, mainText.length * 19)),
      false
    ),
    subTitle: {
      text: subText,
      x: cx,
      y: cy + outerRadius * 0.5,
      fontSize: Math.round(size * 0.072),
    },
    bottomCodeChars: codeText
      ? computeArcCharPlacements(codeText, cx, cy, outerRadius * 0.82, outerRadius * 0.82, 95, true)
      : [],
  };
}

export function computeOvalSealLayout(config = {}) {
  const size = Number(config.size ?? 360);
  const cx = size / 2;
  const cy = size / 2;
  const rx = size * 0.45;
  const ry = size * 0.31;
  const borderWidth = Number(config.borderWidth ?? Math.round(size * 0.022));
  const mainText = String(config.mainText || "星辰创意工作室测试主体");
  const centerCode = String(config.codeText || "91310000TEST0001X");
  const subText = String(config.subText || "财务内部测试章");

  return {
    shape: "oval",
    size,
    cx,
    cy,
    rx,
    ry,
    borderWidth,
    topArcChars: computeArcCharPlacements(mainText, cx, cy, rx * 0.78, ry * 0.75, 200, false),
    centerCode: { text: centerCode, x: cx, y: cy + ry * 0.04, fontSize: Math.round(size * 0.052) },
    subTitle: { text: subText, x: cx, y: cy + ry * 0.54, fontSize: Math.round(size * 0.068) },
  };
}

export function computeSquareLegalSealLayout(config = {}) {
  const size = Number(config.size ?? 300);
  const boxSize = size * 0.78;
  const x0 = (size - boxSize) / 2;
  const y0 = (size - boxSize) / 2;
  const borderWidth = Number(config.borderWidth ?? Math.round(size * 0.036));
  const rawChars = Array.from(String(config.mainText || "林知远").trim()).slice(0, 4);

  let fourChars;
  if (rawChars.length === 2) {
    fourChars = [rawChars[0], rawChars[1], "之", "印"];
  } else if (rawChars.length === 3) {
    fourChars = [rawChars[0], rawChars[1], rawChars[2], "印"];
  } else if (rawChars.length >= 4) {
    fourChars = rawChars.slice(0, 4);
  } else {
    fourChars = [rawChars[0] || "印", "之", "测", "试"];
  }

  // Traditional seal reading order: Right-Top (0), Right-Bottom (1), Left-Top (2), Left-Bottom (3)
  const quarter = boxSize / 4;
  const cxRight = x0 + quarter * 3;
  const cxLeft = x0 + quarter;
  const cyTop = y0 + quarter;
  const cyBottom = y0 + quarter * 3;

  return {
    shape: "square",
    size,
    box: { x: x0, y: y0, width: boxSize, height: boxSize },
    borderWidth,
    cells: [
      { char: fourChars[0], x: cxRight, y: cyTop, order: 0 },
      { char: fourChars[1], x: cxRight, y: cyBottom, order: 1 },
      { char: fourChars[2], x: cxLeft, y: cyTop, order: 2 },
      { char: fourChars[3], x: cxLeft, y: cyBottom, order: 3 },
    ],
  };
}

/**
 * Apply realistic vermilion ink sponge micro-grain & subtle aging distress to RGBA seal pixels.
 */
export function applyInkTextureNoise(rgba, width, height, options = {}) {
  const intensity = Math.max(0, Math.min(1, Number(options.intensity ?? 0.24)));
  if (intensity <= 0) return rgba;

  let seed = (Number(options.seed ?? 20261117) >>> 0) || 1;
  const nextRand = () => {
    seed ^= seed << 13;
    seed ^= seed >>> 17;
    seed ^= seed << 5;
    return (seed >>> 0) / 4294967296;
  };

  for (let i = 0; i < width * height; i += 1) {
    const aIdx = i * 4 + 3;
    const a = rgba[aIdx];
    if (a === 0) continue;

    const r1 = nextRand();
    const r2 = nextRand();
    // Occasional tiny dry-ink fiber pores + subtle opacity modulation
    if (r1 < intensity * 0.16) {
      rgba[aIdx] = Math.round(a * (0.2 + r2 * 0.35));
    } else {
      const mod = 1 - intensity * 0.28 * r2;
      rgba[aIdx] = Math.max(0, Math.min(255, Math.round(a * mod)));
    }
  }
  return rgba;
}

/**
 * Render Circular, Oval, or Square seal onto a 2D CanvasRenderingContext2D.
 */
export function renderSealToContext(ctx, config = {}) {
  const size = Number(config.size ?? 360);
  const shape = config.shape || "circular";
  const color = config.color || "#c81e1e";
  const angleDeg = Number(config.rotationDeg ?? -6);
  const noiseIntensity = Number(config.noiseIntensity ?? 0.22);

  ctx.clearRect(0, 0, size, size);
  ctx.save();
  ctx.translate(size / 2, size / 2);
  ctx.rotate((angleDeg * Math.PI) / 180);
  ctx.translate(-size / 2, -size / 2);

  ctx.strokeStyle = color;
  ctx.fillStyle = color;
  ctx.textAlign = "center";
  ctx.textBaseline = "middle";

  if (shape === "oval") {
    const spec = computeOvalSealLayout({ ...config, size });
    ctx.lineWidth = spec.borderWidth;
    ctx.beginPath();
    ctx.ellipse(spec.cx, spec.cy, spec.rx, spec.ry, 0, 0, Math.PI * 2);
    ctx.stroke();

    ctx.lineWidth = Math.max(1.5, spec.borderWidth * 0.35);
    ctx.beginPath();
    ctx.ellipse(spec.cx, spec.cy, spec.rx - spec.borderWidth * 1.15, spec.ry - spec.borderWidth * 1.15, 0, 0, Math.PI * 2);
    ctx.stroke();

    ctx.font = `bold ${Math.round(size * 0.068)}px "Songti SC", "STSong", "Noto Serif SC", serif`;
    spec.topArcChars.forEach((g) => {
      ctx.save();
      ctx.translate(g.x, g.y);
      ctx.rotate(g.rotationRad);
      ctx.fillText(g.char, 0, 0);
      ctx.restore();
    });

    ctx.font = `600 ${spec.centerCode.fontSize}px ui-monospace, Menlo, monospace`;
    ctx.fillText(spec.centerCode.text, spec.centerCode.x, spec.centerCode.y);

    ctx.font = `bold ${spec.subTitle.fontSize}px "Songti SC", "PingFang SC", serif`;
    ctx.fillText(spec.subTitle.text, spec.subTitle.x, spec.subTitle.y);
  } else if (shape === "square") {
    const spec = computeSquareLegalSealLayout({ ...config, size });
    ctx.lineWidth = spec.borderWidth;
    ctx.strokeRect(spec.box.x, spec.box.y, spec.box.width, spec.box.height);

    // Subtle inner cross hair guide lines (classic personal seal touch)
    ctx.lineWidth = Math.max(1.5, spec.borderWidth * 0.26);
    ctx.beginPath();
    ctx.moveTo(spec.box.x + spec.box.width / 2, spec.box.y);
    ctx.lineTo(spec.box.x + spec.box.width / 2, spec.box.y + spec.box.height);
    ctx.moveTo(spec.box.x, spec.box.y + spec.box.height / 2);
    ctx.lineTo(spec.box.x + spec.box.width, spec.box.y + spec.box.height / 2);
    ctx.stroke();

    ctx.font = `bold ${Math.round(spec.box.width * 0.34)}px "Kaiti SC", "STKaiti", "Songti SC", serif`;
    spec.cells.forEach((cell) => {
      ctx.fillText(cell.char, cell.x, cell.y + 2);
    });
  } else {
    const spec = computeCircularSealLayout({ ...config, size });
    ctx.lineWidth = spec.borderWidth;
    ctx.beginPath();
    ctx.arc(spec.cx, spec.cy, spec.outerRadius, 0, Math.PI * 2);
    ctx.stroke();

    if (spec.starVertices.length > 0) {
      ctx.beginPath();
      spec.starVertices.forEach((pt, idx) => {
        if (idx === 0) ctx.moveTo(pt.x, pt.y);
        else ctx.lineTo(pt.x, pt.y);
      });
      ctx.closePath();
      ctx.fill();
    }

    ctx.font = `bold ${Math.round(size * 0.078)}px "Songti SC", "STSong", "Noto Serif SC", serif`;
    spec.topArcChars.forEach((g) => {
      ctx.save();
      ctx.translate(g.x, g.y);
      ctx.rotate(g.rotationRad);
      ctx.scale(0.88, 1.08);
      ctx.fillText(g.char, 0, 0);
      ctx.restore();
    });

    ctx.font = `bold ${spec.subTitle.fontSize}px "Songti SC", "PingFang SC", serif`;
    ctx.fillText(spec.subTitle.text, spec.subTitle.x, spec.subTitle.y);

    if (spec.bottomCodeChars.length > 0) {
      ctx.font = `600 ${Math.round(size * 0.042)}px ui-monospace, Menlo, monospace`;
      spec.bottomCodeChars.forEach((g) => {
        ctx.save();
        ctx.translate(g.x, g.y);
        ctx.rotate(g.rotationRad);
        ctx.fillText(g.char, 0, 0);
        ctx.restore();
      });
    }
  }

  ctx.restore();

  if (noiseIntensity > 0 && typeof ctx.getImageData === "function") {
    const imgData = ctx.getImageData(0, 0, size, size);
    applyInkTextureNoise(imgData.data, size, size, { intensity: noiseIntensity });
    ctx.putImageData(imgData, 0, 0);
  }
}

// ---- 4. Multi-Page Perforation Seal (骑缝章) N-Equal Slicer ----

/**
 * Compute exact N-page perforation (straddle) seal slices and right-edge placement coordinates.
 * Guarantees sum of slice `srcWidth` equals `sealWidth` with zero gaps or overlaps.
 */
export function computePerforationSlices(sealWidth, sealHeight, pageCount, options = {}) {
  const sw = Math.max(2, Math.floor(sealWidth));
  const sh = Math.max(2, Math.floor(sealHeight));
  const n = Math.max(2, Math.floor(pageCount));
  const pageWidth = Number(options.pageWidth ?? 1240);
  const pageHeight = Number(options.pageHeight ?? 1754);
  const targetSealHeight = Number(options.targetSealHeight ?? Math.round(pageHeight * 0.14));
  const verticalRatio = Math.max(0.05, Math.min(0.95, Number(options.verticalRatio ?? 0.5)));
  const scale = targetSealHeight / sh;

  const slices = [];
  for (let i = 0; i < n; i += 1) {
    const x0 = Math.round((i * sw) / n);
    const x1 = Math.round(((i + 1) * sw) / n);
    const srcWidth = Math.max(1, x1 - x0);
    const destWidth = Math.max(1, Math.round(srcWidth * scale));
    const destHeight = Math.round(targetSealHeight);
    const destX = pageWidth - destWidth;
    const destY = Math.round((pageHeight - destHeight) * verticalRatio);

    slices.push({
      pageIndex: i,
      pageNumber: i + 1,
      totalPages: n,
      srcX: x0,
      srcY: 0,
      srcWidth,
      srcHeight: sh,
      destX,
      destY,
      destWidth,
      destHeight,
      edge: "right",
    });
  }
  return slices;
}

/**
 * Slice an RGBA bitmap vertically according to `computePerforationSlices` output.
 */
export function sliceRgbaImage(srcRgba, width, height, slices) {
  return slices.map((s) => {
    const out = new Uint8ClampedArray(s.srcWidth * s.srcHeight * 4);
    for (let y = 0; y < s.srcHeight; y += 1) {
      const srcRow = (s.srcY + y) * width + s.srcX;
      const dstRow = y * s.srcWidth;
      for (let x = 0; x < s.srcWidth; x += 1) {
        const sp = (srcRow + x) * 4;
        const dp = (dstRow + x) * 4;
        out[dp] = srcRgba[sp];
        out[dp + 1] = srcRgba[sp + 1];
        out[dp + 2] = srcRgba[sp + 2];
        out[dp + 3] = srcRgba[sp + 3];
      }
    }
    return {
      ...s,
      rgba: out,
    };
  });
}

// ---- 5. Pure-JS Offline Multi-Page PDF Binary Generator (DCTDecode JPEG Pages) ----

/**
 * Build a standards-compliant multi-page PDF 1.4 document from an array of JPEG byte buffers.
 * Runs 100% offline in browser or Node.js with zero dependencies.
 * @param {Array<{jpegBytes: Uint8Array, widthPx: number, heightPx: number, pageWidthPt?: number, pageHeightPt?: number}>} pages
 * @returns {Uint8Array}
 */
export function buildMultiPageJpegPdf(pages) {
  if (!Array.isArray(pages) || pages.length === 0) {
    throw new Error("At least one page is required to generate PDF");
  }

  const enc = new TextEncoder();
  const chunks = [];
  let offset = 0;
  const pushBytes = (u8) => {
    chunks.push(u8);
    offset += u8.length;
  };
  const pushStr = (s) => pushBytes(enc.encode(s));

  // Object numbering:
  // 1: Catalog
  // 2: Pages root
  // For page i (0..N-1):
  //   3 + i*3     : Page object
  //   3 + i*3 + 1 : Image XObject
  //   3 + i*3 + 2 : Content stream
  const totalObjects = 2 + pages.length * 3;
  const offsets = new Array(totalObjects + 1).fill(0);

  pushStr("%PDF-1.4\n%\xFF\xFF\xFF\xFF\n");

  // Obj 1: Catalog
  offsets[1] = offset;
  pushStr("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

  // Obj 2: Pages
  const kidsRefs = pages.map((_, i) => `${3 + i * 3} 0 R`).join(" ");
  offsets[2] = offset;
  pushStr(`2 0 obj\n<< /Type /Pages /Count ${pages.length} /Kids [ ${kidsRefs} ] >>\nendobj\n`);

  pages.forEach((p, i) => {
    const pageObjId = 3 + i * 3;
    const imgObjId = pageObjId + 1;
    const contentObjId = pageObjId + 2;
    const pw = Number(p.pageWidthPt ?? 595.28).toFixed(2);
    const ph = Number(p.pageHeightPt ?? 841.89).toFixed(2);
    const imgName = `/Im${i + 1}`;

    // Page object
    offsets[pageObjId] = offset;
    pushStr(
      `${pageObjId} 0 obj\n` +
        `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${pw} ${ph}] ` +
        `/Resources << /XObject << ${imgName} ${imgObjId} 0 R >> >> ` +
        `/Contents ${contentObjId} 0 R >>\nendobj\n`
    );

    // JPEG XObject
    const jpeg = p.jpegBytes instanceof Uint8Array ? p.jpegBytes : new Uint8Array(p.jpegBytes);
    offsets[imgObjId] = offset;
    pushStr(
      `${imgObjId} 0 obj\n` +
        `<< /Type /XObject /Subtype /Image /Width ${Math.round(p.widthPx)} /Height ${Math.round(p.heightPx)} ` +
        `/ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode /Length ${jpeg.length} >>\nstream\n`
    );
    pushBytes(jpeg);
    pushStr("\nendstream\nendobj\n");

    // Content stream drawing full-bleed page image
    const drawCmd = `q\n${pw} 0 0 ${ph} 0 0 cm\n${imgName} Do\nQ\n`;
    const drawBytes = enc.encode(drawCmd);
    offsets[contentObjId] = offset;
    pushStr(`${contentObjId} 0 obj\n<< /Length ${drawBytes.length} >>\nstream\n`);
    pushBytes(drawBytes);
    pushStr("endstream\nendobj\n");
  });

  const xrefStart = offset;
  pushStr(`xref\n0 ${totalObjects + 1}\n`);
  pushStr("0000000000 65535 f \n");
  for (let id = 1; id <= totalObjects; id += 1) {
    pushStr(`${String(offsets[id]).padStart(10, "0")} 00000 n \n`);
  }
  pushStr(
    `trailer\n<< /Size ${totalObjects + 1} /Root 1 0 R >>\nstartxref\n${xrefStart}\n%%EOF\n`
  );

  const out = new Uint8Array(offset);
  let cursor = 0;
  for (const ch of chunks) {
    out.set(ch, cursor);
    cursor += ch.length;
  }
  return out;
}
