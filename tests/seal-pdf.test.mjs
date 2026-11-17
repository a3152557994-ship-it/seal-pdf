import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  PUBLIC_SPKI_BASE64,
  PRODUCT_SLUG,
  extractTransparentSignature,
  smoothSignatureStrokes,
  computeCircularSealLayout,
  computeOvalSealLayout,
  computeSquareLegalSealLayout,
  applyInkTextureNoise,
  computePerforationSlices,
  sliceRgbaImage,
  buildMultiPageJpegPdf,
  verifyLicenseToken,
} from "../src/seal-engine.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");

function toBase64Url(buf) {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function signTestToken(payloadObj, privateKey) {
  const payloadB64 = toBase64Url(Buffer.from(JSON.stringify(payloadObj), "utf8"));
  const sig = crypto.sign(null, Buffer.from(`OPC1.${payloadB64}`, "utf8"), privateKey);
  return `OPC1.${payloadB64}.${toBase64Url(sig)}`;
}

test("src/seal-engine.mjs and docs/seal-engine.js stay byte-identical and PWA manifest exists", () => {
  const srcBytes = fs.readFileSync(path.join(ROOT, "src", "seal-engine.mjs"), "utf8");
  const docsBytes = fs.readFileSync(path.join(ROOT, "docs", "seal-engine.js"), "utf8");
  assert.equal(srcBytes, docsBytes);
  assert.equal(PUBLIC_SPKI_BASE64, "MCowBQYDK2VwAyEAP5NCVP7CT0tgaGLSGMe4r87SjYRWTM6gN6igBZYSXys=");
  assert.equal(PRODUCT_SLUG, "seal-pdf");

  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, "docs", "manifest.webmanifest"), "utf8"));
  assert.equal(manifest.display, "standalone");
  assert.ok(Array.isArray(manifest.icons) && manifest.icons.length >= 2);
});

test("extractTransparentSignature removes uneven gray shadow background into Alpha=0 while preserving crisp pen strokes", () => {
  const w = 120;
  const h = 80;
  const src = new Uint8ClampedArray(w * h * 4);

  // Fill with heavily shadowed uneven paper: brightness 240 on left -> 125 dark gray shadow on right
  for (let y = 0; y < h; y += 1) {
    for (let x = 0; x < w; x += 1) {
      const p = (y * w + x) * 4;
      const bgLum = Math.round(240 - (x / w) * 115);
      src[p] = bgLum;
      src[p + 1] = bgLum;
      src[p + 2] = bgLum - 4;
      src[p + 3] = 255;
    }
  }

  // Draw a 3px thick horizontal signature stroke across both bright and shadowed halves (y = 39..41, x = 15..105)
  for (let y = 39; y <= 41; y += 1) {
    for (let x = 15; x <= 105; x += 1) {
      const p = (y * w + x) * 4;
      src[p] = 28;
      src[p + 1] = 32;
      src[p + 2] = 42;
      src[p + 3] = 255;
    }
  }

  // Add a lone 1-pixel camera sensor noise speck at (10, 10)
  const speckIdx = (10 * w + 10) * 4;
  src[speckIdx] = 50;
  src[speckIdx + 1] = 50;
  src[speckIdx + 2] = 50;

  const out = extractTransparentSignature(src, w, h, {
    inkColor: "blue",
    shadowThreshold: 18,
    inkSolidThreshold: 45,
  });

  // 1. Bright paper corner (2, 2) must be Alpha = 0
  assert.equal(out.rgba[(2 * w + 2) * 4 + 3], 0);
  // 2. Deep shadow paper corner (115, 75) where paper lum ~ 129 MUST ALSO be Alpha = 0!
  assert.equal(out.rgba[(75 * w + 115) * 4 + 3], 0);
  // 3. Isolated 1px camera speck at (10, 10) must be cleaned to Alpha = 0
  assert.equal(out.rgba[speckIdx + 3], 0);
  // 4. Pen stroke pixel inside deep shadow zone (95, 40) must have high Alpha (> 200) and archival blue ink!
  const strokeIdx = (40 * w + 95) * 4;
  assert.ok(out.rgba[strokeIdx + 3] > 200, `Expected high ink alpha inside shadow, got ${out.rgba[strokeIdx + 3]}`);
  assert.equal(out.rgba[strokeIdx], 15);
  assert.equal(out.rgba[strokeIdx + 1], 61);
  assert.equal(out.rgba[strokeIdx + 2], 145);
  assert.ok(out.transparencyRatio > 0.85);
});

test("Perforation seal (骑缝章) N-equal slicer computes contiguous pixel-exact slices and right-edge coordinates", () => {
  for (const pageCount of [2, 3, 5, 7]) {
    const slices = computePerforationSlices(360, 360, pageCount, {
      pageWidth: 1240,
      pageHeight: 1754,
      targetSealHeight: 220,
      verticalRatio: 0.5,
    });

    assert.equal(slices.length, pageCount);
    const widthSum = slices.reduce((acc, s) => acc + s.srcWidth, 0);
    assert.equal(widthSum, 360, `Expected exact width sum 360 for N=${pageCount}, got ${widthSum}`);

    for (let i = 0; i < slices.length; i += 1) {
      const s = slices[i];
      if (i > 0) {
        assert.equal(s.srcX, slices[i - 1].srcX + slices[i - 1].srcWidth, "Slices must be contiguous without gaps");
      }
      assert.equal(s.destX + s.destWidth, 1240, "Perforation slice must sit flush on contract right edge");
      assert.equal(s.edge, "right");
    }
  }

  // Test RGBA bitmap slicing integrity
  const sealW = 12;
  const sealH = 6;
  const fakeSeal = new Uint8ClampedArray(sealW * sealH * 4);
  for (let y = 0; y < sealH; y += 1) {
    for (let x = 0; x < sealW; x += 1) {
      const p = (y * sealW + x) * 4;
      fakeSeal[p] = x * 10;
      fakeSeal[p + 1] = y * 20;
      fakeSeal[p + 2] = 200;
      fakeSeal[p + 3] = 255;
    }
  }
  const threeSlices = computePerforationSlices(sealW, sealH, 3, { pageWidth: 100, pageHeight: 140 });
  const bitmaps = sliceRgbaImage(fakeSeal, sealW, sealH, threeSlices);
  assert.equal(bitmaps.length, 3);
  assert.equal(bitmaps[0].srcWidth, 4);
  assert.equal(bitmaps[1].rgba[0], 40); // x = 4 -> 4 * 10 = 40
  assert.equal(bitmaps[2].rgba[0], 80); // x = 8 -> 8 * 10 = 80
});

test("Seal geometries, smooth strokes, ink texture & offline multi-page PDF 1.4 generator work cleanly", () => {
  const circ = computeCircularSealLayout({ size: 360, mainText: "星辰工作室测试", subText: "测试章" });
  assert.equal(circ.starVertices.length, 10);
  assert.equal(circ.topArcChars.length, 7);

  const oval = computeOvalSealLayout({ size: 360, mainText: "星辰工作室财务测试" });
  assert.ok(oval.rx > oval.ry);

  const sq = computeSquareLegalSealLayout({ size: 300, mainText: "张明" });
  assert.deepEqual(sq.cells.map((c) => c.char), ["张", "明", "之", "印"]);
  assert.ok(sq.cells[0].x > sq.cells[2].x, "Traditional legal square seal starts on right column");

  const segs = smoothSignatureStrokes([
    { x: 10, y: 20, pressure: 0.3, time: 0 },
    { x: 40, y: 50, pressure: 0.8, time: 20 },
    { x: 80, y: 30, pressure: 0.5, time: 40 },
  ]);
  assert.equal(segs.length, 2);
  assert.ok(segs[0].width > 1.8);

  const rgba = new Uint8ClampedArray([200, 30, 30, 255, 200, 30, 30, 255, 0, 0, 0, 0]);
  applyInkTextureNoise(rgba, 3, 1, { intensity: 0.4, seed: 42 });
  assert.equal(rgba[11], 0, "Transparent pixels remain 0 alpha after ink texture noise");

  // Multi-page PDF 1.4 binary verification
  const fakeJpeg = new Uint8Array([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0xff, 0xd9]);
  const pdfBytes = buildMultiPageJpegPdf([
    { jpegBytes: fakeJpeg, widthPx: 760, heightPx: 1075 },
    { jpegBytes: fakeJpeg, widthPx: 760, heightPx: 1075 },
  ]);
  const pdfHeader = Buffer.from(pdfBytes.subarray(0, 8)).toString("ascii");
  const pdfTail = Buffer.from(pdfBytes.subarray(pdfBytes.length - 32)).toString("ascii");
  assert.equal(pdfHeader, "%PDF-1.4");
  assert.ok(pdfTail.includes("%%EOF"));
  assert.ok(Buffer.from(pdfBytes).toString("latin1").includes("/Count 2"));
});

test("OPC1 Ed25519 license verification accepts valid seal-pdf tokens and rejects wrong product or forged signatures", async () => {
  const fakePayload = toBase64Url(Buffer.from(JSON.stringify({ v: 1, p: "seal-pdf", exp: 0 }), "utf8"));
  const badRes = await verifyLicenseToken(`OPC1.${fakePayload}.${toBase64Url(Buffer.alloc(64, 9))}`);
  assert.equal(badRes.valid, false);
  assert.equal(badRes.reason, "BAD_SIGNATURE");

  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const testSpkiB64 = publicKey.export({ format: "der", type: "spki" }).toString("base64");
  const nowSec = 1794900000;

  const valid = signTestToken({ v: 1, p: "seal-pdf", e: "legal@company.cn", plan: "lifetime", exp: 0 }, privateKey);
  const ok = await verifyLicenseToken(valid, { publicSpkiBase64: testSpkiB64, nowSec });
  assert.equal(ok.valid, true);
  assert.equal(ok.payload.p, "seal-pdf");

  const wrong = signTestToken({ v: 1, p: "invoice-a4", exp: 0 }, privateKey);
  const wrongRes = await verifyLicenseToken(wrong, { publicSpkiBase64: testSpkiB64, nowSec });
  assert.equal(wrongRes.valid, false);
  assert.equal(wrongRes.reason, "PRODUCT_MISMATCH");

  const expired = signTestToken({ v: 1, p: "seal-pdf", exp: nowSec - 30 }, privateKey);
  const expRes = await verifyLicenseToken(expired, { publicSpkiBase64: testSpkiB64, nowSec });
  assert.equal(expRes.valid, false);
  assert.equal(expRes.reason, "EXPIRED");
});

test("Repository contains zero local path or private key leaks", () => {
  function walk(dir) {
    for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
      if (ent.name === ".git" || ent.name === "node_modules") continue;
      const full = path.join(dir, ent.name);
      if (ent.isDirectory()) walk(full);
      else if (/\.(mjs|js|json|webmanifest|html|css|md|txt|xml)$/i.test(ent.name)) {
        const text = fs.readFileSync(full, "utf8");
        assert.equal(text.includes("/Users/" + "wang"), false, `Path leak in ${full}`);
        assert.equal(text.includes("BEGIN " + "PRIVATE KEY"), false, `Private key leak in ${full}`);
      }
    }
  }
  walk(ROOT);
});
