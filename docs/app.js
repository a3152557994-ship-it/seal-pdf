import {
  PRODUCT_SLUG,
  extractTransparentSignature,
  smoothSignatureStrokes,
  renderSealToContext,
  computePerforationSlices,
  buildMultiPageJpegPdf,
  verifyLicenseToken,
} from "./seal-engine.js";

const STORAGE_KEY = "seal_pdf_opc1_token";

let isPro = false;
let activeSigMode = "photo"; // 'photo' | 'pad'
let activePageIdx = 2; // Default show Page 3 (signature page) so user sees both main stamp & perforation!

//Canvases
const rawSigCanvas = document.getElementById("rawSigCanvas");
const cleanSigCanvas = document.getElementById("cleanSigCanvas");
const padCanvas = document.getElementById("padCanvas");
const sealPreviewCanvas = document.getElementById("sealPreviewCanvas");
const contractStageCanvas = document.getElementById("contractStageCanvas");

// Offscreen high-res seal canvas (360x360)
const hiSealCanvas = document.createElement("canvas");
hiSealCanvas.width = 360;
hiSealCanvas.height = 360;

// Contract pages array (each is an offscreen Canvas 760x1075)
let contractPages = [];

// Draggable overlays on contract page
const overlays = {
  sig: { enabled: true, pageIndex: 2, x: 455, y: 845, width: 190, height: 85 },
  seal: { enabled: true, pageIndex: 2, x: 495, y: 780, width: 156, height: 156 },
};

// ---- 1. Shadowed Camera Signature Synthesis & True-Alpha Extraction ----

function generateShadowedPaperSample() {
  const ctx = rawSigCanvas.getContext("2d");
  const w = rawSigCanvas.width;
  const h = rawSigCanvas.height;

  // Simulate dim indoor photo of paper: bright warm-gray top-left (235) -> heavy shadow bottom-right (126)
  const img = ctx.createImageData(w, h);
  for (let y = 0; y < h; y += 1) {
    for (let x = 0; x < w; x += 1) {
      const p = (y * w + x) * 4;
      const gx = x / w;
      const gy = y / h;
      const vignette = Math.hypot(gx - 0.82, gy - 0.85);
      const baseLum = Math.round(236 - gx * 68 - gy * 44 + Math.sin(x * 0.17) * 2 + (vignette < 0.45 ? -16 : 0));
      img.data[p] = Math.min(250, baseLum + 3);
      img.data[p + 1] = baseLum;
      img.data[p + 2] = Math.max(95, baseLum - 6);
      img.data[p + 3] = 255;
    }
  }
  ctx.putImageData(img, 0, 0);

  // Draw realistic handwritten fountain-pen signature right across the dark shadow!
  ctx.save();
  ctx.strokeStyle = "#262930";
  ctx.lineCap = "round";
  ctx.lineJoin = "round";

  ctx.lineWidth = 5.2;
  ctx.beginPath();
  ctx.moveTo(54, 108);
  ctx.bezierCurveTo(85, 42, 118, 48, 108, 122);
  ctx.bezierCurveTo(104, 92, 146, 62, 168, 96);
  ctx.stroke();

  ctx.lineWidth = 4.5;
  ctx.beginPath();
  ctx.moveTo(182, 86);
  ctx.bezierCurveTo(215, 46, 245, 128, 272, 68);
  ctx.bezierCurveTo(286, 48, 305, 118, 338, 82);
  ctx.stroke();

  // Expressive underline flourish inside deepest shadow zone
  ctx.lineWidth = 3.2;
  ctx.beginPath();
  ctx.moveTo(72, 134);
  ctx.quadraticCurveTo(205, 114, 344, 126);
  ctx.stroke();
  ctx.restore();

  runSignatureExtraction();
}

function runSignatureExtraction() {
  const rawCtx = rawSigCanvas.getContext("2d");
  const cleanCtx = cleanSigCanvas.getContext("2d");
  const w = rawSigCanvas.width;
  const h = rawSigCanvas.height;
  const src = rawCtx.getImageData(0, 0, w, h);

  const inkColor = document.getElementById("inkColorSelect").value;
  const shadowThreshold = Number(document.getElementById("shadowThresholdRange").value || 20);
  document.getElementById("thresholdVal").textContent = String(shadowThreshold);

  const res = extractTransparentSignature(src.data, w, h, {
    inkColor,
    shadowThreshold,
    inkSolidThreshold: shadowThreshold + 26,
  });

  const outImg = new ImageData(res.rgba, w, h);
  cleanCtx.clearRect(0, 0, w, h);
  cleanCtx.putImageData(outImg, 0, 0);

  document.getElementById("sigStatsText").textContent =
    `✅ 局部自适应去灰底完成：背景纯透明占比 ${(res.transparencyRatio * 100).toFixed(1)}%（Alpha=0），有效笔迹像素 ${res.inkPixelCount} 个`;

  renderContractStage();
}

document.getElementById("sigPhotoInput").addEventListener("change", (e) => {
  const file = e.target.files?.[0];
  if (!file) return;
  const img = new Image();
  img.onload = () => {
    const ctx = rawSigCanvas.getContext("2d");
    ctx.fillStyle = "#ffffff";
    ctx.fillRect(0, 0, rawSigCanvas.width, rawSigCanvas.height);
    const scale = Math.min(rawSigCanvas.width / img.width, rawSigCanvas.height / img.height);
    const dw = img.width * scale;
    const dh = img.height * scale;
    ctx.drawImage(img, (rawSigCanvas.width - dw) / 2, (rawSigCanvas.height - dh) / 2, dw, dh);
    runSignatureExtraction();
    URL.revokeObjectURL(img.src);
  };
  img.src = URL.createObjectURL(file);
});

document.getElementById("loadShadowDemoBtn").addEventListener("click", generateShadowedPaperSample);
document.getElementById("inkColorSelect").addEventListener("change", () => {
  runSignatureExtraction();
  redrawPadStrokes();
});
document.getElementById("shadowThresholdRange").addEventListener("input", runSignatureExtraction);

// ---- 2. Pressure-Sensitive Trackpad / Apple Pencil Signature Pad ----

let padStrokes = [];
let currentStroke = null;

function getPadInkHex() {
  const mode = document.getElementById("inkColorSelect").value;
  if (mode === "blue") return "#0f3d91";
  if (mode === "red") return "#c81e1e";
  return "#111827";
}

function redrawPadStrokes() {
  const ctx = padCanvas.getContext("2d");
  ctx.clearRect(0, 0, padCanvas.width, padCanvas.height);
  ctx.strokeStyle = getPadInkHex();
  ctx.lineCap = "round";
  ctx.lineJoin = "round";

  for (const pts of padStrokes) {
    const segs = smoothSignatureStrokes(pts, { minWidth: 1.8, maxWidth: 5.8 });
    for (const seg of segs) {
      ctx.lineWidth = seg.width;
      ctx.beginPath();
      ctx.moveTo(seg.x0, seg.y0);
      ctx.quadraticCurveTo(seg.cx, seg.cy, seg.x1, seg.y1);
      ctx.stroke();
    }
  }
}

function getCanvasCoords(canvas, evt) {
  const rect = canvas.getBoundingClientRect();
  return {
    x: ((evt.clientX - rect.left) * canvas.width) / rect.width,
    y: ((evt.clientY - rect.top) * canvas.height) / rect.height,
    pressure: evt.pressure || 0.5,
    time: performance.now(),
  };
}

padCanvas.addEventListener("pointerdown", (e) => {
  padCanvas.setPointerCapture(e.pointerId);
  currentStroke = [getCanvasCoords(padCanvas, e)];
  padStrokes.push(currentStroke);
  redrawPadStrokes();
});
padCanvas.addEventListener("pointermove", (e) => {
  if (!currentStroke) return;
  currentStroke.push(getCanvasCoords(padCanvas, e));
  redrawPadStrokes();
});
padCanvas.addEventListener("pointerup", () => {
  currentStroke = null;
  renderContractStage();
});

document.getElementById("clearPadBtn").addEventListener("click", () => {
  padStrokes = [];
  redrawPadStrokes();
  renderContractStage();
});

document.getElementById("tabPhotoBtn").addEventListener("click", () => {
  activeSigMode = "photo";
  document.getElementById("tabPhotoBtn").classList.add("active");
  document.getElementById("tabPadBtn").classList.remove("active");
  document.getElementById("photoModeBox").hidden = false;
  document.getElementById("padModeBox").hidden = true;
  renderContractStage();
});

document.getElementById("tabPadBtn").addEventListener("click", () => {
  activeSigMode = "pad";
  document.getElementById("tabPadBtn").classList.add("active");
  document.getElementById("tabPhotoBtn").classList.remove("active");
  document.getElementById("padModeBox").hidden = false;
  document.getElementById("photoModeBox").hidden = true;
  if (padStrokes.length === 0) {
    // Seed a graceful sample stroke so user sees immediate stroke smoothing
    padStrokes.push([
      { x: 110, y: 115, pressure: 0.4, time: 0 },
      { x: 165, y: 55, pressure: 0.75, time: 25 },
      { x: 210, y: 130, pressure: 0.6, time: 50 },
      { x: 280, y: 72, pressure: 0.8, time: 80 },
      { x: 370, y: 105, pressure: 0.35, time: 115 },
    ]);
    redrawPadStrokes();
  }
  renderContractStage();
});

function getActiveSignatureCanvas() {
  return activeSigMode === "pad" ? padCanvas : cleanSigCanvas;
}

document.getElementById("downloadSigPngBtn").addEventListener("click", () => {
  const srcCanvas = getActiveSignatureCanvas();
  const a = document.createElement("a");
  a.href = srcCanvas.toDataURL("image/png");
  a.download = "transparent-signature-alpha.png";
  a.click();
});

document.getElementById("sendSigToContractBtn").addEventListener("click", () => {
  overlays.sig.enabled = true;
  overlays.sig.pageIndex = activePageIdx;
  renderContractStage();
  document.getElementById("contractStudio").scrollIntoView({ behavior: "smooth" });
});

// ---- 3. Compliant Seal Designer ----

function refreshSealCanvas() {
  const shape = document.getElementById("sealShape").value;
  const mainText = document.getElementById("sealMainText").value.trim() || "星辰数字工作室内部测试";
  const subText = document.getElementById("sealSubText").value.trim();
  const codeText = document.getElementById("sealCodeText").value.trim();
  const noisePct = Number(document.getElementById("sealNoiseRange").value || 24);
  const angleDeg = Number(document.getElementById("sealAngleRange").value || -6);

  document.getElementById("noiseVal").textContent = `${noisePct}%`;
  document.getElementById("angleVal").textContent = `${angleDeg}°`;

  const hiCtx = hiSealCanvas.getContext("2d");
  renderSealToContext(hiCtx, {
    size: 360,
    shape,
    mainText,
    subText,
    codeText,
    noiseIntensity: noisePct / 100,
    rotationDeg: angleDeg,
  });

  const prevCtx = sealPreviewCanvas.getContext("2d");
  prevCtx.clearRect(0, 0, sealPreviewCanvas.width, sealPreviewCanvas.height);
  prevCtx.drawImage(hiSealCanvas, 0, 0, sealPreviewCanvas.width, sealPreviewCanvas.height);

  renderPerforationStrip();
  renderContractStage();
}

["sealShape", "sealMainText", "sealSubText", "sealCodeText", "sealNoiseRange", "sealAngleRange"].forEach((id) => {
  document.getElementById(id).addEventListener("input", refreshSealCanvas);
});

document.getElementById("applySealOnPageBtn").addEventListener("click", () => {
  overlays.seal.enabled = true;
  overlays.seal.pageIndex = activePageIdx;
  renderContractStage();
  document.getElementById("contractStudio").scrollIntoView({ behavior: "smooth" });
});

document.getElementById("applyPerforationBtn").addEventListener("click", () => {
  document.getElementById("enablePerforationToggle").checked = true;
  renderPerforationStrip();
  renderContractStage();
  document.getElementById("contractStudio").scrollIntoView({ behavior: "smooth" });
});

// ---- 4. Sample 3-Page Contract & Perforation Stamp Slicer ----

function buildSampleContractPages() {
  const W = 760;
  const H = 1075;
  const pagesData = [
    {
      title: "技术顾问与软件定制服务协议（测试样张）",
      pageLabel: "第 1 页 / 共 3 页",
      paragraphs: [
        "甲方（委托方）：上海瀚海供应链管理有限公司",
        "乙方（服务方）：星辰数字工作室（内部流转测试主体）",
        "",
        "第一条 合作范围与交付标准",
        "1.1 乙方根据甲方业务需求提供本地离线数据处理工具模块及技术维护支持。",
        "1.2 全部交付软件包均在甲方本地终端运行，不包含任何第三方云端数据采集组件。",
        "",
        "第二条 知识产权与保密义务",
        "2.1 双方对在履行本协议过程中知悉的商业秘密、合同文本及签章负有严格保密义务。",
        "2.2 本样张用于演示多页合同右侧边缘『骑缝章 N 等分自动切分』像素级对齐效果。",
      ],
    },
    {
      title: "技术服务里程碑与验收规范",
      pageLabel: "第 2 页 / 共 3 页",
      paragraphs: [
        "第三条 验收流程与结算周期",
        "3.1 里程碑一：完成核心算法与单元测试验收（100% 通过），甲方向乙方确认首期节点。",
        "3.2 里程碑二：完成离线 PWA 封装与打印版式联调，提供完整源代码及操作手册。",
        "",
        "第四条 违约责任与争议解决",
        "4.1 任何一方违反本协议约定导致对方遭受直接损失的，应依法承担相应赔偿责任。",
        "4.2 请留意本页右侧边缘：系统已自动贴合印章第 2/3 等分骑缝切片！",
      ],
    },
    {
      title: "签署与生效页（可拖拽移动下方签字与印章）",
      pageLabel: "第 3 页 / 共 3 页",
      paragraphs: [
        "第五条 附则与协议生效",
        "5.1 本协议一式贰份，甲乙双方各执壹份，自双方授权代表签字并加盖公章及骑缝章之日起生效。",
        "5.2 未尽事宜由双方另行签订书面补充协议，补充协议与本协议具有同等效力。",
        "",
        "",
        "甲方（盖章）：______________________          乙方（签章）：（已贴入真透明签字与印章）",
        "",
        "授权代表签字：______________________          授权代表签字：",
        "",
        "签署日期：2026 年 11 月 17 日                 签署日期：2026 年 11 月 17 日",
      ],
    },
  ];

  contractPages = pagesData.map((p) => {
    const c = document.createElement("canvas");
    c.width = W;
    c.height = H;
    const ctx = c.getContext("2d");
    ctx.fillStyle = "#ffffff";
    ctx.fillRect(0, 0, W, H);

    // Header border
    ctx.strokeStyle = "#d6d3d1";
    ctx.lineWidth = 1.5;
    ctx.beginPath();
    ctx.moveTo(64, 82);
    ctx.lineTo(W - 64, 82);
    ctx.stroke();

    ctx.fillStyle = "#78716c";
    ctx.font = "13px -apple-system, PingFang SC, sans-serif";
    ctx.fillText("SEAL-PDF OFFLINE CONTRACT WORKSPACE", 64, 66);
    ctx.fillText(p.pageLabel, W - 165, 66);

    ctx.fillStyle = "#1c1917";
    ctx.font = "bold 23px 'Songti SC', 'PingFang SC', serif";
    ctx.fillText(p.title, 64, 142);

    ctx.font = "16px 'Songti SC', 'PingFang SC', serif";
    let y = 205;
    for (const line of p.paragraphs) {
      if (!line) {
        y += 22;
        continue;
      }
      ctx.fillText(line, 64, y);
      y += 42;
    }

    // Subtle right-edge perforation guide ticks
    ctx.fillStyle = "#f5f5f4";
    ctx.fillRect(W - 6, 0, 6, H);
    return c;
  });

  activePageIdx = Math.min(activePageIdx, contractPages.length - 1);
  overlays.sig.pageIndex = contractPages.length - 1;
  overlays.seal.pageIndex = contractPages.length - 1;
  rebuildPageTabs();
  renderPerforationStrip();
  renderContractStage();
}

function rebuildPageTabs() {
  const wrap = document.getElementById("contractPageTabs");
  wrap.innerHTML = "";
  contractPages.forEach((_, idx) => {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = idx === activePageIdx ? "btn-secondary btn-sm active" : "btn-secondary btn-sm";
    btn.textContent = `第 ${idx + 1} 页 / 共 ${contractPages.length} 页`;
    btn.addEventListener("click", () => {
      activePageIdx = idx;
      rebuildPageTabs();
      renderContractStage();
    });
    wrap.appendChild(btn);
  });
}

function renderPerforationStrip() {
  const strip = document.getElementById("sliceStripPreview");
  strip.innerHTML = "";
  const enabled = document.getElementById("enablePerforationToggle").checked;
  if (!enabled || contractPages.length < 2) return;

  const slices = computePerforationSlices(hiSealCanvas.width, hiSealCanvas.height, contractPages.length, {
    pageWidth: 760,
    pageHeight: 1075,
    targetSealHeight: 156,
    verticalRatio: Number(document.getElementById("perfVerticalRange").value || 52) / 100,
  });

  slices.forEach((s) => {
    const item = document.createElement("div");
    item.className = "slice-item";
    const mini = document.createElement("canvas");
    mini.width = Math.max(16, Math.round(s.srcWidth * 0.24));
    mini.height = Math.round(s.srcHeight * 0.24);
    mini.getContext("2d").drawImage(
      hiSealCanvas,
      s.srcX,
      0,
      s.srcWidth,
      s.srcHeight,
      0,
      0,
      mini.width,
      mini.height
    );
    const label = document.createElement("span");
    label.innerHTML = `<strong>第 ${s.pageNumber}/${s.totalPages} 页右缘骑缝</strong><br>切片宽 ${s.srcWidth}px`;
    item.appendChild(mini);
    item.appendChild(label);
    strip.appendChild(item);
  });
}

function composePageToCanvas(pageIndex, outCanvas, includePreviewWatermark) {
  const basePage = contractPages[pageIndex];
  outCanvas.width = basePage.width;
  outCanvas.height = basePage.height;
  const ctx = outCanvas.getContext("2d");
  ctx.drawImage(basePage, 0, 0);

  // 1. Draw Main Seal if placed on this page
  if (overlays.seal.enabled && overlays.seal.pageIndex === pageIndex) {
    ctx.drawImage(
      hiSealCanvas,
      overlays.seal.x,
      overlays.seal.y,
      overlays.seal.width,
      overlays.seal.height
    );
  }

  // 2. Draw Transparent Signature if placed on this page
  if (overlays.sig.enabled && overlays.sig.pageIndex === pageIndex) {
    ctx.drawImage(
      getActiveSignatureCanvas(),
      overlays.sig.x,
      overlays.sig.y,
      overlays.sig.width,
      overlays.sig.height
    );
  }

  // 3. Draw Right-Edge Perforation Slice if enabled and pages >= 2
  if (document.getElementById("enablePerforationToggle").checked && contractPages.length >= 2) {
    const slices = computePerforationSlices(hiSealCanvas.width, hiSealCanvas.height, contractPages.length, {
      pageWidth: basePage.width,
      pageHeight: basePage.height,
      targetSealHeight: 156,
      verticalRatio: Number(document.getElementById("perfVerticalRange").value || 52) / 100,
    });
    const s = slices[pageIndex];
    if (s) {
      ctx.drawImage(
        hiSealCanvas,
        s.srcX,
        s.srcY,
        s.srcWidth,
        s.srcHeight,
        s.destX,
        s.destY,
        s.destWidth,
        s.destHeight
      );
    }
  }

  if (includePreviewWatermark) {
    ctx.save();
    ctx.fillStyle = "rgba(185, 28, 28, 0.14)";
    ctx.font = "bold 22px -apple-system, PingFang SC, sans-serif";
    ctx.translate(basePage.width - 110, basePage.height / 2);
    ctx.rotate(-Math.PI / 2);
    ctx.textAlign = "center";
    ctx.fillText("预览模式 · 解锁 Pro (¥15) 导出无水印高清 PDF", 0, 0);
    ctx.restore();
  }
}

function renderContractStage() {
  if (!contractPages.length) return;
  composePageToCanvas(activePageIdx, contractStageCanvas, !isPro && document.getElementById("enablePerforationToggle").checked);
}

// Drag & Drop Signature / Main Seal on contractStageCanvas
let dragTarget = null;
let dragOffset = { dx: 0, dy: 0 };

contractStageCanvas.addEventListener("pointerdown", (e) => {
  const pt = getCanvasCoords(contractStageCanvas, e);
  // Check sig hit first, then seal hit
  for (const key of ["sig", "seal"]) {
    const item = overlays[key];
    if (
      item.enabled &&
      item.pageIndex === activePageIdx &&
      pt.x >= item.x &&
      pt.x <= item.x + item.width &&
      pt.y >= item.y &&
      pt.y <= item.y + item.height
    ) {
      dragTarget = item;
      dragOffset = { dx: pt.x - item.x, dy: pt.y - item.y };
      contractStageCanvas.setPointerCapture(e.pointerId);
      break;
    }
  }
});

contractStageCanvas.addEventListener("pointermove", (e) => {
  if (!dragTarget) return;
  const pt = getCanvasCoords(contractStageCanvas, e);
  dragTarget.x = Math.max(0, Math.min(contractStageCanvas.width - dragTarget.width, pt.x - dragOffset.dx));
  dragTarget.y = Math.max(0, Math.min(contractStageCanvas.height - dragTarget.height, pt.y - dragOffset.dy));
  renderContractStage();
});

contractStageCanvas.addEventListener("pointerup", () => {
  dragTarget = null;
});

document.getElementById("enablePerforationToggle").addEventListener("change", () => {
  renderPerforationStrip();
  renderContractStage();
});
document.getElementById("perfVerticalRange").addEventListener("input", () => {
  renderPerforationStrip();
  renderContractStage();
});

document.getElementById("contractFilesInput").addEventListener("change", async (e) => {
  const files = Array.from(e.target.files || []);
  if (!files.length) return;
  const loaded = [];
  for (const file of files) {
    const bitmapCanvas = await new Promise((resolve) => {
      const img = new Image();
      img.onload = () => {
        const c = document.createElement("canvas");
        c.width = 760;
        c.height = 1075;
        const ctx = c.getContext("2d");
        ctx.fillStyle = "#ffffff";
        ctx.fillRect(0, 0, c.width, c.height);
        const scale = Math.min(c.width / img.width, c.height / img.height);
        const dw = img.width * scale;
        const dh = img.height * scale;
        ctx.drawImage(img, (c.width - dw) / 2, (c.height - dh) / 2, dw, dh);
        URL.revokeObjectURL(img.src);
        resolve(c);
      };
      img.src = URL.createObjectURL(file);
    });
    loaded.push(bitmapCanvas);
  }
  contractPages = loaded;
  activePageIdx = contractPages.length - 1;
  overlays.sig.pageIndex = activePageIdx;
  overlays.seal.pageIndex = activePageIdx;
  rebuildPageTabs();
  renderPerforationStrip();
  renderContractStage();
});

document.getElementById("resetSampleContractBtn").addEventListener("click", buildSampleContractPages);

// ---- 5. Free & Pro Exports ----

document.getElementById("exportSinglePreviewBtn").addEventListener("click", () => {
  const a = document.createElement("a");
  a.href = contractStageCanvas.toDataURL("image/png");
  a.download = `contract-page-${activePageIdx + 1}-preview.png`;
  a.click();
});

function dataUrlToUint8Array(dataUrl) {
  const b64 = dataUrl.split(",")[1];
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

document.getElementById("exportProPdfBtn").addEventListener("click", () => {
  if (!isPro) {
    document.getElementById("proUnlock").scrollIntoView({ behavior: "smooth" });
    document.getElementById("opcTokenInput").focus();
    document.getElementById("activateMsg").style.color = "#b91c1c";
    document.getElementById("activateMsg").textContent =
      "💡 请先输入 OPC1. Pro 激活码（¥15 永久买断）以解锁无水印多页骑缝章 PDF 一键离线导出。";
    return;
  }

  const tempCanvas = document.createElement("canvas");
  const pagesPayload = contractPages.map((_, idx) => {
    composePageToCanvas(idx, tempCanvas, false);
    const jpegDataUrl = tempCanvas.toDataURL("image/jpeg", 0.94);
    return {
      jpegBytes: dataUrlToUint8Array(jpegDataUrl),
      widthPx: tempCanvas.width,
      heightPx: tempCanvas.height,
      pageWidthPt: 595.28,
      pageHeightPt: 841.89,
    };
  });

  const pdfBytes = buildMultiPageJpegPdf(pagesPayload);
  const blob = new Blob([pdfBytes], { type: "application/pdf" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `sealed-contract-${contractPages.length}pages.pdf`;
  a.click();
  URL.revokeObjectURL(a.href);
});

document.getElementById("exportProPngZipBtn").addEventListener("click", () => {
  if (!isPro) {
    document.getElementById("proUnlock").scrollIntoView({ behavior: "smooth" });
    document.getElementById("opcTokenInput").focus();
    return;
  }
  const tempCanvas = document.createElement("canvas");
  contractPages.forEach((_, idx) => {
    composePageToCanvas(idx, tempCanvas, false);
    const a = document.createElement("a");
    a.href = tempCanvas.toDataURL("image/png");
    a.download = `sealed-contract-page-${idx + 1}.png`;
    a.click();
  });
});

// ---- 6. License Activation & Offline PWA Service Worker ----

function syncProState(unlocked, payload = null) {
  isPro = unlocked;
  const dot = document.getElementById("licenseDot");
  const title = document.getElementById("licenseTitle");
  const pdfBtn = document.getElementById("exportProPdfBtn");
  const pngBtn = document.getElementById("exportProPngZipBtn");

  if (unlocked) {
    dot.classList.add("ok");
    title.textContent = `已解锁 Pro 永久买断版（授权：${payload?.e || PRODUCT_SLUG}）`;
    pdfBtn.textContent = "⬇️ 导出无水印全套骑缝合同多页 PDF";
    pngBtn.textContent = "⬇️ 批量导出各页高清无损 PNG";
  } else {
    dot.classList.remove("ok");
    title.textContent = "当前版本：免费版（透明抠图免费 · 骑缝无水印 PDF 需激活）";
    pdfBtn.textContent = "🔒 导出无水印全套骑缝合同多页 PDF (Pro ¥15)";
    pngBtn.textContent = "🔒 批量导出各页高清无损 PNG (Pro)";
  }
  renderContractStage();
}

document.getElementById("activateBtn").addEventListener("click", async () => {
  const token = document.getElementById("opcTokenInput").value.trim();
  const msg = document.getElementById("activateMsg");
  const res = await verifyLicenseToken(token, { expectedProduct: PRODUCT_SLUG });
  if (res.valid) {
    try { localStorage.setItem(STORAGE_KEY, token); } catch {}
    msg.style.color = "#15803d";
    msg.textContent = "✅ Ed25519 公钥验签通过！无水印骑缝章与多页合同 PDF 导出已永久解锁。";
    syncProState(true, res.payload);
  } else {
    msg.style.color = "#b91c1c";
    msg.textContent = `❌ 激活失败（${res.reason}），请检查完整 OPC1. 激活码。`;
    syncProState(false);
  }
});

(async () => {
  refreshSealCanvas();
  buildSampleContractPages();
  generateShadowedPaperSample();

  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved) {
      document.getElementById("opcTokenInput").value = saved;
      const res = await verifyLicenseToken(saved, { expectedProduct: PRODUCT_SLUG });
      if (res.valid) syncProState(true, res.payload);
    }
  } catch {}

  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("./sw.js").catch(() => {});
  }
})();
