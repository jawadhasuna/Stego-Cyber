// ============================================================
// CONSTANTS
// ============================================================
const DELIMITER = "1111111111111110"; // 16-bit end-of-data marker

// ============================================================
// CRYPTO — PBKDF2 key derivation + AES-GCM (native Web Crypto API)
// ============================================================
async function deriveKey(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 150000, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptMessage(message, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv }, key, new TextEncoder().encode(message)
  );
  // Combine salt + iv + ciphertext(+tag) into one payload, then base64 it
  const combined = new Uint8Array(salt.length + iv.length + ciphertext.byteLength);
  combined.set(salt, 0);
  combined.set(iv, salt.length);
  combined.set(new Uint8Array(ciphertext), salt.length + iv.length);
  return btoa(String.fromCharCode(...combined));
}

async function decryptMessage(base64Payload, password) {
  const combined = Uint8Array.from(atob(base64Payload), c => c.charCodeAt(0));
  const salt = combined.slice(0, 16);
  const iv = combined.slice(16, 28);
  const ciphertext = combined.slice(28);
  const key = await deriveKey(password, salt);
  // AES-GCM verifies integrity automatically — wrong password throws here
  const plainBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  return new TextDecoder().decode(plainBuf);
}

// ============================================================
// STEGANOGRAPHY — LSB embedding/extraction on canvas pixel data
// ============================================================
function stringToBinary(str) {
  return str.split("").map(c => c.charCodeAt(0).toString(2).padStart(8, "0")).join("");
}

function binaryToString(bin) {
  let out = "";
  for (let i = 0; i < bin.length; i += 8) {
    out += String.fromCharCode(parseInt(bin.substr(i, 8), 2));
  }
  return out;
}

// Estimate how many bits the final base64 payload will take, before encrypting
function estimateRequiredBits(plaintextLen) {
  const rawBytes = plaintextLen + 16 /* GCM tag */ + 16 /* salt */ + 12 /* iv */;
  const base64Len = Math.ceil(rawBytes / 3) * 4;
  return base64Len * 8 + DELIMITER.length;
}

function embedDataInImage(imageData, dataStr) {
  const binary = stringToBinary(dataStr) + DELIMITER;
  const pixels = imageData.data; // RGBA, repeating
  const maxBits = (pixels.length / 4) * 3; // R,G,B usable per pixel; alpha untouched
  if (binary.length > maxBits) {
    throw new Error("Image too small for this message. Choose a larger image or shorten the message.");
  }
  let bitIndex = 0;
  for (let i = 0; i < pixels.length && bitIndex < binary.length; i += 4) {
    for (let ch = 0; ch < 3 && bitIndex < binary.length; ch++) {
      pixels[i + ch] = (pixels[i + ch] & ~1) | parseInt(binary[bitIndex]);
      bitIndex++;
    }
  }
  return imageData;
}

function extractDataFromImage(imageData) {
  const pixels = imageData.data;
  let bits = "";
  for (let i = 0; i < pixels.length; i += 4) {
    for (let ch = 0; ch < 3; ch++) {
      bits += (pixels[i + ch] & 1).toString();
      if (bits.endsWith(DELIMITER)) {
        const dataBits = bits.slice(0, -DELIMITER.length);
        if (dataBits.length % 8 !== 0) {
          throw new Error("Corrupted data: incomplete byte sequence.");
        }
        return binaryToString(dataBits);
      }
    }
  }
  throw new Error("No hidden message found in this image.");
}

// ============================================================
// UI WIRING
// ============================================================
const canvas = document.getElementById("work-canvas");
const ctx = canvas.getContext("2d");

let encodeImageData = null; // holds loaded cover image's pixel data
let decodeImageData = null; // holds loaded encoded image's pixel data

// --- Tab switching ---
document.querySelectorAll(".tab-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById(btn.dataset.tab + "-pane").classList.add("active");
  });
});

// --- Load an image file into a canvas and return its ImageData ---
function loadImageToCanvas(file) {
  return new Promise((resolve, reject) => {
    const img = new Image();
    img.onload = () => {
      canvas.width = img.width;
      canvas.height = img.height;
      ctx.drawImage(img, 0, 0);
      resolve({ imageData: ctx.getImageData(0, 0, canvas.width, canvas.height), dataUrl: img.src });
    };
    img.onerror = reject;
    img.src = URL.createObjectURL(file);
  });
}

// --- Encode tab wiring ---
const encodeImageInput = document.getElementById("encode-image-input");
const encodePreview = document.getElementById("encode-preview");
const messageInput = document.getElementById("message-input");
const capacityFill = document.getElementById("capacity-fill");
const capacityText = document.getElementById("capacity-text");
const hideBtn = document.getElementById("hide-btn");
const encodeStatus = document.getElementById("encode-status");
const encodeResult = document.getElementById("encode-result");
const resultPreview = document.getElementById("result-preview");
const downloadLink = document.getElementById("download-link");

let maxCapacityBits = 0;

encodeImageInput.addEventListener("change", async () => {
  const file = encodeImageInput.files[0];
  if (!file) return;
  const { imageData, dataUrl } = await loadImageToCanvas(file);
  encodeImageData = imageData;
  maxCapacityBits = (imageData.data.length / 4) * 3;
  encodePreview.innerHTML = `<img src="${dataUrl}" />`;
  updateCapacityMeter();
});

messageInput.addEventListener("input", updateCapacityMeter);

function updateCapacityMeter() {
  if (!maxCapacityBits) {
    capacityText.textContent = "Load an image first";
    capacityFill.style.width = "0%";
    return;
  }
  const requiredBits = estimateRequiredBits(messageInput.value.length);
  const pct = Math.min(100, (requiredBits / maxCapacityBits) * 100);
  capacityFill.style.width = pct + "%";
  const over = requiredBits > maxCapacityBits;
  capacityFill.classList.toggle("over", over);
  capacityText.textContent = `${requiredBits} / ${maxCapacityBits} bits used` + (over ? " — too large for this image" : "");
}

hideBtn.addEventListener("click", async () => {
  encodeStatus.textContent = "";
  encodeStatus.className = "status-line";
  encodeResult.hidden = true;

  const message = messageInput.value;
  const password = document.getElementById("encode-password-input").value;

  if (!encodeImageData) return setStatus(encodeStatus, "Please select a cover image first.", "error");
  if (!message) return setStatus(encodeStatus, "Please enter a message to hide.", "error");
  if (!password) return setStatus(encodeStatus, "Please enter a password.", "error");

  hideBtn.disabled = true;
  setStatus(encodeStatus, "Encrypting and embedding...", "");

  try {
    const encryptedPayload = await encryptMessage(message, password);
    // Work on a copy of the pixel data so the original stays untouched for re-use
    const dataCopy = new ImageData(
      new Uint8ClampedArray(encodeImageData.data), encodeImageData.width, encodeImageData.height
    );
    const stego = embedDataInImage(dataCopy, encryptedPayload);

    canvas.width = stego.width;
    canvas.height = stego.height;
    ctx.putImageData(stego, 0, 0);

    canvas.toBlob(blob => {
      const url = URL.createObjectURL(blob);
      resultPreview.src = url;
      downloadLink.href = url;
      encodeResult.hidden = false;
      setStatus(encodeStatus, "Message hidden successfully.", "success");
      hideBtn.disabled = false;
    }, "image/png");
  } catch (err) {
    setStatus(encodeStatus, err.message, "error");
    hideBtn.disabled = false;
  }
});

// --- Decode tab wiring ---
const decodeImageInput = document.getElementById("decode-image-input");
const decodePreview = document.getElementById("decode-preview");
const revealBtn = document.getElementById("reveal-btn");
const decodeStatus = document.getElementById("decode-status");
const decodedOutput = document.getElementById("decoded-output");

decodeImageInput.addEventListener("change", async () => {
  const file = decodeImageInput.files[0];
  if (!file) return;
  const { imageData, dataUrl } = await loadImageToCanvas(file);
  decodeImageData = imageData;
  decodePreview.innerHTML = `<img src="${dataUrl}" />`;
});

revealBtn.addEventListener("click", async () => {
  decodeStatus.textContent = "";
  decodeStatus.className = "status-line";
  decodedOutput.value = "";

  const password = document.getElementById("decode-password-input").value;
  if (!decodeImageData) return setStatus(decodeStatus, "Please select an encoded image first.", "error");
  if (!password) return setStatus(decodeStatus, "Please enter the password.", "error");

  revealBtn.disabled = true;
  setStatus(decodeStatus, "Extracting and decrypting...", "");

  try {
    const payload = extractDataFromImage(decodeImageData);
    const message = await decryptMessage(payload, password);
    decodedOutput.value = message;
    setStatus(decodeStatus, "Message revealed.", "success");
  } catch (err) {
    setStatus(decodeStatus, "Decryption failed. Wrong password or corrupted image.", "error");
  } finally {
    revealBtn.disabled = false;
  }
});

function setStatus(el, text, cls) {
  el.textContent = text;
  el.className = "status-line" + (cls ? " " + cls : "");
}