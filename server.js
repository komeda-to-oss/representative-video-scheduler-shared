const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { Readable } = require("stream");

const PORT = Number(process.env.PORT || 8782);
const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, "public");
const DATA_DIR = path.join(ROOT, "data");
const UPLOAD_DIR = path.join(DATA_DIR, "uploads");
const STATE_FILE = path.join(DATA_DIR, "demo-state.json");
const SEED_STATE_FILE = path.join(ROOT, "..", "render-deploy-work", "share-state.json");
const BUNDLED_MEDIA_DIR = path.join(PUBLIC_DIR, "seed-media");
const SEED_MEDIA_DIR = fs.existsSync(BUNDLED_MEDIA_DIR)
  ? BUNDLED_MEDIA_DIR
  : path.join(ROOT, "..", "render-deploy-work", "media");
const PASSCODE = process.env.APP_PASSCODE || "SNova0101";
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");
const MAX_UPLOAD_BYTES = 100 * 1024 * 1024;
const CLOUDINARY = parseCloudinaryUrl(process.env.CLOUDINARY_URL || "");
const CLOUDINARY_STATE_ID = "representative-video-scheduler/state.json";

fs.mkdirSync(UPLOAD_DIR, { recursive: true });

function blankRows(month, count = 6) {
  const [year, monthNumber] = month.split("-").map(Number);
  return Array.from({ length: count }, (_, index) => {
    const date = new Date(year, monthNumber - 1, 8 + index * 7);
    return {
      postDate: date.toISOString().slice(0, 10),
      title: `動画${index + 1}`,
      memo: "",
      ready: false,
      thumbData: "",
      thumbName: "",
      videoUrl: "",
      videoFileName: ""
    };
  });
}

function loadInitialState() {
  if (fs.existsSync(STATE_FILE)) {
    return JSON.parse(fs.readFileSync(STATE_FILE, "utf8"));
  }

  const seed = JSON.parse(fs.readFileSync(SEED_STATE_FILE, "utf8"));
  seed.rows = (seed.rows || []).map((row, index) => ({
    ...row,
    videoUrl: `/seed-media/video-${index + 1}.mp4`,
    videoData: "",
    videoPreviewUrl: ""
  }));

  return {
    revision: 1,
    updatedAt: new Date().toISOString(),
    active: seed,
    archives: {}
  };
}

let sharedState = loadInitialState();
let cloudStateUrl = CLOUDINARY
  ? `https://res.cloudinary.com/${CLOUDINARY.cloudName}/raw/upload/${CLOUDINARY_STATE_ID}`
  : "";

function parseCloudinaryUrl(value) {
  if (!value) return null;
  try {
    const parsed = new URL(value);
    if (parsed.protocol !== "cloudinary:") return null;
    return {
      cloudName: parsed.hostname,
      apiKey: decodeURIComponent(parsed.username),
      apiSecret: decodeURIComponent(parsed.password)
    };
  } catch {
    return null;
  }
}

function cloudinarySignature(params) {
  const source = Object.keys(params)
    .sort()
    .map((key) => `${key}=${params[key]}`)
    .join("&");
  return crypto.createHash("sha1").update(source + CLOUDINARY.apiSecret).digest("hex");
}

async function uploadCloudinary(buffer, options = {}) {
  if (!CLOUDINARY) throw new Error("cloud_not_configured");
  const resourceType = options.resourceType || "auto";
  const params = {
    overwrite: "true",
    timestamp: String(Math.floor(Date.now() / 1000))
  };
  if (options.folder) params.folder = options.folder;
  if (options.publicId) params.public_id = options.publicId;

  const form = new FormData();
  form.append("file", new Blob([buffer]), options.filename || "upload.bin");
  Object.entries(params).forEach(([key, value]) => form.append(key, value));
  form.append("api_key", CLOUDINARY.apiKey);
  form.append("signature", cloudinarySignature(params));

  const response = await fetch(
    `https://api.cloudinary.com/v1_1/${CLOUDINARY.cloudName}/${resourceType}/upload`,
    { method: "POST", body: form }
  );
  const result = await response.json();
  if (!response.ok) throw new Error(result.error?.message || "cloud_upload_failed");
  return result;
}

async function hydrateCloudState() {
  if (!CLOUDINARY) return;
  try {
    const response = await fetch(`${cloudStateUrl}?v=${Date.now()}`, { cache: "no-store" });
    if (response.ok) {
      sharedState = await response.json();
      return;
    }
  } catch {
    // The first production boot creates the shared state below.
  }
  await persistStateFile(sharedState);
}

async function persistStateFile(value) {
  if (CLOUDINARY) {
    const uploaded = await uploadCloudinary(
      Buffer.from(JSON.stringify(value, null, 2), "utf8"),
      {
        resourceType: "raw",
        publicId: CLOUDINARY_STATE_ID,
        filename: "state.json"
      }
    );
    cloudStateUrl = uploaded.secure_url || cloudStateUrl;
    return;
  }

  const temp = `${STATE_FILE}.tmp`;
  fs.writeFileSync(temp, JSON.stringify(value, null, 2), "utf8");
  fs.renameSync(temp, STATE_FILE);
}

async function saveState(nextState) {
  sharedState = {
    ...nextState,
    revision: Number(sharedState.revision || 0) + 1,
    updatedAt: new Date().toISOString()
  };
  await persistStateFile(sharedState);
  return sharedState;
}

function parseCookies(req) {
  return Object.fromEntries(
    String(req.headers.cookie || "")
      .split(";")
      .map((part) => part.trim().split("="))
      .filter((pair) => pair.length === 2)
      .map(([key, value]) => [key, decodeURIComponent(value)])
  );
}

function sessionToken() {
  return crypto.createHmac("sha256", SESSION_SECRET).update("scheduler-access").digest("hex");
}

function protectedMediaUrl(sourceUrl) {
  const encoded = Buffer.from(sourceUrl, "utf8").toString("base64url");
  const signature = crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(encoded)
    .digest("base64url")
    .slice(0, 24);
  return `/api/media/${encoded}.${signature}`;
}

function decodeProtectedMedia(value) {
  const separator = value.lastIndexOf(".");
  if (separator < 1) return null;
  const encoded = value.slice(0, separator);
  const actual = value.slice(separator + 1);
  const expected = crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(encoded)
    .digest("base64url")
    .slice(0, 24);
  if (actual.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(actual), Buffer.from(expected))) {
    return null;
  }
  const decoded = Buffer.from(encoded, "base64url").toString("utf8");
  return decoded.startsWith("https://res.cloudinary.com/") ? decoded : null;
}

function isAuthorized(req) {
  const cookies = parseCookies(req);
  return cookies.scheduler_session === sessionToken();
}

function sendJson(res, status, value, headers = {}) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    ...headers
  });
  res.end(JSON.stringify(value));
}

function readBody(req, limit = 2 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > limit) {
        reject(new Error("too_large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function safeSegment(value, fallback) {
  const cleaned = String(value || "")
    .normalize("NFKC")
    .replace(/[^a-zA-Z0-9._-]/g, "_")
    .slice(0, 80);
  return cleaned || fallback;
}

function contentType(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  return {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".webp": "image/webp",
    ".mp4": "video/mp4",
    ".mov": "video/quicktime"
  }[ext] || "application/octet-stream";
}

function serveFile(res, filePath) {
  if (!fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) {
    res.writeHead(404);
    res.end("Not found");
    return;
  }
  res.writeHead(200, {
    "Content-Type": contentType(filePath),
    "Cache-Control": filePath.endsWith(".html") ? "no-store" : "public, max-age=3600"
  });
  fs.createReadStream(filePath).pipe(res);
}

async function handleApi(req, res, url) {
  if (req.method === "POST" && url.pathname === "/api/login") {
    try {
      const body = JSON.parse((await readBody(req)).toString("utf8"));
      if (body.passcode !== PASSCODE) {
        sendJson(res, 401, { ok: false, message: "パスワードが違います" });
        return;
      }
      sendJson(res, 200, { ok: true }, {
        "Set-Cookie": `scheduler_session=${sessionToken()}; HttpOnly; SameSite=Strict; Path=/; Max-Age=86400`
      });
    } catch {
      sendJson(res, 400, { ok: false });
    }
    return;
  }

  if (!isAuthorized(req)) {
    sendJson(res, 401, { ok: false, message: "ログインしてください" });
    return;
  }

  if (req.method === "GET" && url.pathname.startsWith("/api/media/")) {
    const sourceUrl = decodeProtectedMedia(url.pathname.slice("/api/media/".length));
    if (!sourceUrl) {
      sendJson(res, 403, { ok: false });
      return;
    }
    try {
      const headers = {};
      if (req.headers.range) headers.Range = req.headers.range;
      const upstream = await fetch(sourceUrl, { headers });
      const responseHeaders = {
        "Content-Type": upstream.headers.get("content-type") || "application/octet-stream",
        "Accept-Ranges": upstream.headers.get("accept-ranges") || "bytes",
        "Cache-Control": "private, max-age=3600"
      };
      if (upstream.headers.get("content-length")) {
        responseHeaders["Content-Length"] = upstream.headers.get("content-length");
      }
      if (upstream.headers.get("content-range")) {
        responseHeaders["Content-Range"] = upstream.headers.get("content-range");
      }
      res.writeHead(upstream.status, responseHeaders);
      if (upstream.body) Readable.fromWeb(upstream.body).pipe(res);
      else res.end();
    } catch {
      sendJson(res, 502, { ok: false, message: "動画を読み込めませんでした" });
    }
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/state") {
    sendJson(res, 200, sharedState);
    return;
  }

  if (req.method === "PUT" && url.pathname === "/api/state") {
    try {
      const body = JSON.parse((await readBody(req, 8 * 1024 * 1024)).toString("utf8"));
      if (!body.active || !Array.isArray(body.active.rows) || typeof body.archives !== "object") {
        sendJson(res, 400, { ok: false, message: "保存データが不正です" });
        return;
      }
      sendJson(res, 200, await saveState(body));
    } catch (error) {
      sendJson(res, error.message === "too_large" ? 413 : 400, { ok: false });
    }
    return;
  }

  if (req.method === "PUT" && url.pathname === "/api/upload") {
    try {
      const month = safeSegment(url.searchParams.get("month"), "month");
      const slot = safeSegment(url.searchParams.get("slot"), "0");
      const kind = url.searchParams.get("kind") === "thumb" ? "thumb" : "video";
      const original = safeSegment(req.headers["x-file-name"], kind);
      const ext = safeSegment(path.extname(original).toLowerCase(), kind === "thumb" ? ".jpg" : ".mp4");
      const monthDir = path.join(UPLOAD_DIR, month);
      fs.mkdirSync(monthDir, { recursive: true });
      const filename = `${kind}-${slot}-${Date.now()}${ext.startsWith(".") ? ext : `.${ext}`}`;
      const body = await readBody(req, MAX_UPLOAD_BYTES);

      if (CLOUDINARY) {
        const uploaded = await uploadCloudinary(body, {
          resourceType: "auto",
          folder: `representative-video-scheduler/${month}`,
          publicId: `${kind}-${slot}-${Date.now()}`,
          filename: original
        });
        sendJson(res, 200, {
          ok: true,
          url: protectedMediaUrl(uploaded.secure_url),
          name: original
        });
        return;
      }

      const target = path.join(monthDir, filename);
      fs.writeFileSync(target, body);
      sendJson(res, 200, {
        ok: true,
        url: `/uploads/${encodeURIComponent(month)}/${encodeURIComponent(filename)}`,
        name: original
      });
    } catch (error) {
      sendJson(res, error.message === "too_large" ? 413 : 400, {
        ok: false,
        message: error.message === "too_large" ? "100MB以下のファイルを選んでください" : "アップロードできませんでした"
      });
    }
    return;
  }

  sendJson(res, 404, { ok: false });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);

  if (url.pathname.startsWith("/api/")) {
    await handleApi(req, res, url);
    return;
  }

  if (url.pathname.startsWith("/seed-media/")) {
    if (!isAuthorized(req)) {
      sendJson(res, 401, { ok: false, message: "ログインしてください" });
      return;
    }
    serveFile(res, path.join(SEED_MEDIA_DIR, path.basename(url.pathname)));
    return;
  }

  if (url.pathname.startsWith("/uploads/")) {
    if (!isAuthorized(req)) {
      sendJson(res, 401, { ok: false, message: "ログインしてください" });
      return;
    }
    const relative = decodeURIComponent(url.pathname.slice("/uploads/".length));
    const target = path.resolve(UPLOAD_DIR, relative);
    if (!target.startsWith(path.resolve(UPLOAD_DIR))) {
      res.writeHead(403);
      res.end("Forbidden");
      return;
    }
    serveFile(res, target);
    return;
  }

  const requestPath = url.pathname === "/" ? "index.html" : url.pathname.slice(1);
  const target = path.resolve(PUBLIC_DIR, requestPath);
  if (!target.startsWith(path.resolve(PUBLIC_DIR))) {
    res.writeHead(403);
    res.end("Forbidden");
    return;
  }
  serveFile(res, target);
});

hydrateCloudState().catch((error) => {
  console.error("Cloud state initialization failed:", error.message);
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Shared scheduler demo: http://127.0.0.1:${PORT}`);
});
