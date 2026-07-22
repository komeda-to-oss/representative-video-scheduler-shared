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
const MUX = parseMuxConfig();
const R2 = parseR2Config();
const MUX_FREE_ASSET_LIMIT = 10;

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

function parseMuxConfig() {
  const tokenId = process.env.MUX_TOKEN_ID || "";
  const tokenSecret = process.env.MUX_TOKEN_SECRET || "";
  return tokenId && tokenSecret ? { tokenId, tokenSecret } : null;
}

function parseR2Config() {
  const accountId = process.env.R2_ACCOUNT_ID || process.env.CLOUDFLARE_ACCOUNT_ID || "";
  const bucket = process.env.R2_BUCKET || "";
  const accessKeyId = process.env.R2_ACCESS_KEY_ID || "";
  const secretAccessKey = process.env.R2_SECRET_ACCESS_KEY || "";
  return accountId && bucket && accessKeyId && secretAccessKey
    ? { accountId, bucket, accessKeyId, secretAccessKey }
    : null;
}

function awsEncode(value) {
  return encodeURIComponent(value).replace(/[!'()*]/g, (char) =>
    `%${char.charCodeAt(0).toString(16).toUpperCase()}`
  );
}

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function hmac(key, value, encoding) {
  return crypto.createHmac("sha256", key).update(value).digest(encoding);
}

function amzTimestamp(date = new Date()) {
  return date.toISOString().replace(/[:-]|\.\d{3}/g, "");
}

function r2ObjectPath(key) {
  return `/${awsEncode(R2.bucket)}/${String(key).split("/").map(awsEncode).join("/")}`;
}

function r2PresignedUrl(method, key, expiresIn = 3600) {
  if (!R2) throw new Error("r2_not_configured");
  const now = new Date();
  const amzDate = amzTimestamp(now);
  const dateStamp = amzDate.slice(0, 8);
  const host = `${R2.accountId}.r2.cloudflarestorage.com`;
  const credentialScope = `${dateStamp}/auto/s3/aws4_request`;
  const params = {
    "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
    "X-Amz-Content-Sha256": "UNSIGNED-PAYLOAD",
    "X-Amz-Credential": `${R2.accessKeyId}/${credentialScope}`,
    "X-Amz-Date": amzDate,
    "X-Amz-Expires": String(expiresIn),
    "X-Amz-SignedHeaders": "host"
  };
  const canonicalQuery = Object.keys(params)
    .sort()
    .map((name) => `${awsEncode(name)}=${awsEncode(params[name])}`)
    .join("&");
  const canonicalHeaders = `host:${host}\n`;
  const canonicalRequest = [
    method,
    r2ObjectPath(key),
    canonicalQuery,
    canonicalHeaders,
    "host",
    "UNSIGNED-PAYLOAD"
  ].join("\n");
  const stringToSign = [
    "AWS4-HMAC-SHA256",
    amzDate,
    credentialScope,
    sha256Hex(canonicalRequest)
  ].join("\n");
  const dateKey = hmac(`AWS4${R2.secretAccessKey}`, dateStamp);
  const regionKey = hmac(dateKey, "auto");
  const serviceKey = hmac(regionKey, "s3");
  const signingKey = hmac(serviceKey, "aws4_request");
  const signature = hmac(signingKey, stringToSign, "hex");
  return `https://${host}${r2ObjectPath(key)}?${canonicalQuery}&X-Amz-Signature=${signature}`;
}

function protectedR2MediaUrl(key, filename = "") {
  const encoded = Buffer.from(key, "utf8").toString("base64url");
  const suffix = filename ? `?name=${encodeURIComponent(filename)}` : "";
  return `/api/r2/media/${encoded}${suffix}`;
}

function decodeR2MediaKey(value) {
  try {
    const key = Buffer.from(value, "base64url").toString("utf8");
    if (!key || key.includes("..") || key.startsWith("/") || key.startsWith("\\")) return null;
    return key;
  } catch {
    return null;
  }
}

async function muxApi(pathname, options = {}) {
  if (!MUX) throw new Error("mux_not_configured");
  const headers = {
    "Authorization": `Basic ${Buffer.from(`${MUX.tokenId}:${MUX.tokenSecret}`).toString("base64")}`,
    "Content-Type": "application/json",
    ...(options.headers || {})
  };
  const response = await fetch(`https://api.mux.com/video/v1${pathname}`, {
    method: options.method || "GET",
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined
  });
  const text = await response.text();
  let result = {};
  try {
    result = text ? JSON.parse(text) : {};
  } catch {
    result = { message: text };
  }
  if (!response.ok) {
    const messages = result.error?.messages || result.error?.message || result.message;
    throw new Error(Array.isArray(messages) ? messages.join(", ") : messages || "mux_request_failed");
  }
  return result;
}

async function muxRequest(pathname, options = {}) {
  const result = await muxApi(pathname, options);
  return result.data || result;
}

function muxPlaybackId(asset) {
  return (asset?.playback_ids || []).find((item) => item.policy === "public")?.id
    || asset?.playback_ids?.[0]?.id
    || "";
}

async function createMuxAssetFromR2Key(key, metadata = {}) {
  const sourceUrl = r2PresignedUrl("GET", key, 7 * 24 * 60 * 60);
  const passthrough = JSON.stringify({
    source: "representative-video-scheduler",
    month: metadata.month || "",
    slot: metadata.slot || "",
    title: String(metadata.title || "").slice(0, 120)
  }).slice(0, 255);
  const asset = await muxRequest("/assets", {
    method: "POST",
    body: {
      inputs: [{ url: sourceUrl }],
      playback_policies: ["public"],
      video_quality: "basic",
      passthrough
    }
  });
  return {
    assetId: asset.id,
    playbackId: muxPlaybackId(asset),
    status: asset.status || "preparing"
  };
}

function muxDirectUploadAssetId(upload) {
  return upload?.asset_id || upload?.assetId || "";
}

async function createMuxDirectUpload(metadata = {}, origin = "*") {
  const slot = String(metadata.slot ?? "");
  const title = String(metadata.title || metadata.fileName || "Video").slice(0, 120);
  const passthrough = JSON.stringify({
    source: "representative-video-scheduler",
    flow: "mux-free-direct",
    month: metadata.month || "",
    slot,
    title
  }).slice(0, 255);
  const upload = await muxRequest("/uploads", {
    method: "POST",
    body: {
      cors_origin: origin || "*",
      new_asset_settings: {
        playback_policies: ["public"],
        video_quality: "basic",
        passthrough,
        meta: {
          title,
          external_id: `${metadata.month || "month"}-${slot || "slot"}`
        }
      }
    }
  });
  return {
    uploadId: upload.id,
    uploadUrl: upload.url,
    status: upload.status || "waiting"
  };
}

async function readMuxDirectUpload(uploadId) {
  const upload = await muxRequest(`/uploads/${encodeURIComponent(uploadId)}`);
  const assetId = muxDirectUploadAssetId(upload);
  let asset = null;
  if (assetId) {
    asset = await muxRequest(`/assets/${encodeURIComponent(assetId)}`).catch(() => null);
  }
  return {
    uploadId: upload.id || uploadId,
    uploadStatus: upload.status || "",
    assetId,
    status: asset?.status || upload.asset_status || "",
    playbackId: muxPlaybackId(asset),
    errored: Boolean(upload.error || asset?.errors),
    message: upload.error?.message || asset?.errors?.messages?.join?.(", ") || ""
  };
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
  if (req.method === "GET" && url.pathname === "/api/capabilities") {
    sendJson(res, 200, {
      ok: true,
      state: true,
      muxConfigured: Boolean(MUX),
      r2Configured: Boolean(R2),
      muxFreeAssetLimit: MUX_FREE_ASSET_LIMIT,
      maxUploadBytes: MAX_UPLOAD_BYTES,
      preferredVideoFlow: MUX ? "mux-direct" : CLOUDINARY ? "cloudinary" : "local"
    });
    return;
  }

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

  if (req.method === "POST" && url.pathname === "/api/mux/direct-upload") {
    if (!MUX) {
      sendJson(res, 503, { ok: false, message: "Mux is not configured" });
      return;
    }
    try {
      const body = JSON.parse((await readBody(req, 256 * 1024)).toString("utf8"));
      const origin = req.headers.origin || "*";
      sendJson(res, 200, {
        ok: true,
        ...(await createMuxDirectUpload(body, origin))
      });
    } catch (error) {
      sendJson(res, 502, { ok: false, message: error.message || "mux_direct_upload_failed" });
    }
    return;
  }

  if (req.method === "GET" && url.pathname.startsWith("/api/mux/uploads/")) {
    if (!MUX) {
      sendJson(res, 503, { ok: false, message: "Mux is not configured" });
      return;
    }
    try {
      const uploadId = safeSegment(url.pathname.slice("/api/mux/uploads/".length), "");
      sendJson(res, 200, {
        ok: true,
        ...(await readMuxDirectUpload(uploadId))
      });
    } catch (error) {
      sendJson(res, 502, { ok: false, message: error.message || "mux_upload_fetch_failed" });
    }
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/r2/upload-url") {
    if (!R2) {
      sendJson(res, 503, { ok: false, message: "Cloudflare R2 is not configured" });
      return;
    }
    try {
      const body = JSON.parse((await readBody(req, 256 * 1024)).toString("utf8"));
      const month = safeSegment(body.month, "month");
      const slot = safeSegment(body.slot, "0");
      const kind = body.kind === "thumb" ? "thumb" : "video";
      const original = safeSegment(body.fileName, kind === "thumb" ? "thumbnail.jpg" : "video.mp4");
      const key = [
        "representative-video-scheduler",
        "media",
        month,
        `slot-${slot}`,
        `${kind}-${Date.now()}-${original}`
      ].join("/");
      sendJson(res, 200, {
        ok: true,
        key,
        uploadUrl: r2PresignedUrl("PUT", key, 3600),
        mediaUrl: protectedR2MediaUrl(key, original)
      });
    } catch (error) {
      sendJson(res, 400, { ok: false, message: error.message || "r2_upload_url_failed" });
    }
    return;
  }

  if (req.method === "GET" && url.pathname.startsWith("/api/r2/media/")) {
    if (!R2) {
      sendJson(res, 503, { ok: false, message: "Cloudflare R2 is not configured" });
      return;
    }
    const key = decodeR2MediaKey(url.pathname.slice("/api/r2/media/".length));
    if (!key) {
      sendJson(res, 403, { ok: false });
      return;
    }
    try {
      const headers = {};
      if (req.headers.range) headers.Range = req.headers.range;
      const upstream = await fetch(r2PresignedUrl("GET", key, 3600), { headers });
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
      if (url.searchParams.get("download") === "1") {
        const filename = safeSegment(url.searchParams.get("name"), path.basename(key) || "download");
        responseHeaders["Content-Disposition"] = `attachment; filename="${filename}"`;
      }
      res.writeHead(upstream.status, responseHeaders);
      if (upstream.body) Readable.fromWeb(upstream.body).pipe(res);
      else res.end();
    } catch {
      sendJson(res, 502, { ok: false, message: "R2 media fetch failed" });
    }
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/mux/asset-from-r2") {
    if (!MUX || !R2) {
      sendJson(res, 503, { ok: false, message: "Mux and Cloudflare R2 are not configured" });
      return;
    }
    try {
      const body = JSON.parse((await readBody(req, 256 * 1024)).toString("utf8"));
      const key = decodeR2MediaKey(Buffer.from(String(body.key || ""), "utf8").toString("base64url"));
      if (!key) {
        sendJson(res, 400, { ok: false, message: "Invalid R2 key" });
        return;
      }
      sendJson(res, 200, {
        ok: true,
        ...(await createMuxAssetFromR2Key(key, body))
      });
    } catch (error) {
      sendJson(res, 502, { ok: false, message: error.message || "mux_asset_create_failed" });
    }
    return;
  }

  if (req.method === "GET" && url.pathname.startsWith("/api/mux/assets/")) {
    if (!MUX) {
      sendJson(res, 503, { ok: false, message: "Mux is not configured" });
      return;
    }
    try {
      const assetId = safeSegment(url.pathname.slice("/api/mux/assets/".length), "");
      const asset = await muxRequest(`/assets/${assetId}`);
      sendJson(res, 200, {
        ok: true,
        assetId: asset.id,
        playbackId: muxPlaybackId(asset),
        status: asset.status || "preparing"
      });
    } catch (error) {
      sendJson(res, 502, { ok: false, message: error.message || "mux_asset_fetch_failed" });
    }
    return;
  }

  if (req.method === "DELETE" && url.pathname.startsWith("/api/mux/assets/")) {
    if (!MUX) {
      sendJson(res, 503, { ok: false, message: "Mux is not configured" });
      return;
    }
    try {
      const assetId = safeSegment(url.pathname.slice("/api/mux/assets/".length), "");
      await muxRequest(`/assets/${assetId}`, { method: "DELETE" });
      sendJson(res, 200, { ok: true, assetId });
    } catch (error) {
      sendJson(res, 502, { ok: false, message: error.message || "mux_asset_delete_failed" });
    }
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
