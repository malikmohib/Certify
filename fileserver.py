import json
import os
import re
import time
from pathlib import Path
from typing import Any, Dict
from urllib.parse import quote

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, Response, RedirectResponse

# -----------------------------------------------------------------------------
# Config (VPS defaults)
# -----------------------------------------------------------------------------
PUBLIC_DIR = Path(os.environ.get("PUBLIC_DIR", "/opt/couponbot/public")).expanduser().resolve()
FILES_DIR = (PUBLIC_DIR / "files").resolve()
META_DIR = (PUBLIC_DIR / "meta").resolve()

BASE_URL = os.environ.get("BASE_URL", "https://install-hk.certify.icu").strip().rstrip("/")
if not BASE_URL.lower().startswith("https://"):
    raise RuntimeError("BASE_URL must start with https:// (required for iOS OTA)")

TTL_SECONDS = int(os.environ.get("SIGNED_TTL_SECONDS", str(12 * 3600)).strip() or str(12 * 3600))
TTL_SECONDS = max(600, min(TTL_SECONDS, 7 * 24 * 3600))  # 10 min .. 7 days

FILES_DIR.mkdir(parents=True, exist_ok=True)
META_DIR.mkdir(parents=True, exist_ok=True)

SAFE_FILENAME_RE = re.compile(r"^[a-zA-Z0-9._-]{1,200}$")
SAFE_ID_RE = re.compile(r"^[a-zA-Z0-9._-]{6,128}$")

app = FastAPI()


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def _is_within(base: Path, target: Path) -> bool:
    try:
        return target.resolve().is_relative_to(base.resolve())
    except Exception:
        return False


def _safe_filename(name: str) -> str:
    name = (name or "").strip()
    if "/" in name or "\\" in name:
        raise HTTPException(status_code=400, detail="Invalid filename")
    if not SAFE_FILENAME_RE.fullmatch(name):
        raise HTTPException(status_code=400, detail="Invalid filename")
    return name


def _safe_id(app_id: str) -> str:
    app_id = (app_id or "").strip()
    if not SAFE_ID_RE.fullmatch(app_id):
        raise HTTPException(status_code=400, detail="Invalid id")
    return app_id


def _html_escape(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


def _plist_escape(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def _delete_expired(meta_path: Path, meta: Dict[str, Any]) -> None:
    # Delete IPA (best-effort) then meta (best-effort)
    try:
        ipa_filename = str(meta.get("ipa_filename") or "").strip()
        if ipa_filename:
            ipa_filename = _safe_filename(ipa_filename)
            ipa_path = (FILES_DIR / ipa_filename).resolve()
            if _is_within(FILES_DIR, ipa_path) and ipa_path.exists():
                try:
                    ipa_path.unlink()
                except Exception:
                    pass
    except Exception:
        pass

    try:
        if meta_path.exists():
            meta_path.unlink()
    except Exception:
        pass


def _load_meta(app_id: str) -> Dict[str, Any]:
    app_id = _safe_id(app_id)
    meta_path = (META_DIR / f"{app_id}.meta.json").resolve()

    if not _is_within(META_DIR, meta_path) or not meta_path.exists():
        raise HTTPException(status_code=404, detail="Meta not found")

    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except Exception:
        raise HTTPException(status_code=500, detail="Meta corrupted")

    # Required keys
    for k in ["ipa_filename", "title", "bundle_id", "bundle_version", "created_at"]:
        if k not in meta or str(meta[k]).strip() == "":
            raise HTTPException(status_code=500, detail=f"Meta missing: {k}")

    # Validate and resolve IPA path
    meta["ipa_filename"] = _safe_filename(str(meta["ipa_filename"]))
    ipa_path = (FILES_DIR / meta["ipa_filename"]).resolve()
    if not _is_within(FILES_DIR, ipa_path) or not ipa_path.exists():
        raise HTTPException(status_code=404, detail="IPA missing")

    # Expiry check
    created_at = int(meta.get("created_at") or 0)
    if created_at and int(time.time()) - created_at > TTL_SECONDS:
        _delete_expired(meta_path, meta)
        raise HTTPException(status_code=404, detail="Expired")

    return meta


def _render_manifest(meta: Dict[str, Any]) -> str:
    ipa_url = f"{BASE_URL}/files/{meta['ipa_filename']}"
    title = _plist_escape(str(meta["title"]))
    bundle_id = _plist_escape(str(meta["bundle_id"]))
    bundle_version = _plist_escape(str(meta["bundle_version"]))

    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>items</key>
  <array>
    <dict>
      <key>assets</key>
      <array>
        <dict>
          <key>kind</key>
          <string>software-package</string>
          <key>url</key>
          <string>{ipa_url}</string>
        </dict>
      </array>
      <key>metadata</key>
      <dict>
        <key>bundle-identifier</key>
        <string>{bundle_id}</string>
        <key>bundle-version</key>
        <string>{bundle_version}</string>
        <key>kind</key>
        <string>software</string>
        <key>title</key>
        <string>{title}</string>
      </dict>
    </dict>
  </array>
</dict>
</plist>
"""


# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------
@app.get("/")
def home():
    return {"status": "ok"}


@app.get("/health")
def health():
    return {
        "ok": True,
        "base_url": BASE_URL,
        "ttl_seconds": TTL_SECONDS,
        "public_dir": str(PUBLIC_DIR),
        "files_dir": str(FILES_DIR),
        "meta_dir": str(META_DIR),
    }


@app.get("/files/{name}")
def get_ipa(name: str):
    name = _safe_filename(name)
    p = (FILES_DIR / name).resolve()
    if not _is_within(FILES_DIR, p) or not p.exists():
        raise HTTPException(status_code=404, detail="Not found")

    return FileResponse(
        p,
        filename=p.name,
        media_type="application/octet-stream",
        headers={"Cache-Control": "no-store"},
    )


@app.get("/manifest/{app_id}.plist")
def get_manifest(app_id: str):
    meta = _load_meta(app_id)
    plist = _render_manifest(meta)

    # iOS prefers application/x-plist
    return Response(
        content=plist,
        media_type="application/x-plist",
        headers={"Cache-Control": "no-store"},
    )


@app.get("/go/{app_id}")
def go_install(app_id: str):
    # Validate exists + not expired
    _load_meta(app_id)

    manifest_url = f"{BASE_URL}/manifest/{app_id}.plist"
    itms_link = f"itms-services://?action=download-manifest&url={quote(manifest_url, safe='')}"
    return RedirectResponse(url=itms_link, status_code=302)


@app.get("/miniapp/", response_class=HTMLResponse)
def miniapp():
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>One Button Installer</title>
  <script src="https://telegram.org/js/telegram-web-app.js"></script>
  <style>
    html,body{height:100%;margin:0;background:#0b0f19;}
    .wrap{height:100%;display:grid;place-items:center;padding:24px;}
    button{width:min(420px,100%);height:60px;border:0;border-radius:14px;
           font-size:18px;font-weight:800;cursor:pointer;background:#111;color:#fff;}
    .hint{margin-top:14px;color:#9aa4b2;font:14px/1.4 system-ui;text-align:center;max-width:420px;}
  </style>
</head>
<body>
  <div class="wrap">
    <div>
      <button id="installBtn">Install</button>
      <div class="hint" id="hint">Loading…</div>
    </div>
  </div>

<script>
(() => {
  const tg = window.Telegram?.WebApp;
  const hint = document.getElementById("hint");
  const btn = document.getElementById("installBtn");

  function setHint(msg){ hint.textContent = msg || ""; }

  try {
    tg?.ready();
    tg?.expand();
  } catch(e) {}

  // ✅ Option B: get install id from Telegram start_param (startapp value)
    // Accept install id from either querystring (?id=xxx) OR Telegram start_param (startapp)
  const params = new URLSearchParams(window.location.search);
  const idFromQuery = params.get("id") || "";
  const idFromStart = tg?.initDataUnsafe?.start_param || "";
  const start = (idFromQuery || idFromStart || "").trim();


// Accept:
// 1) "gbox-2ca4efb057"  (already correct)
// 2) "esign-gbox-2ca4efb057" (button prefix + real id)
// 3) "scarlet-gbox-2ca4efb057"
function normalizeInstallId(s) {
  if (!s) return "";
  const parts = s.split("-");
  // If it has 3+ parts, drop the first segment (button variant)
  // and keep the rest as the real meta install id.
  if (parts.length >= 3) return parts.slice(1).join("-");
  return s;
}

const appId = normalizeInstallId(start);


  // basic format check (match your SAFE_ID_RE)
  const ok = /^[a-zA-Z0-9._-]{6,128}$/.test(appId);

  if (!ok) {
    btn.disabled = true;
    btn.style.opacity = "0.6";
    setHint("Missing/invalid install id. Open this page from the bot Install button.");
    return;
  }

  setHint("Tap Install. iOS will switch to Safari to start installation.");

  btn.onclick = () => {
    const goUrl = `${window.location.origin}/go/${encodeURIComponent(appId)}`;
    try {
      tg?.openLink(goUrl, { try_instant_view: false });
    } catch (e) {
      window.location.href = goUrl;
    }
  };
})();
</script>
</body>
</html>
""".strip()



@app.get("/install/{app_id}", response_class=HTMLResponse)
def install_page(app_id: str):
    meta = _load_meta(app_id)

    manifest_url = f"{BASE_URL}/manifest/{app_id}.plist"
    itms_link = f"itms-services://?action=download-manifest&url={quote(manifest_url, safe='')}"

    title = _html_escape(str(meta["title"]))
    bundle_id = _html_escape(str(meta["bundle_id"]))
    bundle_version = _html_escape(str(meta["bundle_version"]))
    manifest_url_html = _html_escape(manifest_url)
    itms_link_html = _html_escape(itms_link)

    return f"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Install {title}</title>
</head>
<body style="font-family:-apple-system,system-ui,Arial; padding:20px; line-height:1.45;">
  <h2>Install {title}</h2>

  <p>
    <b>Bundle ID:</b> <code>{bundle_id}</code><br/>
    <b>Version:</b> <code>{bundle_version}</code>
  </p>

  <p style="margin-top:18px;">
    <a href="{itms_link_html}"
       style="display:inline-block;padding:12px 16px;background:#111;color:#fff;
              text-decoration:none;border-radius:10px;font-weight:700;">
      Install
    </a>
  </p>

  <p style="margin-top:18px;color:#555;">
    If opened from Telegram, use <b>Open in Safari</b>.<br/>
    Or use the Mini App: <code>{_html_escape(BASE_URL)}/miniapp/?id={_html_escape(app_id)}</code>
  </p>

  <p style="margin-top:18px;">
    <small>Manifest URL:</small><br/>
    <code>{manifest_url_html}</code>
  </p>
</body>
</html>
""".strip()
