from __future__ import annotations

import asyncio
import base64
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Literal, Optional, Tuple

# -----------------------------
# CONFIG (same as your signer)
# -----------------------------

ZSIGN_BIN = Path(os.environ.get("ZSIGN_BIN", "/usr/local/bin/zsign"))

IPA_MAP: Dict[str, Path] = {
    "gbox": Path(os.environ.get("IPA_GBOX", "/root/signbot-local/ipas/Gbox.ipa")),
    "esgn": Path(os.environ.get("IPA_ESGN", "/root/signbot-local/ipas/esign_5.0.2_unsigned.ipa")),
    "scarlet": Path(os.environ.get("IPA_SCARLET", "/root/signbot-local/ipas/ScarletAlpha.ipa")),
}

BUNDLE_ID_MAP: Dict[str, str] = {
    "esgn": os.environ.get("BUNDLE_ESGN", "com.example.esgn"),
    "gbox": os.environ.get("BUNDLE_GBOX", "com.example.gbox"),
    "scarlet": os.environ.get("BUNDLE_SCARLET", "com.example.scarlet"),
}

APP_TITLE_MAP: Dict[str, str] = {
    "esgn": os.environ.get("TITLE_ESGN", "ESign"),
    "gbox": os.environ.get("TITLE_GBOX", "GBox"),
    "scarlet": os.environ.get("TITLE_SCARLET", "Scarlet"),
}

# IMPORTANT: OTA install requires HTTPS + Safari
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "https://example.com").rstrip("/")
PUBLIC_DIR = Path(os.environ.get("PUBLIC_DIR", "/root/signbot-local/public")).resolve()
PUBLIC_FILES_DIR = (PUBLIC_DIR / "files").resolve()
PUBLIC_META_DIR = (PUBLIC_DIR / "meta").resolve()

SAFE_ID_RE = re.compile(r"^[a-zA-Z0-9._-]{6,128}$")

SigningVariant = Literal["esgn", "gbox", "scarlet"]


@dataclass
class SignOutput:
    install_id: str
    install_page_url: str
    ipa_url: str
    public_ipa_name: str


# -----------------------------
# META JSON
# -----------------------------
def write_meta_json(
    *,
    meta_path: Path,
    ipa_filename: str,
    title: str,
    bundle_id: str,
    bundle_version: str,
    variant: str,
) -> None:
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "ipa_filename": ipa_filename,
        "title": title,
        "bundle_id": bundle_id,
        "bundle_version": bundle_version,
        "variant": variant,
        "created_at": int(time.time()),
    }
    meta_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


# -----------------------------
# ZSIGN
# -----------------------------
async def sign_with_zsign(
    *,
    ipa_path: Path,
    p12_path: Path,
    prov_path: Path,
    password: str,
    bundleid: str,
    out_ipa: Path,
) -> Path:
    if not ZSIGN_BIN.exists():
        raise ValueError(f"zsign not found at: {ZSIGN_BIN}")
    if not ipa_path.exists():
        raise ValueError(f"IPA not found: {ipa_path}")
    if not p12_path.exists():
        raise ValueError("Missing .p12 file.")
    if not prov_path.exists():
        raise ValueError("Missing .mobileprovision file.")
    if password is None or password == "":
        raise ValueError("Password is empty.")

    out_ipa.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        str(ZSIGN_BIN),
        "-k", str(p12_path),
        "-p", password,
        "-m", str(prov_path),
        "-b", bundleid,
        "-o", str(out_ipa),
        str(ipa_path),
    ]

    def _run():
        return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    res = await asyncio.to_thread(_run)
    if res.returncode != 0 or not out_ipa.exists():
        out = (res.stdout or "")[-4000:]
        raise ValueError(f"zsign failed.\n\nOutput:\n{out}")

    return out_ipa


# -----------------------------
# PUBLIC PUBLISH
# -----------------------------
def ensure_public_dirs() -> None:
    PUBLIC_FILES_DIR.mkdir(parents=True, exist_ok=True)
    PUBLIC_META_DIR.mkdir(parents=True, exist_ok=True)


def validate_runtime() -> None:
    if not ZSIGN_BIN.exists():
        raise RuntimeError(f"zsign binary not found at {ZSIGN_BIN}")
    missing = [k for k, p in IPA_MAP.items() if not p.exists()]
    if missing:
        raise RuntimeError("Missing IPA files for variants: " + ", ".join(missing))
    ensure_public_dirs()


def _b64_to_bytes(b64_str: str) -> bytes:
    try:
        return base64.b64decode((b64_str or "").strip())
    except Exception:
        raise ValueError("Failed to decode base64 cert data.")


# -----------------------------
# MAIN FUNCTION YOU'LL CALL FROM BOT A
# -----------------------------
async def sign_variant_from_b64_cert(
    *,
    variant: SigningVariant,
    udid: str,
    p12_b64: str,
    mp_b64: str,
    password: str,
    bundle_version: str = "1.0",
    workdir: Optional[Path] = None,
) -> SignOutput:
    """
    ✅ Takes base64 cert/profile, writes them to files, signs the chosen IPA variant,
    publishes to PUBLIC_DIR, and returns install + download URLs.

    - variant: "esgn" | "gbox" | "scarlet"
    - udid: used only for temp filenames
    - p12_b64 / mp_b64: from provider API
    - password: p12 password (you said always "1")
    """
    validate_runtime()

    if variant not in IPA_MAP:
        raise ValueError("Invalid variant.")
    ipa_path = IPA_MAP[variant]
    bundleid = BUNDLE_ID_MAP.get(variant, "com.example.app")
    title = APP_TITLE_MAP.get(variant, variant)

    if not udid:
        raise ValueError("UDID is missing.")
    if not p12_b64 or not mp_b64:
        raise ValueError("Certificate data missing (base64).")

    p12_bytes = _b64_to_bytes(p12_b64)
    mp_bytes = _b64_to_bytes(mp_b64)
    if not p12_bytes:
        raise ValueError("Decoded .p12 is empty.")
    if not mp_bytes:
        raise ValueError("Decoded .mobileprovision is empty.")

    # Workdir
    if workdir is None:
        tmpdir = Path(tempfile.mkdtemp(prefix="signsvc_"))
    else:
        tmpdir = workdir
        tmpdir.mkdir(parents=True, exist_ok=True)

    cert_dir = tmpdir / "cert"
    cert_dir.mkdir(parents=True, exist_ok=True)

    p12_path = cert_dir / f"{udid}.p12"
    prov_path = cert_dir / f"{udid}.mobileprovision"
    p12_path.write_bytes(p12_bytes)
    prov_path.write_bytes(mp_bytes)

    job = uuid.uuid4().hex[:10]
    signed_tmp = tmpdir / f"{variant}-{job}.signed.ipa"

    signed_path = await sign_with_zsign(
        ipa_path=ipa_path,
        p12_path=p12_path,
        prov_path=prov_path,
        password=password,
        bundleid=bundleid,
        out_ipa=signed_tmp,
    )

    # Publish
    public_ipa_name = signed_path.name
    public_ipa_path = PUBLIC_FILES_DIR / public_ipa_name
    shutil.copy2(signed_path, public_ipa_path)

    install_id = f"{variant}-{job}"
    if not SAFE_ID_RE.match(install_id):
        raise ValueError("Generated install id is invalid.")

    meta_path = PUBLIC_META_DIR / f"{install_id}.meta.json"
    write_meta_json(
        meta_path=meta_path,
        ipa_filename=public_ipa_name,
        title=title,
        bundle_id=bundleid,
        bundle_version=bundle_version,
        variant=variant,
    )

    install_page_url = f"{PUBLIC_BASE_URL}/install/{install_id}"
    ipa_url = f"{PUBLIC_BASE_URL}/files/{public_ipa_name}"

    return SignOutput(
        install_id=install_id,
        install_page_url=install_page_url,
        ipa_url=ipa_url,
        public_ipa_name=public_ipa_name,
    )
