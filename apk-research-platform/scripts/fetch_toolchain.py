#!/usr/bin/env python
"""Project-internal toolchain fetcher for the APK analysis platform.

Everything is installed **inside this repository** under ``tools/``; no system
PATH, registry or global package is touched, and ``--clean`` removes the whole
tree again (full rollback).

Components
  jdk        Eclipse Temurin JDK 21 (runs jadx / apktool / d8 / sdkmanager)
  node       Node.js 22 LTS (frontend build only)
  jadx       JADX 1.5.6 CLI (Java decompiler, smali fallback built in)
  apktool    Apktool 3.0.3 (resource decoding + repackaging)
  android    Android SDK cmdline-tools + build-tools;34.0.0 + platforms;android-34
             (aapt2/d8/android.jar -> self-built ground-truth sample APKs)

Usage
  python scripts/fetch_toolchain.py --list
  python scripts/fetch_toolchain.py                 # install everything
  python scripts/fetch_toolchain.py --only jdk,node
  python scripts/fetch_toolchain.py --verify
  python scripts/fetch_toolchain.py --clean
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "tools"
CACHE = TOOLS / "_cache"
MANIFEST = TOOLS / "MANIFEST.json"

UA = "apk-research-platform/1.0 (+toolchain-fetch)"

COMPONENTS: list[dict] = [
    {
        "id": "node",
        "version": "22.23.4",
        "url": "https://nodejs.org/dist/v22.23.4/node-v22.23.4-win-x64.zip",
        "sha256_url": "https://nodejs.org/dist/v22.23.4/SHASUMS256.txt",
        "strip_prefix": "node-v22.23.4-win-x64",
        "dest": "node",
        "probe": ["node.exe", "-v"],
    },
    {
        "id": "jdk",
        "version": "21-ga-temurin",
        "url": (
            "https://api.adoptium.net/v3/binary/latest/21/ga/windows/x64/jdk/"
            "hotspot/normal/eclipse?project=jdk"
        ),
        "strip_prefix": None,
        "dest": "jdk",
        "probe": ["bin/java.exe", "-version"],
    },
    {
        "id": "jadx",
        "version": "1.5.6",
        "url": "https://github.com/skylot/jadx/releases/download/v1.5.6/jadx-1.5.6.zip",
        "strip_prefix": None,
        "dest": "jadx",
        "probe": ["bin/jadx.bat", "--version"],
    },
    {
        "id": "apktool",
        "version": "3.0.3",
        "url": "https://github.com/iBotPeaches/Apktool/releases/download/v3.0.3/apktool_3.0.3.jar",
        "single_file": "apktool/apktool.jar",
        "dest": "apktool",
        "probe": ["apktool.bat", "--version"],
    },
    {
        "id": "android",
        "version": "cmdline-tools-13114758",
        "url": "https://dl.google.com/android/repository/commandlinetools-win-13114758_latest.zip",
        "strip_prefix": None,
        "dest": "android-sdk/cmdline-tools",
        "post_rename": {"cmdline-tools": "latest"},
        "packages": ["platform-tools", "build-tools;34.0.0", "platforms;android-34"],
        "probe": ["android-sdk/build-tools/34.0.0/aapt2.exe", "version"],
    },
]

BY_ID = {c["id"]: c for c in COMPONENTS}


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def log(msg: str) -> None:
    print(f"[fetch] {msg}", flush=True)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def download(url: str, dest: Path, expect_sha256: str | None = None, retries: int = 3) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() and dest.stat().st_size > 0:
        if expect_sha256 and sha256_file(dest) != expect_sha256:
            log(f"cached file checksum mismatch, re-downloading {dest.name}")
            dest.unlink()
        else:
            log(f"cache hit {dest.name}")
            return dest
    part = dest.with_suffix(dest.suffix + ".part")
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=60) as resp, part.open("wb") as out:
                total = int(resp.headers.get("Content-Length") or 0)
                done = 0
                t0 = time.time()
                last = 0.0
                while True:
                    chunk = resp.read(1 << 20)
                    if not chunk:
                        break
                    out.write(chunk)
                    done += len(chunk)
                    if time.time() - last > 2:
                        last = time.time()
                        pct = f"{done * 100 / total:5.1f}%" if total else "  ?  "
                        rate = done / max(time.time() - t0, 1e-6) / 1048576
                        log(f"  {dest.name} {pct} {done / 1048576:7.1f}MB @ {rate:5.1f}MB/s")
            part.replace(dest)
            if expect_sha256:
                got = sha256_file(dest)
                if got != expect_sha256:
                    dest.unlink()
                    raise RuntimeError(f"sha256 mismatch for {dest.name}: {got} != {expect_sha256}")
            log(f"downloaded {dest.name} ({dest.stat().st_size / 1048576:.1f}MB)")
            return dest
        except Exception as exc:  # noqa: BLE001
            part.unlink(missing_ok=True)
            log(f"attempt {attempt}/{retries} failed for {url}: {exc}")
            if attempt == retries:
                raise
            time.sleep(2 * attempt)
    raise RuntimeError("unreachable")


def fetch_text(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read().decode("utf-8", "replace")


def safe_extract(zip_path: Path, dest: Path, strip_prefix: str | None = None) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    dest_root = dest.resolve()
    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            name = info.filename
            if strip_prefix:
                if not name.startswith(strip_prefix.rstrip("/") + "/"):
                    continue
                name = name[len(strip_prefix.rstrip("/")) + 1 :]
            if not name or name.endswith("/"):
                continue
            target = (dest / name).resolve()
            if not str(target).startswith(str(dest_root)):
                raise RuntimeError(f"zip slip blocked: {info.filename}")
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, target.open("wb") as out:
                shutil.copyfileobj(src, out)
            mode = (info.external_attr >> 16) & 0o777
            if mode and not platform.system() == "Windows":
                os.chmod(target, mode)


def run(
    cmd: list[str], cwd: Path | None = None, env: dict | None = None, quiet: bool = False, input_text: str | None = None
) -> tuple[int, str]:
    proc = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        env=env,
        input=input_text,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        errors="replace",
        timeout=3600,
    )
    if not quiet:
        tail = "\n".join(proc.stdout.strip().splitlines()[-4:])
        log(f"  $ {' '.join(cmd[:3])}... -> exit {proc.returncode} {tail[:400]}")
    return proc.returncode, proc.stdout


# --------------------------------------------------------------------------
# per-component installation
# --------------------------------------------------------------------------
def checksum_for(comp: dict, filename: str) -> str | None:
    if not comp.get("sha256_url"):
        return None
    try:
        for line in fetch_text(comp["sha256_url"]).splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1].lstrip("*") == filename:
                return parts[0]
    except Exception as exc:  # noqa: BLE001
        log(f"checksum list unavailable ({exc}); recording computed digest instead")
    return None


def install(comp: dict, force: bool = False) -> dict:
    comp_id, dest = comp["id"], TOOLS / comp["dest"]
    if dest.exists() and comp.get("probe") and not force:
        probe_ok, _ = probe(comp)
        if probe_ok:
            log(f"{comp_id}: already installed at {dest}")
            return materialise(comp, installed="skipped-existing")
    version = comp["version"]
    if comp.get("single_file"):
        target = TOOLS / comp["single_file"]
        tmp = CACHE / Path(comp["url"]).name
        download(comp["url"], tmp)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(tmp, target)
        write_apktool_wrapper(target)
        return materialise(comp, installed="ok", artifact=target)
    archive = CACHE / Path(urllib.parse.urlparse(comp["url"]).path).name
    expect = checksum_for(comp, archive.name)
    download(comp["url"], archive, expect)
    tmp_dest = dest.with_name(dest.name + ".new")
    if tmp_dest.exists():
        shutil.rmtree(tmp_dest, ignore_errors=True)
    safe_extract(archive, tmp_dest, comp.get("strip_prefix"))
    # some archives nest one directory level (jadx ships bin/ lib/ at top level,
    # the JDK ships jdk-21.x.y+hotspot/, cmdline-tools ships cmdline-tools/)
    if comp.get("post_rename"):
        for src_name, dst_name in comp["post_rename"].items():
            cand = tmp_dest / src_name
            if cand.exists():
                cand.rename(tmp_dest / dst_name)
    children = [p for p in tmp_dest.iterdir()]
    if comp.get("strip_prefix") is None and len(children) == 1 and children[0].is_dir() and comp_id in ("jdk",):
        inner = children[0]
        for p in inner.iterdir():
            p.rename(tmp_dest / p.name)
        inner.rmdir()
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    tmp_dest.rename(dest)
    if comp_id == "android":
        install_android_packages(comp)
    return materialise(comp, installed="ok")


def write_apktool_wrapper(jar: Path) -> None:
    java = TOOLS / "jdk" / "bin" / "java.exe"
    bat = jar.parent / "apktool.bat"
    bat.write_text(
        "@echo off\r\n"
        f'"{java}" -jar "{jar}" %*\r\n',
        encoding="utf-8",
    )


def install_android_packages(comp: dict) -> None:
    sdk_root = TOOLS / "android-sdk"
    sdkmanager = sdk_root / "cmdline-tools" / "latest" / "bin" / "sdkmanager.bat"
    if not sdkmanager.exists():
        raise RuntimeError(f"sdkmanager not found at {sdkmanager}")
    env = dict(os.environ)
    env["JAVA_HOME"] = str(TOOLS / "jdk")
    env["PATH"] = f"{TOOLS / 'jdk' / 'bin'};{env.get('PATH', '')}"
    env["ANDROID_SDK_ROOT"] = str(sdk_root)
    env["ANDROID_HOME"] = str(sdk_root)
    run(
        [str(sdkmanager), f"--sdk_root={sdk_root}", "--licenses"],
        env=env,
        quiet=True,
        input_text="y\n" * 60,
    )
    pkgs = comp.get("packages") or []
    log(f"installing Android SDK packages: {pkgs}")
    rc, out = run([str(sdkmanager), f"--sdk_root={sdk_root}", *pkgs], env=env)
    if rc != 0:
        log(out[-1500:])
        raise RuntimeError("sdkmanager failed")


def probe(comp: dict) -> tuple[bool, str]:
    if comp.get("single_file"):
        exe = TOOLS / "apktool" / "apktool.bat"
        args = []
    elif comp["id"] == "android":
        exe = TOOLS / comp["probe"][0]
        args = comp["probe"][1:]
    else:
        exe = TOOLS / comp["dest"] / comp["probe"][0]
        args = comp["probe"][1:]
    if not exe.exists():
        return False, f"missing {exe}"
    try:
        rc, out = run([str(exe), *args], quiet=True)
        return rc == 0, (out or "").strip().splitlines()[0][:200] if out.strip() else ""
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def load_manifest() -> dict:
    if MANIFEST.exists():
        try:
            return json.loads(MANIFEST.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            return {}
    return {}


def materialise(comp: dict, installed: str, artifact: Path | None = None) -> dict:
    mf = load_manifest()
    entry = {
        "id": comp["id"],
        "version": comp["version"],
        "url": comp["url"],
        "dest": comp["dest"],
        "installed_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "state": installed,
        "sha256": sha256_file(artifact) if artifact and artifact.exists() else None,
        "probe": comp.get("probe"),
    }
    if comp.get("single_file"):
        entry["sha256"] = sha256_file(TOOLS / comp["single_file"])
    ok, detail = probe(comp)
    entry["probe_ok"] = ok
    entry["probe_detail"] = detail
    mf[comp["id"]] = entry
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST.write_text(json.dumps(mf, indent=2, ensure_ascii=False), encoding="utf-8")
    log(f"{comp['id']}: probe {'OK' if ok else 'FAIL'} {detail}")
    return entry


def verify_all() -> int:
    fails = 0
    for comp in COMPONENTS:
        ok, detail = probe(comp)
        log(f"{comp['id']:<8} {'OK ' if ok else 'FAIL'} {detail}")
        fails += 0 if ok else 1
    return fails


def clean() -> None:
    for name in ("jdk", "node", "jadx", "apktool", "android-sdk", "_cache"):
        p = TOOLS / name
        if p.exists():
            log(f"removing {p}")
            shutil.rmtree(p, ignore_errors=True)
    MANIFEST.unlink(missing_ok=True)
    log("toolchain removed; host environment unchanged")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--only", default="", help="comma separated component ids")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--clean", action="store_true")
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args(argv)

    if args.list:
        for c in COMPONENTS:
            print(f"{c['id']:<8} {c['version']:<24} -> tools/{c['dest']:<24} {c['url']}")
        return 0
    if args.clean:
        clean()
        return 0
    if args.verify:
        return 1 if verify_all() else 0

    ids = [x.strip() for x in args.only.split(",") if x.strip()] or [c["id"] for c in COMPONENTS]
    unknown = [i for i in ids if i not in BY_ID]
    if unknown:
        log(f"unknown components: {unknown}")
        return 2
    TOOLS.mkdir(parents=True, exist_ok=True)
    CACHE.mkdir(parents=True, exist_ok=True)
    failures: list[str] = []
    for cid in ids:
        comp = BY_ID[cid]
        log(f"== {cid} {comp['version']} ==")
        try:
            install(comp, force=args.force)
        except Exception as exc:  # noqa: BLE001
            log(f"{cid}: FAILED - {exc}")
            failures.append(cid)
    log("done." if not failures else f"failures: {failures}")
    return 1 if failures else 0


if __name__ == "__main__":
    if platform.system() != "Windows":
        print("this fetcher targets Windows x64 (project host); other hosts: use system packages", file=sys.stderr)
    raise SystemExit(main(sys.argv[1:]))
