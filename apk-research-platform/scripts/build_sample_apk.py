"""Build a real, signed sample APK with the bundled Android SDK (ground truth).

The taskbook cannot be verified against a black-box binary, so the platform ships
a sample whose contents *we* control: known package, known classes, known
methods, known string literals, known permissions. Every P1/P2 assertion
("apk_search_code finds validateLicense", "apk_read_method returns the body")
is checked against this file and ``samples/ground_truth.json``.

Usage:  python scripts/build_sample_apk.py [--out samples/sample-app.apk]
Outputs: the APK, a debug keystore under tools/keystore/, and ground_truth.json.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import hashlib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "tools"
JAVA = TOOLS / "jdk" / "bin" / "java.exe"
JAVAC = TOOLS / "jdk" / "bin" / "javac.exe"
KEYTOOL = TOOLS / "jdk" / "bin" / "keytool.exe"
BUILD_TOOLS = TOOLS / "android-sdk" / "build-tools" / "34.0.0"
ANDROID_JAR = TOOLS / "android-sdk" / "platforms" / "android-34" / "android.jar"
KEYSTORE = TOOLS / "keystore" / "debug.keystore"
WORK = ROOT / "samples" / "build"

MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.reef"
    android:versionCode="7"
    android:versionName="1.2.3">
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.READ_PHONE_STATE" />
    <application android:label="@string/app_name" android:allowBackup="false">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        <service android:name=".SyncService" android:exported="false" />
        <receiver android:name=".BootReceiver" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED" />
            </intent-filter>
        </receiver>
        <provider android:name=".ReefProvider" android:authorities="com.example.reef.provider" android:exported="false" />
    </application>
</manifest>
"""

STRINGS = """<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">Reef Sample</string>
    <string name="welcome">Welcome to the reef</string>
    <string name="license_endpoint">https://license.example-reef.test/v1/activate</string>
    <string name="telemetry_endpoint">https://telemetry.example-reef.test/collect</string>
</resources>
"""

CLEAN_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.tide"
    android:versionCode="3"
    android:versionName="0.9.0">
    <application android:label="@string/app_name" android:allowBackup="false">
        <activity android:name=".PingActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
"""

CLEAN_STRINGS = """<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">Tide Timer</string>
    <string name="welcome">Count the tides</string>
</resources>
"""

# The clean corpus exists so G1 can show that the agent's plan changes with what it
# observes: same tools, a project with no network client and no credential-shaped
# literals, so "hunt for hardcoded secrets" is the wrong plan and the trace must show it.
CLEAN_SOURCES = {
    "com/example/tide/PingActivity.java": """package com.example.tide;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

public class PingActivity extends Activity {
    private static final String TAG = "TidePing";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        TextView view = new TextView(this);
        view.setText("tide " + TideMath.tide(3));
        setContentView(view);
        Log.i(TAG, "rendered tide view");
    }
}
""",
    "com/example/tide/TideMath.java": """package com.example.tide;

public final class TideMath {
    private TideMath() {
    }

    public static int tide(int day) {
        if (day < 0) {
            return 0;
        }
        return (day * 7 + 3) % 11;
    }
}
""",
}

SOURCES = {
    "com/example/reef/MainActivity.java": """package com.example.reef;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;

public class MainActivity extends Activity {
    private static final String TAG = "ReefMain";
    private final SecurityHelper helper = new SecurityHelper();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Log.i(TAG, "starting reef sample");
        boolean licensed = helper.validateLicense("REEF-LICENSE-4417");
        if (!licensed) {
            Log.w(TAG, "license rejected");
        }
        String token = helper.buildToken("device-42", "REEF-SALT-9000");
        Log.d(TAG, "token " + token);
        helper.reportTelemetry("https://telemetry.example-reef.test/collect", token);
    }
}
""",
    "com/example/reef/SecurityHelper.java": """package com.example.reef;

import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

public class SecurityHelper {
    private static final String LICENSE_ENDPOINT = "https://license.example-reef.test/v1/activate";
    private static final String DEFAULT_SALT = "REEF-SALT-9000";

    public boolean validateLicense(String candidate) {
        if (candidate == null || candidate.isEmpty()) {
            return false;
        }
        String normalised = candidate.trim().toUpperCase(Locale.ROOT);
        return normalised.startsWith("REEF-LICENSE-") && normalised.length() == 18;
    }

    public String buildToken(String deviceId, String salt) {
        String material = deviceId + ":" + (salt == null ? DEFAULT_SALT : salt);
        return sha256Hex(material);
    }

    public void reportTelemetry(String endpoint, String token) {
        HttpUploader uploader = new HttpUploader();
        uploader.post(endpoint + "?t=" + token, "{\\"event\\":\\"start\\"}");
    }

    private static String sha256Hex(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] bytes = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : bytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }
}
""",
    "com/example/reef/HttpUploader.java": """package com.example.reef;

import android.util.Log;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

public class HttpUploader {
    public static final String USER_AGENT = "ReefSample/1.2.3";
    public static final String API_KEY_HEADER = "X-Reef-Key";
    private static final String STATIC_API_KEY = "REEF-API-KEY-7781";

    public int post(String endpoint, String body) {
        HttpURLConnection connection = null;
        try {
            connection = (HttpURLConnection) new URL(endpoint).openConnection();
            connection.setRequestMethod("POST");
            connection.setRequestProperty(API_KEY_HEADER, STATIC_API_KEY);
            connection.setDoOutput(true);
            try (OutputStream out = connection.getOutputStream()) {
                out.write(body.getBytes("UTF-8"));
            }
            return connection.getResponseCode();
        } catch (Exception e) {
            Log.e("ReefUploader", "upload failed", e);
            return -1;
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }
}
""",
    "com/example/reef/SyncService.java": """package com.example.reef;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;

public class SyncService extends Service {
    private SecurityHelper helper = new SecurityHelper();

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        helper.buildToken("service-device", "SERVICE-SALT-12");
        return START_STICKY;
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
""",
    "com/example/reef/BootReceiver.java": """package com.example.reef;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

public class BootReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        Log.i("ReefBoot", "boot completed, arming sync");
        Intent service = new Intent(context, SyncService.class);
        context.startService(service);
    }
}
""",
    "com/example/reef/ReefProvider.java": """package com.example.reef;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;

public class ReefProvider extends ContentProvider {
    public static final String AUTHORITY = "com.example.reef.provider";

    @Override
    public boolean onCreate() {
        return true;
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
        return null;
    }

    @Override
    public String getType(Uri uri) {
        return "vnd.reef/cursor";
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        return null;
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        return 0;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        return 0;
    }
}
""",
}

GROUND_TRUTH = {
    "package": "com.example.reef",
    "version_name": "1.2.3",
    "version_code": "7",
    "min_sdk": "21",
    "target_sdk": "34",
    "app_name": "Reef Sample",
    "permissions": ["android.permission.INTERNET", "android.permission.READ_PHONE_STATE"],
    "activities": ["com.example.reef.MainActivity"],
    "services": ["com.example.reef.SyncService"],
    "receivers": ["com.example.reef.BootReceiver"],
    "providers": ["com.example.reef.ReefProvider"],
    "classes": [
        "com.example.reef.MainActivity",
        "com.example.reef.SecurityHelper",
        "com.example.reef.HttpUploader",
        "com.example.reef.SyncService",
        "com.example.reef.BootReceiver",
        "com.example.reef.ReefProvider",
    ],
    "methods": {
        "com.example.reef.SecurityHelper": ["validateLicense", "buildToken", "reportTelemetry", "sha256Hex"],
        "com.example.reef.MainActivity": ["onCreate"],
        "com.example.reef.HttpUploader": ["post"],
    },
    "strings": [
        "REEF-LICENSE-4417",
        "REEF-SALT-9000",
        "REEF-API-KEY-7781",
        "https://license.example-reef.test/v1/activate",
        "https://telemetry.example-reef.test/collect",
        "X-Reef-Key",
    ],
    "resources": {
        "string/app_name": "Reef Sample",
        "string/license_endpoint": "https://license.example-reef.test/v1/activate",
    },
    "notes": [
        "REEF-API-KEY-7781 is a synthetic secret baked into the sample; it exists so the",
        "platform can prove secret-detection evidence is traceable, not to model a real breach.",
    ],
    "hostile_variants": {},
}


def run(cmd: list[str], cwd: Path | None = None, timeout: int = 600) -> subprocess.CompletedProcess:
    proc = subprocess.run(
        [str(c) for c in cmd],
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        errors="replace",
        timeout=timeout,
    )
    if proc.returncode != 0:
        sys.stderr.write(f"[build] FAILED: {' '.join(str(c) for c in cmd)}\n{proc.stdout}\n{proc.stderr}\n")
        raise SystemExit(proc.returncode)
    return proc


def ensure_keystore() -> None:
    if KEYSTORE.exists():
        return
    KEYSTORE.parent.mkdir(parents=True, exist_ok=True)
    run(
        [
            str(KEYTOOL), "-genkeypair", "-v", "-keystore", str(KEYSTORE), "-storepass", "android",
            "-alias", "androiddebugkey", "-keypass", "android", "-keyalg", "RSA", "-keysize", "2048",
            "-validity", "10000", "-dname", "CN=Android Debug,O=Android,C=US",
        ]
    )


def build(out: Path, *, sources: dict[str, str] | None = None, manifest: str | None = None, strings: str | None = None) -> Path:
    sources = sources or SOURCES
    manifest = manifest or MANIFEST
    strings = strings or STRINGS
    for exe in (JAVA, JAVAC, ANDROID_JAR, BUILD_TOOLS / "aapt2.exe"):
        if not exe.exists():
            raise SystemExit(f"[build] missing tool: {exe} (run scripts/fetch_toolchain.py)")
    ensure_keystore()
    if WORK.exists():
        shutil.rmtree(WORK)
    res = WORK / "res" / "values"
    res.mkdir(parents=True)
    (res / "strings.xml").write_text(strings, encoding="utf-8")
    (WORK / "AndroidManifest.xml").write_text(manifest, encoding="utf-8")
    src = WORK / "java"
    for rel, code in sources.items():
        path = src / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(code, encoding="utf-8")

    flat = WORK / "compiled"
    flat.mkdir()
    run([str(BUILD_TOOLS / "aapt2.exe"), "compile", "-o", str(flat), str(WORK / "res" / "values" / "strings.xml")])

    gen = WORK / "gen"
    gen.mkdir()
    unsig = WORK / "app-unsigned.apk"
    run(
        [
            str(BUILD_TOOLS / "aapt2.exe"), "link", "-o", str(unsig),
            "-I", str(ANDROID_JAR),
            "--manifest", str(WORK / "AndroidManifest.xml"),
            "--min-sdk-version", "21", "--target-sdk-version", "34",
            "--java", str(gen),
            str(flat / "values_strings.arsc.flat"),
        ]
    )

    classes = WORK / "classes"
    classes.mkdir()
    java_files = [str(p) for p in src.rglob("*.java")] + [str(p) for p in gen.rglob("R.java")]
    run([str(JAVAC), "-nowarn", "-Xlint:-options", "-source", "8", "-target", "8",
         "-bootclasspath", str(ANDROID_JAR), "-cp", str(ANDROID_JAR), "-d", str(classes), *java_files])

    dex_dir = WORK / "dex"
    dex_dir.mkdir()
    class_files = [str(p) for p in classes.rglob("*.class")]
    run([str(JAVA), "-cp", str(BUILD_TOOLS / "lib" / "d8.jar"), "com.android.tools.r8.D8",
         "--lib", str(ANDROID_JAR), "--min-api", "21", "--output", str(dex_dir), *class_files])

    with zipfile.ZipFile(unsig, "a") as zf:
        zf.write(dex_dir / "classes.dex", "classes.dex")

    aligned = WORK / "app-aligned.apk"
    run([str(BUILD_TOOLS / "zipalign.exe"), "-f", "-p", "4", str(unsig), str(aligned)])

    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists():
        out.unlink()
    run(
        [
            str(JAVA), "-jar", str(BUILD_TOOLS / "lib" / "apksigner.jar"), "sign",
            "--ks", str(KEYSTORE), "--ks-pass", "pass:android", "--key-pass", "pass:android",
            "--ks-key-alias", "androiddebugkey", "--min-sdk-version", "21",
            "--out", str(out), str(aligned),
        ]
    )
    return out


def hostile_variants(source: Path, ground_truth: dict) -> dict:
    """Build the malformed inputs P5 must reject (and record their expectations).

    Each variant is padded past the 1 KiB floor with an inert entry so it fails for the
    reason it was built for instead of tripping ``apk_too_small`` first.
    """
    out_dir = source.parent
    variants: dict[str, dict] = {}
    pad = b"\x00" * 2048

    def write(path, entries, *, stored=True):
        mode = zipfile.ZIP_STORED if stored else zipfile.ZIP_DEFLATED
        with zipfile.ZipFile(path, "w", mode, compresslevel=9 if not stored else None) as zf:
            for name, blob in entries:
                zf.writestr(name, blob)
            zf.writestr("assets/pad.bin", pad)

    truncated = out_dir / "hostile-truncated.apk"
    data = source.read_bytes()
    truncated.write_bytes(data[: len(data) // 3])
    variants["hostile-truncated.apk"] = {"expect_error": "corrupt_zip", "why": "central directory cut off"}

    renamed = out_dir / "hostile-not-zip.apk"
    renamed.write_bytes(b"#!/bin/sh\necho not an apk\n" * 100)
    variants["hostile-not-zip.apk"] = {"expect_error": "not_a_zip", "why": "text file with an .apk name"}

    slip = out_dir / "hostile-zip-slip.apk"
    write(
        slip,
        [
            ("AndroidManifest.xml", b"\x03\x00\x08\x00" + b"\x00" * 64),
            ("classes.dex", b"dex\n035\x00" + b"\x00" * 64),
            ("../../escape.txt", b"escaped"),
        ],
    )
    variants["hostile-zip-slip.apk"] = {"expect_error": "zip_slip", "why": "entry path escapes the archive root"}

    no_manifest = out_dir / "hostile-no-manifest.apk"
    write(no_manifest, [("classes.dex", b"dex\n035\x00" + b"\x00" * 64)])
    variants["hostile-no-manifest.apk"] = {"expect_error": "missing_manifest", "why": "no AndroidManifest.xml"}

    no_dex = out_dir / "hostile-no-dex.apk"
    write(
        no_dex,
        [
            ("AndroidManifest.xml", b"\x03\x00\x08\x00" + b"\x00" * 64),
            ("res/values/strings.xml", b"<resources/>"),
        ],
    )
    variants["hostile-no-dex.apk"] = {"expect_error": "missing_dex", "why": "manifest present but zero dex"}

    bomb = out_dir / "hostile-bomb.apk"
    write(
        bomb,
        [
            ("AndroidManifest.xml", b"\x03\x00\x08\x00" + b"\x00" * 64),
            ("classes.dex", b"dex\n035\x00" + b"\x00" * 64),
            ("assets/payload.bin", b"\x00" * (64 * 1024 * 1024)),
        ],
        stored=False,
    )
    variants["hostile-bomb.apk"] = {
        "expect_error": "zip_bomb",
        "why": "64 MiB declared payload from a few KB, ratio far over the 100:1 guard",
        "note": "the file itself is small; the guard reads declared sizes before inflating",
    }
    ground_truth["hostile_variants"] = variants
    return variants


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=None)
    parser.add_argument("--variant", choices=["reef", "clean"], default="reef")
    parser.add_argument("--no-hostile", action="store_true")
    args = parser.parse_args()
    if args.variant == "clean":
        default_out = ROOT / "samples" / "sample-clean.apk"
        out = Path(args.out) if args.out else default_out
        built = build(out, sources=CLEAN_SOURCES, manifest=CLEAN_MANIFEST, strings=CLEAN_STRINGS)
    else:
        out = Path(args.out) if args.out else ROOT / "samples" / "sample-app.apk"
        built = build(out)
    gt = json.loads(json.dumps(GROUND_TRUTH))

    # pin the artefacts the pipeline must reproduce: the APK digest, the signing
    # certificate digest and the synthetic secret literals the corpus contains.
    sys.path.insert(0, str(ROOT / "backend"))
    try:
        from loguru import logger

        logger.remove()  # androguard logs DEBUG to stderr by default
    except Exception:  # noqa: BLE001
        pass
    from apkplat.apkfile import parse_metadata  # local import: needs backend on path

    digest = hashlib.sha256(built.read_bytes()).hexdigest()
    meta = parse_metadata(built)
    gt["apk_sha256"] = digest
    gt["apk_bytes"] = built.stat().st_size
    gt["certificate_sha256"] = meta.get("certificate_sha256")
    gt["certificate_schemes"] = sorted(k for k in ("v1", "v2", "v3") if (meta.get("signing") or {}).get(k))
    gt["signing_agrees_with_androguard"] = bool((meta.get("signing") or {}).get("agrees_with_androguard"))
    gt["secret_literals"] = (
        ["REEF-LICENSE-4417", "REEF-SALT-9000", "REEF-API-KEY-7781", "SERVICE-SALT-12"] if args.variant == "reef" else []
    )
    gt["built_by"] = "scripts/build_sample_apk.py (aapt2 + javac + d8 + zipalign + apksigner)"
    gt["variant"] = args.variant
    gt["rebuild_note"] = (
        "apk_sha256 is a snapshot of this exact build: re-running the builder re-signs and "
        "re-zips the APK, so always regenerate ground_truth.json together with the APK."
    )
    if not args.no_hostile and args.variant == "reef":
        hostile_variants(built, gt)
    truth_name = "ground_truth.json" if args.variant == "reef" else "ground_truth_clean.json"
    (out.parent / truth_name).write_text(json.dumps(gt, indent=2), encoding="utf-8")
    print(f"[build] apk   {built}  ({built.stat().st_size} bytes)  sha256={digest}")
    print(f"[build] cert  {gt['certificate_sha256']}")
    print(f"[build] truth {out.parent / truth_name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
