import os
import re
import math
import hashlib
import zipfile
from collections import Counter
try:
    from androguard.core.apk import APK
    ANDROGUARD_AVAILABLE = True
except Exception:
    ANDROGUARD_AVAILABLE = False

DANGEROUS_PERMISSIONS = {
    "android.permission.SEND_SMS": 8,
    "android.permission.RECEIVE_SMS": 7,
    "android.permission.READ_SMS": 6,
    "android.permission.CALL_PHONE": 5,
    "android.permission.READ_CALL_LOG": 5,
    "android.permission.WRITE_CALL_LOG": 5,
    "android.permission.READ_CONTACTS": 4,
    "android.permission.RECORD_AUDIO": 4,
    "android.permission.ACCESS_FINE_LOCATION": 3,
    "android.permission.ACCESS_COARSE_LOCATION": 2,
    "android.permission.CAMERA": 2,
    "android.permission.READ_PHONE_STATE": 4,
    "android.permission.REQUEST_INSTALL_PACKAGES": 7,
    "android.permission.SYSTEM_ALERT_WINDOW": 7,
    "android.permission.RECEIVE_BOOT_COMPLETED": 6,
    "android.permission.INTERNET": 1,
    "android.permission.WRITE_EXTERNAL_STORAGE": 2,
}

SUSPICIOUS_APIS = {
    "SmsManager": 7,
    "sendTextMessage": 8,
    "Runtime.exec": 8,
    "ProcessBuilder": 7,
    "DexClassLoader": 8,
    "PathClassLoader": 5,
    "AccessibilityService": 7,
    "getDeviceId": 5,
    "getSubscriberId": 5,
    "HttpURLConnection": 2,
    "Socket": 3,
    "WebView": 1,
    "Cipher": 1,
    "Base64": 1,
}

SUSPICIOUS_COMPONENTS = {
    "android.intent.action.BOOT_COMPLETED": 7,
    "android.provider.Telephony.SMS_RECEIVED": 8,
    "android.intent.action.PACKAGE_ADDED": 4,
    "android.intent.action.PACKAGE_REPLACED": 4,
    "android.accessibilityservice.AccessibilityService": 8,
}

URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def entropy(s):
    if not s:
        return 0
    counts = Counter(s)
    n = len(s)
    return -sum((c/n) * math.log2(c/n) for c in counts.values())

def unique(items):
    return list(dict.fromkeys(items))

def analyze_apk(path):
    zf = zipfile.ZipFile(path)
    names = zf.namelist()

    result = {
        "file": os.path.basename(path),
        "sha256": sha256_file(path),
        "size_mb": round(os.path.getsize(path) / (1024*1024), 2),
        "androguard": ANDROGUARD_AVAILABLE,
        "package": "Unknown",
        "version": "Unknown",
        "permissions": [],
        "activities": [],
        "services": [],
        "receivers": [],
        "providers": [],
        "intents": [],
        "urls": [],
        "ips": [],
        "suspicious_apis": [],
        "risk_factors": [],
        "scores": {},
    }

    raw_text_parts = []
    for name in names:
        if name.endswith((".xml", ".json", ".txt", ".js", ".smali", ".dex")) or "assets/" in name:
            try:
                data = zf.read(name)
                raw_text_parts.append(data.decode("utf-8", errors="ignore"))
            except Exception:
                pass
    blob = "\n".join(raw_text_parts)

    result["urls"] = unique(URL_RE.findall(blob))[:30]
    result["ips"] = unique(IP_RE.findall(blob))[:30]

    if ANDROGUARD_AVAILABLE:
        try:
            apk = APK(path) # pyright: ignore[reportPossiblyUnboundVariable]
            result["package"] = apk.get_package() or "Unknown"
            result["version"] = apk.get_androidversion_name() or "Unknown"
            result["permissions"] = sorted(apk.get_permissions() or [])
            result["activities"] = sorted(apk.get_activities() or [])
            result["services"] = sorted(apk.get_services() or [])
            result["receivers"] = sorted(apk.get_receivers() or [])
            result["providers"] = sorted(apk.get_providers() or [])

            try:
                for comp_type, comps in [
                    ("activities", result["activities"]),
                    ("services", result["services"]),
                    ("receivers", result["receivers"])
                ]:
                    for comp in comps:
                        try:
                            data = apk.get_intent_filters(comp_type[:-1] if comp_type != "receivers" else "receiver", comp)
                            if data:
                                result["intents"].extend(list(data.keys()))
                        except Exception:
                            pass
            except Exception:
                pass
        except Exception:
            
            pass

    
    permission_points = 0
    dangerous_found = []
    for p in result["permissions"]:
        if p in DANGEROUS_PERMISSIONS:
            permission_points += DANGEROUS_PERMISSIONS[p]
            dangerous_found.append(p)

    if dangerous_found:
        for p in dangerous_found:
            result["risk_factors"].append({
                "severity": "high" if DANGEROUS_PERMISSIONS[p] >= 6 else "medium",
                "title": "Sensitive permission",
                "detail": p,
                "points": DANGEROUS_PERMISSIONS[p]
            })

    
    component_points = 0
    component_text = "\n".join(result["intents"] + result["receivers"] + result["services"])
    for indicator, pts in SUSPICIOUS_COMPONENTS.items():
        if indicator.lower() in component_text.lower() or indicator.lower() in blob.lower():
            component_points += pts
            result["risk_factors"].append({
                "severity": "high",
                "title": "Suspicious component/intent",
                "detail": indicator,
                "points": pts
            })

    api_points = 0
    api_found = []
    for api, pts in SUSPICIOUS_APIS.items():
        if api.lower() in blob.lower():
            api_found.append(api)
            api_points += pts
            result["risk_factors"].append({
                "severity": "high" if pts >= 7 else "medium",
                "title": "Suspicious API indicator",
                "detail": api,
                "points": pts
            })
    result["suspicious_apis"] = unique(api_found)
    native_libs = [n for n in names if n.endswith(".so")]
    dex_files = [n for n in names if n.endswith(".dex")]
    dynamic_points = 0
    if len(dex_files) > 1:
        dynamic_points += 4
        result["risk_factors"].append({
            "severity": "medium",
            "title": "Multiple DEX files",
            "detail": f"{len(dex_files)} DEX files present",
            "points": 4
        })
    if native_libs:
        dynamic_points += min(5, len(native_libs))
        result["risk_factors"].append({
            "severity": "low",
            "title": "Native libraries",
            "detail": f"{len(native_libs)} native .so libraries",
            "points": min(5, len(native_libs))
        })

    obfuscation_points = 0
    short_name_count = sum(
        1 for n in names
        if "/" not in n and len(os.path.splitext(n)[0]) <= 2 and os.path.splitext(n)[0]
    )
    if short_name_count >= 5:
        obfuscation_points += min(8, short_name_count)
        result["risk_factors"].append({
            "severity": "medium",
            "title": "Possible obfuscation",
            "detail": f"{short_name_count} unusually short archive names",
            "points": min(8, short_name_count)
        })

    network_points = min(10, len(result["urls"]) * 2 + len(result["ips"]) * 3)
    if network_points:
        result["risk_factors"].append({
            "severity": "medium",
            "title": "Network indicators",
            "detail": f"{len(result['urls'])} URL(s), {len(result['ips'])} IP address(es)",
            "points": network_points
        })

    
    combo_points = 0
    pset = set(result["permissions"])
    if "android.permission.RECEIVE_BOOT_COMPLETED" in pset and (
        "android.permission.INTERNET" in pset or result["urls"]
    ):
        combo_points += 7
        result["risk_factors"].append({
            "severity": "high",
            "title": "Persistence + network combination",
            "detail": "Boot persistence combined with network capability",
            "points": 7
        })
    if {"android.permission.READ_SMS", "android.permission.SEND_SMS"}.issubset(pset):
        combo_points += 10
        result["risk_factors"].append({
            "severity": "high",
            "title": "SMS access + sending combination",
            "detail": "Application can read and send SMS",
            "points": 10
        })
    if "android.permission.SYSTEM_ALERT_WINDOW" in pset and "android.permission.RECORD_AUDIO" in pset:
        combo_points += 5
        result["risk_factors"].append({
            "severity": "medium",
            "title": "Overlay + microphone combination",
            "detail": "Sensitive overlay capability combined with microphone access",
            "points": 5
        })

    cert_score = 0
    if ANDROGUARD_AVAILABLE:
        try:
            apk = APK(path) # pyright: ignore[reportPossiblyUnboundVariable]
            certs = apk.get_certificates_der_v2() or apk.get_certificates_der_v3() or apk.get_certificates()
            result["certificate_present"] = bool(certs)
        except Exception:
            result["certificate_present"] = False
    else:
        result["certificate_present"] = "META-INF/" in "\n".join(names)

    if not result["certificate_present"]:
        cert_score = 5
        result["risk_factors"].append({
            "severity": "medium",
            "title": "Certificate information unavailable",
            "detail": "Signing certificate could not be parsed by the analyzer",
            "points": 5
        })

    raw = (
        permission_points +
        component_points +
        api_points +
        dynamic_points +
        obfuscation_points +
        network_points +
        combo_points +
        cert_score
    )
    risk = min(100, raw)

    
    if risk >= 70:
        classification = "Malicious"
    elif risk >= 30:
        classification = "Suspicious"
    else:
        classification = "Safe"

    
    seen = set()
    clean = []
    for f in result["risk_factors"]:
        key = (f["title"], f["detail"])
        if key not in seen:
            seen.add(key)
            clean.append(f)
    result["risk_factors"] = clean

    result["scores"] = {
        "permissions": min(20, permission_points),
        "api_behavior": min(25, api_points),
        "components": min(15, component_points),
        "network": min(15, network_points),
        "obfuscation": min(10, obfuscation_points),
        "certificate": min(10, cert_score),
        "other": min(5, dynamic_points + combo_points),
    }
    result["risk_score"] = risk
    result["classification"] = classification
    result["summary"] = (
        "Static analysis indicates multiple potentially dangerous characteristics."
        if risk >= 70 else
        "Static analysis found characteristics that warrant additional review."
        if risk >= 30 else
        "No major suspicious indicators were detected by the current static rules."
    )
    return result
