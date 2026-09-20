#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
cron: 22 10,19 * * *
new Env('Qoder 签到')

Qoder（阿里，qoder.com.cn 国内版 / qoder.com 国际版）每日积分自动签到
· 单文件 · 零依赖（仅 Python 标准库）· 核心逻辑提取自 qoder2api-hub-main 网关

用法：
  python qoder-checkin.py login [cn|intl]   OAuth 设备授权一键免客户端登录，凭证存 auths/<uid>.json
  python qoder-checkin.py import            只读探测本机官方客户端已登录凭证（桌面 App / CLI），确认后导入
  python qoder-checkin.py list              列出 auths/ 下已保存的账号
  python qoder-checkin.py checkin           执行签到（无参数等同）：每日签到 -> Pro 福利包 -> 额度/套餐刷新

凭证：仅读取脚本同目录 auths/<uid>.json（每账号一个文件，与 Qoder2API-Hub
     账号文件同构）；登录/导入在本地执行生成，青龙部署时把该目录上传即可。
可选环境变量：
  RANDOM_SIGNIN      签到前随机延时开关（默认 true）
  MAX_RANDOM_DELAY   随机延时上限秒数（默认 3600，即最多 1 小时）
  DEBUG_HTTP         =1 时打印请求/响应调试信息

能力（提取自 qoder2api-hub-main）：
  - 双区域独立配置：国内版 (has_checkin) / 国际版（仅额度套餐）
  - OAuth 设备授权（PKCE S256，双区 URL 参数按官方差异构造）免客户端登录
  - 本机已登录凭证只读探测：桌面 App（auth.v1.dat，os_crypt/DPAPI 解出
    AES-256-GCM 密钥）与 CLI（~/.qoder*/.auth/user，AES-128-CBC）
  - 稳定物理设备指纹隔离：machine/session 按 UID 加盐哈希派生，同一账号
    长期固定同一台虚拟物理设备，多账号之间天然隔离，防跨账号关联风控
  - 每日签到与福利领取（growth campaigns 框架，2026-09 官方新版）：
    GET /sash/api/v1/me/campaigns 列出活动（需桌面宿主头 User-Agent: Qoder
    + Cosy-ClientType: 10 + Cosy-Version，缺失则服务端返回空列表），
    自动领取全部 CLAIM_BENEFIT 可领福利（每日 +100 Credits 等）；
    每日 10:00 (UTC+8) 刷新新一天活动，领取后 30 天有效
  - 实时额度（quota/usage：基础 + 赠送/签到额度聚合）与套餐（plan）查询
  - token 按前缀路由刷新：drt- -> deviceToken/refresh；jrt- -> jobToken/refresh
    （失败回落 PAT -> jobToken/exchange）；会话死亡标记自动停用账号

可选通知：脚本目录放置 notify.py（青龙面板自带）后自动发送签到结果。

免责声明：本脚本为第三方逆向脚本，与官方无关，可能违反相关产品的服务条款，
接口随时可能失效。仅供个人学习研究，请自行评估风险后使用。
"""
import base64
import datetime
import hashlib
import hmac
import json
import os
import random
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import webbrowser
from pathlib import Path

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
AUTH_DIR = BASE_DIR / "auths"

# 区域常量（逆向自官方桌面/CLI 客户端，提取自 qoder2api-hub-main）
REALM_CONFIGS = {
    "cn": {
        "name": "国内版",
        "openapi": "https://openapi.qoder.com.cn",
        "website": "https://qoder.com.cn",
        "client_id": "1c5e33e1-364d-4ce6-b02c-acaa81274a5c",
        "redirect_uri": "qoder-work-cn://",
        "domain": "qoder.com.cn",
        "ua": "QoderWork/1.1.34",
        "has_checkin": True,       # 官方：仅国内版有每日签到 (sash daily-check-in)
        "send_client_id": True,    # CN 设备授权 URL 带 client_id + machine_id + redirect_uri
        "send_redirect_uri": True,
        "nonce_dashed": True,      # CN nonce 使用带横线 uuid
        "home_dir": ".qoder-cn",   # 官方 CLI 客户端本地目录
        "app_dir": "com.qodercn.app.stable",   # 桌面 App Roaming 数据目录
    },
    "intl": {
        "name": "国际版",
        "openapi": "https://openapi.qoder.sh",
        "website": "https://qoder.com",
        "client_id": "e883ade2-e6e3-4d6d-adf7-f92ceff5fdcb",
        "redirect_uri": "qoder://aicoding.aicoding-agent/login-success",
        "domain": "qoder.com",
        "ua": "Qoder/1.1.34",
        "has_checkin": False,      # 官方：国际版无签到接口
        "send_client_id": True,    # Intl 设备授权 URL 带 client_id + machine_id（无 redirect_uri）
        "send_redirect_uri": False,
        "nonce_dashed": False,     # intl nonce 为 32-hex
        "home_dir": ".qoder",
        "app_dir": "com.qoder.app.stable",
    },
}

CLIENT_UA = "Go-http-client/2.0"
DEFAULT_USER_TYPE = "personal_professional_trial"
REFRESH_MARGIN = 24 * 3600        # 剩余不足 24h 主动刷新 token
LOGIN_TTL_SECONDS = 600           # 登录窗口最长 10 分钟
REQUEST_GAP = 1.0                 # 同账号相邻请求 >= 1s 防风控间隔
INTER_ACCOUNT_GAP = 1.5           # 账号间间隔

# 业务端点（全部挂 openapi 基址，纯 Bearer，无 COSY 签名）
PATH_DEVICE_POLL = "/api/v1/deviceToken/poll"
PATH_DEVICE_REFRESH = "/api/v1/deviceToken/refresh"
PATH_JOB_EXCHANGE = "/api/v1/jobToken/exchange"
PATH_JOB_REFRESH = "/api/v1/jobToken/refresh"
PATH_USERINFO = "/api/v1/userinfo"
PATH_QUOTA = "/api/v2/quota/usage"
PATH_PLAN = "/api/v2/user/plan"

# 每日签到（growth campaigns 框架，2026-09 官方新版；每日 10:00 UTC+8 刷新）
PATH_CAMPAIGNS = "/sash/api/v1/me/campaigns"
# campaigns 端点需桌面宿主身份头（逆向自官方桌面客户端 campaignMainService）：
# 服务端按这些头识别客户端，缺失时返回空活动列表（showCampaign=false）
DESKTOP_UA = "Qoder"
DESKTOP_CLIENT_TYPE = "10"
DESKTOP_CLIENT_VERSION = "0.3.4"

# 会话死亡标记：上游主动吊销离线会话，刷新已无意义，需要重新登录
SESSION_DEAD_MARKERS = ("TOKEN_EXPIRE", "12153", "Offline user session not found")

# 随机延时（青龙面板友好）：每个账号签到前独立随机延时，避免同时刻打卡
RANDOM_SIGNIN = os.getenv("RANDOM_SIGNIN", "true").lower() == "true"
MAX_RANDOM_DELAY = int(os.getenv("MAX_RANDOM_DELAY", "3600"))
DEBUG_HTTP = os.getenv("DEBUG_HTTP") == "1"


# ---------------------------------------------------------------------------
# 通知（青龙面板 notify.py 可选）
# ---------------------------------------------------------------------------
try:
    from notify import send as _ql_send
    _HAS_NOTIFY = True
except Exception:
    _HAS_NOTIFY = False


def notify(title: str, content: str) -> None:
    """发送青龙面板通知；无 notify.py 时仅打印。"""
    if _HAS_NOTIFY:
        try:
            _ql_send(title, content)
            print(f"📢 通知已发送: {title}")
        except Exception as e:
            print(f"⚠️  通知发送失败: {e}")
    else:
        print(f"\n📢 {title}\n📄 {content}")


# ---------------------------------------------------------------------------
# 纯标准库密码学（提取自 qoder2api-hub-main/qoder_sign.py，仅解密方向）
#   - AES-128-CBC 解密：CLI 凭证 ~/.qoder*/.auth/user
#   - AES-256-GCM 解密：桌面 App auth.v1.dat（Chromium os_crypt "v10"）
#   - Windows DPAPI：解出 Local State 中 os_crypt 保护的对称密钥
# ---------------------------------------------------------------------------
def _gmul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _rotl8(x: int, k: int) -> int:
    return ((x << k) | (x >> (8 - k))) & 0xFF


def _build_sbox() -> list:
    sbox = []
    for i in range(256):
        inv = 0
        if i:
            for x in range(1, 256):
                if _gmul(i, x) == 1:
                    inv = x
                    break
        s = inv ^ _rotl8(inv, 1) ^ _rotl8(inv, 2) ^ _rotl8(inv, 3) ^ _rotl8(inv, 4) ^ 0x63
        sbox.append(s)
    return sbox


_SBOX = _build_sbox()
assert _SBOX[0x53] == 0xED and _SBOX[0x00] == 0x63, "AES S-box self-check failed"

_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _expand_key(key: bytes) -> list:
    """AES 密钥扩展 -> 轮密钥。支持 AES-128 (16B) / AES-256 (32B)。"""
    if len(key) == 16:
        w = [list(key[i:i + 4]) for i in range(0, 16, 4)]
        for i in range(4, 44):
            t = list(w[i - 1])
            if i % 4 == 0:
                t = t[1:] + t[:1]                     # RotWord
                t = [_SBOX[b] for b in t]             # SubWord
                t[0] ^= _RCON[i // 4 - 1]
            w.append([w[i - 4][j] ^ t[j] for j in range(4)])
        n_words = 44
    elif len(key) == 32:
        w = [list(key[i:i + 4]) for i in range(0, 32, 4)]
        for i in range(8, 60):
            t = list(w[i - 1])
            if i % 8 == 0:
                t = t[1:] + t[:1]
                t = [_SBOX[b] for b in t]
                t[0] ^= _RCON[i // 8 - 1]
            elif i % 8 == 4:
                t = [_SBOX[b] for b in t]
            w.append([w[i - 8][j] ^ t[j] for j in range(4)])
        n_words = 60
    else:
        raise ValueError("aes key must be 16 or 32 bytes, got %d" % len(key))
    round_keys = []
    for r in range(n_words // 4):
        rk = []
        for c in range(4):
            rk.extend(w[r * 4 + c])
        round_keys.append(rk)
    return round_keys


def _encrypt_block(block: bytes, round_keys: list) -> bytes:
    nr = len(round_keys) - 1          # AES-128: 10, AES-256: 14
    state = list(block)
    rk0 = round_keys[0]
    state = [state[i] ^ rk0[i] for i in range(16)]

    def sub_shift(s):
        out = [0] * 16
        # 列优先状态: s[r + 4c]
        for c in range(4):
            for r in range(4):
                out[r + 4 * c] = _SBOX[s[r + 4 * ((c + r) % 4)]]
        return out

    def mix_col(s):
        out = [0] * 16
        for c in range(4):
            a = s[4 * c:4 * c + 4]
            out[4 * c + 0] = _gmul(a[0], 2) ^ _gmul(a[1], 3) ^ a[2] ^ a[3]
            out[4 * c + 1] = a[0] ^ _gmul(a[1], 2) ^ _gmul(a[2], 3) ^ a[3]
            out[4 * c + 2] = a[0] ^ a[1] ^ _gmul(a[2], 2) ^ _gmul(a[3], 3)
            out[4 * c + 3] = _gmul(a[0], 3) ^ a[1] ^ a[2] ^ _gmul(a[3], 2)
        return out

    for rnd in range(1, nr):
        state = sub_shift(state)
        state = mix_col(state)
        rk = round_keys[rnd]
        state = [state[i] ^ rk[i] for i in range(16)]
    state = sub_shift(state)
    rk = round_keys[nr]
    state = [state[i] ^ rk[i] for i in range(16)]
    return bytes(state)


_INV_SBOX = [0] * 256
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i


def _xtimes(a: int, n: int) -> int:
    """GF(2^8) 乘以常数 n（InvMixColumns 用 9/11/13/14）。"""
    r = 0
    for _ in range(8):
        if n & 1:
            r ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        n >>= 1
    return r


def _decrypt_block(block: bytes, round_keys: list) -> bytes:
    """AES 单块解密（与正向实现严格互逆；轮数由密钥长度决定）。"""
    nr = len(round_keys) - 1
    state = [block[i] ^ round_keys[nr][i] for i in range(16)]

    def inv_sub_shift(s):
        out = [0] * 16
        for c in range(4):
            for r in range(4):
                out[r + 4 * ((c + r) % 4)] = _INV_SBOX[s[r + 4 * c]]
        return out

    def inv_mix_col(s):
        out = [0] * 16
        for c in range(4):
            a = s[4 * c:4 * c + 4]
            out[4 * c + 0] = (_xtimes(a[0], 14) ^ _xtimes(a[1], 11)
                              ^ _xtimes(a[2], 13) ^ _xtimes(a[3], 9))
            out[4 * c + 1] = (_xtimes(a[0], 9) ^ _xtimes(a[1], 14)
                              ^ _xtimes(a[2], 11) ^ _xtimes(a[3], 13))
            out[4 * c + 2] = (_xtimes(a[0], 13) ^ _xtimes(a[1], 9)
                              ^ _xtimes(a[2], 14) ^ _xtimes(a[3], 11))
            out[4 * c + 3] = (_xtimes(a[0], 11) ^ _xtimes(a[1], 13)
                              ^ _xtimes(a[2], 9) ^ _xtimes(a[3], 14))
        return out

    for rnd in range(nr - 1, 0, -1):
        state = inv_sub_shift(state)
        rk = round_keys[rnd]
        state = [state[i] ^ rk[i] for i in range(16)]
        state = inv_mix_col(state)
    state = inv_sub_shift(state)
    return bytes(state[i] ^ round_keys[0][i] for i in range(16))


def aes_cbc_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-128-CBC 解密 + 严格 PKCS7 校验。用于 CLI 凭证文件读取。"""
    if len(key) != 16 or len(iv) != 16:
        raise ValueError("aes key/iv must be 16 bytes")
    if not data or len(data) % 16:
        raise ValueError("ciphertext length %d not block aligned" % len(data))
    round_keys = _expand_key(key)
    out = bytearray()
    prev = iv
    for off in range(0, len(data), 16):
        blk = data[off:off + 16]
        dec = _decrypt_block(blk, round_keys)
        out.extend(a ^ b for a, b in zip(dec, prev))
        prev = blk
    pad = out[-1]
    if pad < 1 or pad > 16 or bytes(out[-pad:]) != bytes([pad] * pad):
        raise ValueError("bad PKCS7 padding")
    return bytes(out[:-pad])


def _gf128_mul(x: int, y: int) -> int:
    """GHASH 域乘法（SP800-38D）。"""
    z, v = 0, y
    for i in range(127, -1, -1):
        if (x >> i) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ 0xE1000000000000000000000000000000
        else:
            v >>= 1
    return z


def _aes_ecb_block(block: bytes, round_keys: list) -> bytes:
    return _encrypt_block(block, round_keys)


def aes_gcm_decrypt(key: bytes, nonce: bytes, sealed: bytes) -> bytes:
    """AES-GCM 解密（key 16/32 字节），带 tag 严格校验。

    用于桌面端 auth.v1.dat（Chromium os_crypt "v10" 布局）。
    """
    if len(sealed) < 16:
        raise ValueError("gcm payload too short")
    if len(nonce) != 12:
        raise ValueError("gcm nonce must be 12 bytes")
    if len(key) not in (16, 24, 32):
        raise ValueError("gcm key must be 16/24/32 bytes")
    if len(key) == 24:
        raise ValueError("AES-192 not supported by the pure implementation")
    ct, tag = sealed[:-16], sealed[-16:]
    rks = _expand_key(key)
    base = nonce + b"\x00\x00\x00\x01"           # J0 = nonce||1
    high = int.from_bytes(base, "big") & ~0xFFFFFFFF
    low = (int.from_bytes(base[-4:], "big") + 1) & 0xFFFFFFFF
    out = bytearray()
    for off in range(0, len(ct), 16):
        ks = _aes_ecb_block((high | low).to_bytes(16, "big"), rks)
        chunk = ct[off:off + 16]
        out.extend(a ^ b for a, b in zip(chunk, ks))
        low = (low + 1) & 0xFFFFFFFF
    h = _aes_ecb_block(b"\x00" * 16, rks)
    y, hh = 0, int.from_bytes(h, "big")
    for off in range(0, len(ct), 16):
        blk = ct[off:off + 16].ljust(16, b"\x00")
        y = _gf128_mul(y ^ int.from_bytes(blk, "big"), hh)
    y = _gf128_mul(y ^ (len(ct) * 8), hh)        # lenA=0
    j0_enc = _aes_ecb_block(base, rks)
    expect = bytes(a ^ b for a, b in zip(y.to_bytes(16, "big"), j0_enc))
    if not hmac.compare_digest(expect, tag):
        raise ValueError("GCM authentication failed")
    return bytes(out)


def dpapi_unprotect(data: bytes) -> bytes:
    """Windows DPAPI CryptUnprotectData（读取 os_crypt 保护的对称密钥用）。"""
    if os.name != "nt":
        raise OSError("DPAPI 仅 Windows 可用")
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_byte))]

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    fun = crypt32.CryptUnprotectData
    fun.argtypes = [ctypes.POINTER(DATA_BLOB), wintypes.LPCWSTR,
                    ctypes.POINTER(DATA_BLOB), ctypes.c_void_p,
                    wintypes.LPVOID, wintypes.DWORD,
                    ctypes.POINTER(DATA_BLOB)]
    fun.restype = wintypes.BOOL
    in_blob = DATA_BLOB(len(data),
                        (ctypes.c_byte * len(data)).from_buffer_copy(data))
    out_blob = DATA_BLOB()
    if not fun(ctypes.byref(in_blob), None, None, None, None, 0,
               ctypes.byref(out_blob)):
        raise OSError("CryptUnprotectData failed: %d" % ctypes.get_last_error())
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        ctypes.WinDLL("kernel32").LocalFree(out_blob.pbData)


def chromium_decrypt_v10(blob: bytes, key: bytes) -> bytes:
    """解 Chromium/Electron os_crypt "v10" 载荷：v10 + nonce12 + AES-256-GCM。"""
    if blob[:3] != b"v10":
        raise ValueError("not a v10 payload")
    return aes_gcm_decrypt(key, blob[3:15], blob[15:])


# ---------------------------------------------------------------------------
# 稳定物理设备指纹隔离（提取自 qoder2api-hub-main/qoder_fingerprint.py）
#   以账号 UID 加盐哈希单向派生固定的伪物理设备特征，同一账号长期来自
#   同一台虚拟物理设备，多账号之间天然隔离，阻断跨账号关联风控。
# ---------------------------------------------------------------------------
def derive_id(uid: str, salt: str) -> str:
    """由 uid + salt 稳定派生 36 位十六进制设备/会话标识（幂等）。"""
    seed = f"{salt}:{uid or 'anonymous'}"
    return hashlib.md5(seed.encode("utf-8")).hexdigest()[:36]


def generate_request_id(uid: str) -> str:
    """生成带稳定前缀与微秒时间戳的防风控请求 ID。"""
    prefix = derive_id(uid, "req")
    suffix = str(time.time_ns() % 1000000).zfill(6)
    return f"{prefix}-{suffix}"


# ---------------------------------------------------------------------------
# 通用小工具
# ---------------------------------------------------------------------------
def get_realm_config(realm):
    return REALM_CONFIGS.get(realm) or REALM_CONFIGS["cn"]


def detect_realm_from_domain(domain):
    d = str(domain or "").lower()
    if "qoder.sh" in d or (d.endswith("qoder.com") and "qoder.com.cn" not in d) \
            or "qoder.com/" in d:
        return "intl"
    return "cn"


def session_dead(msg):
    s = str(msg or "")
    return any(m in s for m in SESSION_DEAD_MARKERS)


def normalize_epoch(value):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0
    if number > 1e11:      # 毫秒
        number /= 1000.0
    return int(number)


def parse_rfc3339(value):
    try:
        return int(datetime.datetime.strptime(str(value)[:19],
                    "%Y-%m-%dT%H:%M:%S").timestamp())
    except Exception:
        return 0


def human_delta(seconds):
    if seconds is None:
        return ""
    if seconds <= 0:
        return "已过期"
    if seconds >= 86400:
        return "%.1f 天" % (seconds / 86400)
    if seconds >= 3600:
        return "%.1f 小时" % (seconds / 3600)
    return "%d 分钟" % int(seconds / 60)


class ApiError(Exception):
    """HTTP 非 2xx：携带状态码与响应体。"""

    def __init__(self, code, body=""):
        self.code = code
        self.body = body or ""
        super().__init__("HTTP %d %s" % (code, self.body[:160]))


def http_json(url, data=None, method=None, headers=None, timeout=30,
              retries=3, backoff=1.0):
    """urlopen + json decode with retries。仅访问固定官方端点。"""
    attempts = max(1, int(retries or 1))
    last = None
    for attempt in range(1, attempts + 1):
        req = urllib.request.Request(
            url, data=data,
            method=method or ("POST" if data is not None else "GET"),
            headers=headers or {})
        if DEBUG_HTTP:
            print(f"[http] {req.method} {url}"
                  + (f" body={data[:200]!r}" if data else ""))
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = resp.status
                raw = resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read().decode("utf-8", "replace")
            except Exception:
                body = ""
            if exc.code >= 500 and attempt < attempts:
                last = exc
                if DEBUG_HTTP:
                    print(f"[http] 5xx retry {attempt}/{attempts}: {body[:120]}")
                time.sleep(backoff * attempt)
                continue
            raise ApiError(exc.code, body) from exc
        except Exception as exc:      # URLError / 超时 / TLS reset
            last = exc
            if attempt >= attempts:
                raise
            if DEBUG_HTTP:
                print(f"[http] retry {attempt}/{attempts}: {exc}")
            time.sleep(backoff * attempt)
            continue
        if DEBUG_HTTP:
            print(f"[http] <- {status} {raw[:300]}")
        try:
            return json.loads(raw) if raw.strip() else {}
        except ValueError:
            return {"_raw": raw, "_status": status}
    raise last


# ---------------------------------------------------------------------------
# 账号（提取自 qoder2api-hub-main/qoder_accounts.py 的 Account）
# ---------------------------------------------------------------------------
class QoderAccount(object):
    def __init__(self, data, path=None):
        data = data or {}
        self.path = path
        self.uid = str(data.get("uid") or "")
        self.nickname = str(data.get("nickname") or "")
        self.domain = str(data.get("domain") or "")
        self.realm = str(data.get("realm") or detect_realm_from_domain(self.domain))
        if self.realm not in REALM_CONFIGS:
            self.realm = "cn"
        if not self.domain:
            self.domain = get_realm_config(self.realm)["domain"]
        self.platform = str(data.get("platform") or "CLI")
        self.access_token = str(data.get("accessToken") or "")
        self.refresh_token = str(data.get("refreshToken") or "")
        self.personal_token = str(data.get("personalToken") or "")
        self.expires_at = normalize_epoch(data.get("expiresAt"))
        self.added_at = data.get("addedAt") or time.time()
        self.source = str(data.get("source") or "oauth")
        self.enabled = data.get("enabled", True)
        self.last_error = str(data.get("lastError") or "")
        self.credits = data.get("credits") or None
        self.plan = str(data.get("plan") or "")
        self.last_checkin = data.get("lastCheckin") or None
        self.user_type = str(data.get("userType") or "") or DEFAULT_USER_TYPE
        self.organization_id = str(data.get("organizationId") or "")
        self.organization_name = str(data.get("organizationName") or "")

    # -- 持久化 ------------------------------------------------------------
    def to_dict(self):
        return {
            "uid": self.uid,
            "nickname": self.nickname,
            "domain": self.domain,
            "realm": self.realm,
            "platform": self.platform,
            "accessToken": self.access_token,
            "refreshToken": self.refresh_token,
            "personalToken": self.personal_token,
            "expiresAt": self.expires_at,
            "addedAt": self.added_at,
            "source": self.source,
            "enabled": self.enabled,
            "lastError": self.last_error,
            "credits": self.credits,
            "plan": self.plan,
            "lastCheckin": self.last_checkin,
            "userType": self.user_type,
            "organizationId": self.organization_id,
            "organizationName": self.organization_name,
        }

    def save(self, directory=None):
        base = Path(directory) if directory else AUTH_DIR
        base.mkdir(parents=True, exist_ok=True)
        safe_uid = re.sub(r"[^A-Za-z0-9_-]", "_", str(self.uid or "")).strip("_ ")
        name = (safe_uid or uuid.uuid4().hex) + ".json"
        path = base / name
        tmp = base / (name + ".tmp")
        tmp.write_text(json.dumps(self.to_dict(), ensure_ascii=False, indent=2),
                       encoding="utf-8")
        os.replace(tmp, path)
        self.path = str(path)
        return self.path

    @property
    def display(self):
        return self.nickname or (self.uid[:8] if self.uid else "?")

    @property
    def realm_name(self):
        return get_realm_config(self.realm)["name"]

    # -- 出站头（携带稳定设备指纹） ----------------------------------------
    def headers(self):
        cfg = get_realm_config(self.realm)
        return {
            "Content-Type": "application/json",
            "Accept": "application/json, text/plain, */*",
            "User-Agent": CLIENT_UA,
            "Authorization": "Bearer " + self.access_token,
            "X-Request-ID": generate_request_id(self.uid),
            "X-Machine-ID": derive_id(self.uid, "machine"),
            "X-Session-ID": derive_id(self.uid, "session"),
            "Origin": cfg["website"],
            "Referer": cfg["website"] + "/",
        }

    # -- 刷新（按 token 前缀路由） ----------------------------------------
    def needs_refresh(self):
        if not self.expires_at:
            return False          # 未知过期时间，直接用，401 再兜底
        return self.expires_at - time.time() < REFRESH_MARGIN

    def refresh(self):
        """刷新 access token。drt- 走 deviceToken，jrt-/PAT 走 jobToken。

        PAT 永不覆盖活跃的 OAuth 会话，只做 jrt- 过期后的最终兜底。
        """
        cfg = get_realm_config(self.realm)
        base = cfg["openapi"]
        # 1) OAuth 设备族
        if self.refresh_token.startswith("drt-"):
            return self._post_token(base + PATH_DEVICE_REFRESH,
                                    {"refresh_token": self.refresh_token},
                                    kind="device")
        # 2) jobToken 族：jrt- 优先，失败回落 PAT 重新交换
        if self.refresh_token:
            if self._post_token(base + PATH_JOB_REFRESH,
                                {"refresh_token": self.refresh_token}, kind="job"):
                return True
        if self.personal_token:
            if self._post_token(base + PATH_JOB_EXCHANGE,
                                {"personal_token": self.personal_token}, kind="job"):
                return True
        if not self.refresh_token and not self.personal_token:
            self.last_error = "no refresh token; sign in again"
        return False

    def _post_token(self, url, payload, kind):
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": CLIENT_UA,
        }
        try:
            data = http_json(url, data=json.dumps(payload).encode(), method="POST",
                             headers=headers, timeout=30)
        except ApiError as exc:
            self.last_error = "refresh failed: HTTP %d %s" % (exc.code, exc.body[:160])
            if exc.code in (401, 403) and session_dead(exc.body):
                self.enabled = False
                self.last_error = "session dead (TOKEN_EXPIRE): re-login required"
            return False
        except Exception as exc:
            self.last_error = "refresh failed: %s" % exc
            return False

        if kind == "device":
            token = data.get("token") or data.get("device_token") or ""
            refresh = data.get("refresh_token") or self.refresh_token
            exp = device_expiry(data)
        else:
            token = data.get("token") or ""
            refresh = data.get("refresh_token") or self.refresh_token
            if data.get("expires_in"):
                exp = int(time.time() + int(data["expires_in"]) / 1000)
            else:
                exp = self.expires_at
        if not token:
            self.last_error = "refresh returned no token"
            return False
        self.access_token = token
        self.refresh_token = refresh
        self.expires_at = exp or self.expires_at
        self.last_error = ""
        self.enabled = True
        self.save()
        return True

    # -- 每日签到（growth campaigns 框架，仅国内版） -----------------------
    def campaigns_headers(self):
        """campaigns 端点专用头（逆向自官方桌面客户端 campaignMainService）。

        服务端按 Cosy-ClientType / User-Agent 识别客户端，缺失时返回空活动
        列表；机器身份头（Cosy-Machine*）非必需。普通业务头会被降级。
        """
        return {
            "Accept": "application/json",
            "Authorization": "Bearer " + self.access_token,
            "User-Agent": DESKTOP_UA,
            "Cosy-ClientType": DESKTOP_CLIENT_TYPE,
            "Cosy-Version": DESKTOP_CLIENT_VERSION,
        }

    def campaigns_status(self, _retried=False):
        """GET /sash/api/v1/me/campaigns -> (ok, data|error)。"""
        cfg = get_realm_config(self.realm)
        try:
            data = http_json(cfg["openapi"] + PATH_CAMPAIGNS, method="GET",
                             headers=self.campaigns_headers(), timeout=15,
                             retries=2)
        except ApiError as exc:
            # token 失效：刷新后重试一次
            if exc.code in (401, 403) and not _retried and self.refresh():
                return self.campaigns_status(_retried=True)
            return False, str(exc)
        except Exception as exc:
            return False, str(exc)
        return True, data

    def campaign_claim(self, campaign_id):
        """POST /sash/api/v1/me/campaigns/<campaignId>/claim -> 领取福利。"""
        cfg = get_realm_config(self.realm)
        url = (cfg["openapi"] + PATH_CAMPAIGNS + "/"
               + urllib.parse.quote(str(campaign_id or ""), safe="") + "/claim")
        try:
            res = http_json(url, data=b"{}", method="POST",
                            headers=self.campaigns_headers(), timeout=15,
                            retries=1)
        except ApiError as exc:
            # 409 AlreadyExists：已领取过 / 不符合条件，归一化为已领
            if exc.code == 409 or "AlreadyExists" in exc.body:
                return {"ok": True, "already": True, "msg": "已领取过"}
            return {"ok": False, "error": str(exc)}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}
        if res.get("status") == "CLAIMED":
            return {"ok": True, "msg": "领取成功", "data": res}
        if res.get("success") is False:
            return {"ok": False, "error": str(res.get("message") or res)[:160]}
        return {"ok": True, "msg": "领取成功", "data": res}

    @staticmethod
    def _campaign_title(c):
        """取活动的中文标题（placements.content.zh.title），缺则回退 key。"""
        for pl in c.get("placements") or []:
            content = pl.get("content") or {}
            for lang in ("zh", "en"):
                title = (content.get(lang) or {}).get("title")
                if title:
                    return str(title)
        return str(c.get("campaignKey") or c.get("campaignId") or "?")

    def checkin(self):
        """每日签到：列出活动 -> 领取全部 CLAIM_BENEFIT 可领福利。

        campaigns 框架每日 10:00 (UTC+8) 刷新新一天活动（act-YYYYMMDD-NNN），
        任何 CLAIM_BENEFIT 类福利（每日 +100、Pro 包等）都会被自动领取。
        返回 {ok, already, msg, earned, claimed:[{title, amount, days}]}。
        """
        if not get_realm_config(self.realm)["has_checkin"]:
            return {"ok": False, "error": "签到仅国内版开放"}
        ok, data = self.campaigns_status()
        if not ok:
            return {"ok": False, "error": data}
        campaigns = data.get("campaigns") or []
        if not campaigns:
            return {"ok": True, "already": True,
                    "msg": "当前无进行中的活动"}
        claimable = [c for c in campaigns
                     if c.get("actionType") == "CLAIM_BENEFIT"
                     and c.get("claimStatus") == "CLAIMABLE"]
        if not claimable:
            self._stamp_checkin()
            titles = [self._campaign_title(c) for c in campaigns
                      if c.get("claimStatus") == "CLAIMED"]
            return {"ok": True, "already": True, "msg": "今日活动均已领取",
                    "claimed_titles": titles}
        ok_any, earned, claimed = True, 0, []
        for c in claimable:
            benefit = c.get("benefit") or {}
            amount = int(benefit.get("amount") or 0) \
                if benefit.get("kind") == "CREDITS" else 0
            days = (benefit.get("validity") or {}).get("days")
            res = self.campaign_claim(c.get("campaignId"))
            if res.get("ok"):
                earned += amount
                claimed.append({"title": self._campaign_title(c),
                                "amount": amount, "days": days})
            else:
                ok_any = False
                claimed.append({"title": self._campaign_title(c),
                                "amount": 0, "days": days,
                                "error": res.get("error")})
        self._stamp_checkin()
        return {"ok": ok_any, "earned": earned, "claimed": claimed}

    def _stamp_checkin(self):
        self.last_checkin = time.strftime("%Y-%m-%d %H:%M:%S")
        self.save()

    # -- 额度与套餐 --------------------------------------------------------
    def fetch_credits(self):
        """GET /api/v2/quota/usage -> 聚合基础额度 + 赠送/签到额度。"""
        cfg = get_realm_config(self.realm)
        url = cfg["openapi"] + PATH_QUOTA
        try:
            q = http_json(url, method="GET", headers=self.headers(), timeout=30)
        except Exception as exc:
            return {"ok": False, "error": str(exc)}
        uq = q.get("userQuota") or {}
        aq = q.get("addOnQuota") or {}

        def _num(d, k):
            try:
                return float(d.get(k) or 0)
            except Exception:
                return 0.0

        self.credits = {
            "remain": int(_num(uq, "remaining") + _num(aq, "remaining")),
            "used": int(_num(uq, "used") + _num(aq, "used")),
            "size": int(_num(uq, "total") + _num(aq, "total")),
            "exceeded": bool(q.get("isQuotaExceeded")),
            "packages": [
                {"name": "基础额度", "remain": int(_num(uq, "remaining")),
                 "used": int(_num(uq, "used")), "size": int(_num(uq, "total"))},
                {"name": "赠送/签到额度", "remain": int(_num(aq, "remaining")),
                 "used": int(_num(aq, "used")), "size": int(_num(aq, "total"))},
            ],
            "updated_iso": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        return {"ok": True, "credits": self.credits}

    def fetch_plan(self):
        """GET /api/v2/user/plan -> 套餐名（Pro Trial 等）。"""
        cfg = get_realm_config(self.realm)
        url = cfg["openapi"] + PATH_PLAN
        try:
            p = http_json(url, method="GET", headers=self.headers(), timeout=15,
                          retries=1)
        except Exception:
            return self.plan
        name = str(p.get("plan_tier_name") or p.get("user_type") or "")
        if name and name != self.plan:
            self.plan = name
        return name


def device_expiry(data):
    """deviceToken 响应的过期时间：expires_in(ms) / expires_at(RFC3339)，默认 30 天。"""
    if data.get("expires_in"):
        return int(time.time() + int(data["expires_in"]) / 1000)
    if data.get("expires_at"):
        exp = parse_rfc3339(data["expires_at"])
        if exp:
            return exp
    return int(time.time()) + 30 * 86400


# ---------------------------------------------------------------------------
# 凭证仓库：auths/<uid>.json
# ---------------------------------------------------------------------------
def load_accounts():
    """读取 auths/*.json 全部账号，按文件排序。"""
    accounts = []
    if not AUTH_DIR.is_dir():
        return accounts
    for p in sorted(AUTH_DIR.glob("*.json")):
        if p.name.endswith(".tmp"):
            continue
        try:
            # utf-8-sig：兼容 Windows 记事本保存的 BOM 头
            data = json.loads(p.read_text(encoding="utf-8-sig"))
        except Exception as exc:
            print(f"⚠️  跳过无法解析的凭证 {p.name}: {exc}")
            continue
        if not isinstance(data, dict) or not data.get("accessToken"):
            continue
        acc = QoderAccount(data, path=str(p))
        if not acc.uid:
            acc.uid = p.stem
        accounts.append(acc)
    return accounts


def usable_accounts(accounts):
    return [a for a in accounts if a.enabled and a.access_token]


# ---------------------------------------------------------------------------
# 本机已登录凭证的只读探测与导入（提取自 qoder2api-hub-main/qoder_accounts.py）
#
# 两类官方存储：
#   1. 桌面 App（Electron）： %APPDATA%\com.qoder[.cn].app.stable\auth.v1.dat
#      布局 "v10" + AES-256-GCM；密钥在同目录 Local State 的
#      os_crypt.encrypted_key（DPAPI 保护）-> 剥 "DPAPI" 前缀 -> DPAPI 解出。
#      明文 schema: {schemaVersion, token(dt-), refreshToken(drt-), expiresAt,
#                    user:{id,name,email,...}}
#   2. CLI/官方客户端： ~/.qoder[.cn]/.auth/user[.{profile}]
#      AES-128-CBC key=iv=machine_id 前 16 字符，标准 Base64（strict padding）；
#      明文 UserInfo JSON（或明文以 "{" 开头的兼容形态）。
# 扫描全程只读；交互确认后才写入 auths/。
# ---------------------------------------------------------------------------
def _roaming_app_dir(cfg):
    base = os.environ.get("APPDATA") or os.path.join(
        os.path.expanduser("~"), "AppData", "Roaming")
    return os.path.join(base, cfg["app_dir"])


def _read_chromium_os_crypt_key(app_dir):
    """Local State.os_crypt.encrypted_key -> DPAPI 解出的 32 字节 AES key。"""
    p = os.path.join(app_dir, "Local State")
    with open(p, encoding="utf-8") as fh:
        state = json.load(fh)
    ek = (state.get("os_crypt") or {}).get("encrypted_key")
    if not ek:
        raise RuntimeError("Local State has no os_crypt.encrypted_key")
    blob = base64.b64decode(ek)
    if blob[:5] != b"DPAPI":
        raise RuntimeError("unexpected encrypted_key header %r" % blob[:5])
    return dpapi_unprotect(blob[5:])


def _load_app_auth(realm):
    """解出桌面 App auth.v1.dat 的明文 dict；失败抛异常。"""
    cfg = get_realm_config(realm)
    app_dir = _roaming_app_dir(cfg)
    key = _read_chromium_os_crypt_key(app_dir)
    with open(os.path.join(app_dir, "auth.v1.dat"), "rb") as fh:
        blob = fh.read()
    plain = chromium_decrypt_v10(blob, key)
    data = json.loads(plain.decode("utf-8"))
    if not isinstance(data, dict) or not data.get("token"):
        raise RuntimeError("auth.v1.dat has unexpected schema")
    return data


def _load_cli_user(path, machine_key):
    """解 CLI 端 ~/.qoder*/.auth/user（AES-128-CBC）或明文兼容形态。"""
    with open(path, encoding="utf-8") as fh:
        raw = fh.read().strip()
    if raw.startswith("{"):
        return json.loads(raw)
    key = (machine_key or "")[:16].encode("utf-8")
    if len(key) != 16:
        raise RuntimeError("machine_id shorter than 16 bytes")
    pt = aes_cbc_decrypt(base64.b64decode(raw), key, key)
    return json.loads(pt.decode("utf-8"))


def scan_desktop_credentials():
    """只读探测本机双区已登录凭证。返回候选列表（不含任何明文令牌）。"""
    found = []
    for realm in ("intl", "cn"):
        cfg = get_realm_config(realm)
        # 1) 桌面 App (auth.v1.dat)
        item = {
            "kind": "app",
            "path": os.path.join(_roaming_app_dir(cfg), "auth.v1.dat"),
            "file": "auth.v1.dat",
            "realm": realm,
            "realmName": cfg["name"],
            "readable": False,
            "valid": False,
            "uid": "",
            "nickname": "",
            "expiresAt": 0,
            "error": "",
        }
        try:
            data = _load_app_auth(realm)
            user = data.get("user") or {}
            item["readable"] = True
            exp = normalize_epoch(data.get("expiresAt")) or parse_rfc3339(
                data.get("expiresAt"))
            token_prefix = str(data.get("token") or "")[:3]
            item.update({
                "valid": token_prefix == "dt-" or bool(data.get("refreshToken")),
                "uid": str(user.get("id") or ""),
                "nickname": str(user.get("name") or ""),
                "expiresAt": exp,
                "expiresIn": human_delta(exp - time.time()) if exp else "未知",
            })
        except FileNotFoundError:
            item["error"] = "未找到（本机未登录或未安装该版本客户端）"
        except Exception as exc:
            item["error"] = str(exc)
        found.append(item)

        # 2) CLI 端 user / user.{profile}
        auth_dir = os.path.join(os.path.expanduser("~"), cfg["home_dir"], ".auth")
        if os.path.isdir(auth_dir):
            machine_key = ""
            try:
                with open(os.path.join(auth_dir, "machine_id"),
                          encoding="utf-8") as fh:
                    machine_key = fh.read().strip()
            except Exception:
                pass
            try:
                names = [n for n in os.listdir(auth_dir)
                         if n == "user" or n.startswith("user.")]
            except Exception:
                names = []
            for n in names:
                p = os.path.join(auth_dir, n)
                cli_item = {
                    "kind": "cli",
                    "path": p,
                    "file": n,
                    "realm": realm,
                    "realmName": cfg["name"],
                    "readable": False,
                    "valid": False,
                    "uid": "",
                    "nickname": "",
                    "expiresAt": 0,
                    "error": "",
                }
                try:
                    data = _load_cli_user(p, machine_key)
                    token = str(data.get("access_token") or "")
                    cli_item["readable"] = True
                    exp = normalize_epoch(data.get("expire_time"))
                    cli_item.update({
                        "valid": token.startswith(("dt-", "jt-")),
                        "uid": str(data.get("uid") or ""),
                        "nickname": str(data.get("name") or ""),
                        "expiresAt": exp,
                        "expiresIn": human_delta(exp - time.time()) if exp else "未知",
                    })
                except Exception as exc:
                    cli_item["error"] = str(exc)
                found.append(cli_item)
    return found


def import_desktop_credential(path, realm):
    """把扫描到的凭证写入 auths/<uid>.json。返回 QoderAccount。"""
    cfg = get_realm_config(realm)
    base = os.path.basename(path)

    token = refresh = uid = nickname = ""
    exp = 0
    if base == "auth.v1.dat":
        data = _load_app_auth(realm)
        token = str(data.get("token") or "")
        refresh = str(data.get("refreshToken") or "")
        user = data.get("user") or {}
        uid = str(user.get("id") or "")
        nickname = str(user.get("name") or "")
        exp = parse_rfc3339(data.get("expiresAt"))
    else:
        auth_dir = os.path.dirname(path)
        machine_key = ""
        try:
            with open(os.path.join(auth_dir, "machine_id"),
                      encoding="utf-8") as fh:
                machine_key = fh.read().strip()
        except Exception:
            pass
        data = _load_cli_user(path, machine_key)
        token = str(data.get("access_token") or "")
        refresh = str(data.get("refresh_token") or "")
        uid = str(data.get("uid") or "")
        nickname = str(data.get("name") or "")
        exp = normalize_epoch(data.get("expire_time"))

    if not token:
        raise RuntimeError("credential has no access token")
    if not uid:
        uid = "d-" + uuid.uuid4().hex[:24]
    account = QoderAccount({
        "uid": uid,
        "nickname": nickname or uid[:8],
        "domain": cfg["domain"],
        "realm": realm,
        "platform": "CLI",
        "accessToken": token,
        "refreshToken": refresh,
        "expiresAt": exp or (int(time.time()) + 30 * 86400),
        "source": "desktop-app",
        "enabled": True,
    })
    account.save()
    return account


def do_import():
    """只读探测本机已登录凭证，交互确认后导入 auths/。"""
    print("== Qoder 本机凭证探测（只读） ==")
    items = scan_desktop_credentials()
    for it in items:
        where = "桌面App" if it["kind"] == "app" else "CLI"
        state = "✔ 有效" if it["valid"] else ("✖ " + (it["error"] or "无效"))
        print(f"  [{it['realmName']}·{where}] {it['file']}"
              f"  uid={it['uid'] or '-'}  {it['nickname'] or '-'}"
              f"  过期={it.get('expiresIn') or '-'}  {state}")
    valid = [i for i in items if i.get("valid")]
    if not valid:
        print("\n⚠️  未探测到有效凭证。请先安装/登录官方 Qoder 客户端，或使用 login 命令。")
        return 1
    try:
        if not sys.stdin.isatty():
            print("\n⚠️  非交互环境，仅探测不导入。请在本地终端执行 import。")
            return 1
        ans = input(f"\n导入以上 {len(valid)} 个有效凭证到 auths/ ？[y/N]: ").strip().lower()
    except EOFError:
        print("\n⚠️  非交互环境，仅探测不导入。请在本地终端执行 import。")
        return 1
    if ans not in ("y", "yes"):
        print("已取消。")
        return 1
    imported, errors = [], []
    for it in valid:
        try:
            acc = import_desktop_credential(it["path"], it["realm"])
            imported.append(acc)
            print(f"✓ 已导入 [{acc.display}] ({acc.realm_name}) -> {acc.path}")
        except Exception as exc:
            errors.append("%s/%s: %s" % (it["realm"], it["file"], exc))
            print(f"! 导入失败 {it['file']}: {exc}")
    if errors:
        return 2
    print(f"\n✅ 共导入 {len(imported)} 个账号，可执行 checkin 签到。")
    return 0


# ---------------------------------------------------------------------------
# OAuth 设备授权一键免客户端登录（提取自 qoder2api-hub-main/qoder_accounts.py）
#   PKCE (S256) 设备流。双区 URL 参数差异（官方逆向）：
#     CN   : challenge, challenge_method, nonce(带横线), redirect_uri,
#            client_id, machine_id
#     Intl : challenge, challenge_method, nonce(32-hex), client_id,
#            machine_id（无 redirect_uri）
# ---------------------------------------------------------------------------
def _make_pkce():
    """RFC 7636 S256: (verifier, challenge)。"""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    raw = os.urandom(64)
    verifier = "".join(alphabet[b % len(alphabet)] for b in raw)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return verifier, challenge


def _local_machine_id(realm):
    """读取本机官方客户端的 machine_id（优先，保持设备一致），缺则生成。"""
    cfg = get_realm_config(realm)
    p = os.path.join(os.path.expanduser("~"), cfg["home_dir"], ".auth",
                     "machine_id")
    try:
        with open(p, encoding="utf-8") as fh:
            mid = fh.read().strip()
        if mid:
            return mid
    except Exception:
        pass
    return str(uuid.uuid4())


def _build_login(realm):
    cfg = get_realm_config(realm)
    verifier, challenge = _make_pkce()
    nonce = str(uuid.uuid4()) if cfg["nonce_dashed"] else uuid.uuid4().hex
    q = {
        "challenge": challenge,
        "challenge_method": "S256",
        "nonce": nonce,
    }
    if cfg.get("send_redirect_uri"):
        q["redirect_uri"] = cfg["redirect_uri"]
    if cfg.get("send_client_id"):
        q["client_id"] = cfg["client_id"]
        q["machine_id"] = _local_machine_id(realm)
    auth_url = cfg["website"] + "/device/selectAccounts?" + urllib.parse.urlencode(q)
    return {"verifier": verifier, "nonce": nonce, "authUrl": auth_url}


def _poll_login(realm, info):
    """轮询 deviceToken/poll。返回 (status, message, data)。"""
    cfg = get_realm_config(realm)
    q = urllib.parse.urlencode({
        "nonce": info["nonce"],
        "verifier": info["verifier"],
        "challenge_method": "S256",
    })
    url = cfg["openapi"] + PATH_DEVICE_POLL + "?" + q
    if DEBUG_HTTP:
        print(f"[http] GET {url}")
    req = urllib.request.Request(url, method="GET", headers={
        "Accept": "application/json",
        "User-Agent": "QoderWork",
    })
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            status = resp.status
            raw = resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        # 404 / 202 = 用户尚未完成授权（继续轮询）
        if exc.code in (404, 202):
            return "pending", "等待浏览器完成授权", None
        try:
            body = exc.read().decode("utf-8", "replace")
        except Exception:
            body = ""
        return "error", "poll http %d %s" % (exc.code, body[:160]), None
    except Exception as exc:
        return "pending", "poll error: %s" % exc, None
    if status in (404, 202):
        return "pending", "等待浏览器完成授权", None
    try:
        data = json.loads(raw)
    except Exception:
        return "pending", "waiting for grant", None
    token = data.get("token") or data.get("device_token") or ""
    if not token:
        return "pending", "waiting for token", None
    return "ok", "authorized", data


def do_login(realm_arg=None):
    """OAuth 设备授权登录：打印授权 URL -> 浏览器完成 -> 轮询拿 token -> 入库。"""
    realm = str(realm_arg or "").strip().lower()
    if realm not in REALM_CONFIGS:
        try:
            if sys.stdin.isatty():
                pick = input("选择区域: [1] 国内版(cn)  [2] 国际版(intl)  默认 1: ").strip()
                realm = "intl" if pick == "2" else "cn"
            else:
                realm = "cn"
        except EOFError:
            realm = "cn"
    cfg = get_realm_config(realm)
    print(f"== Qoder 登录（{cfg['name']} · OAuth 设备授权，免客户端） ==")

    info = _build_login(realm)
    print("\n请在浏览器完成账号授权（最长等待 10 分钟）：")
    print(f"  {info['authUrl']}\n")
    try:
        webbrowser.open(info["authUrl"])
    except Exception:
        pass

    deadline = time.time() + LOGIN_TTL_SECONDS
    last_print = 0
    while time.time() < deadline:
        status, message, data = _poll_login(realm, info)
        if status == "ok":
            break
        if status == "error":
            print(f"❌ {message}")
            return 1
        now = time.time()
        if now - last_print >= 15:
            print(f"  ... {message}")
            last_print = now
        time.sleep(3)
    else:
        print("❌ 登录超时，请重试。")
        return 1

    token = data.get("token") or data.get("device_token") or ""
    uid = str(data.get("user_id") or "")
    nickname = ""
    user_type, org_id, org_name = DEFAULT_USER_TYPE, "", ""
    # 拉取 userinfo 补全昵称/用户类型（尽力而为，不阻塞入库）
    try:
        ui = http_json(cfg["openapi"] + PATH_USERINFO, method="GET", headers={
            "Accept": "application/json",
            "User-Agent": CLIENT_UA,
            "Authorization": "Bearer " + token,
        }, timeout=15, retries=2)
        uid = str(ui.get("id") or uid)
        nickname = str(ui.get("name") or "")
        user_type = str(ui.get("user_type") or "") or DEFAULT_USER_TYPE
        org_id = str(ui.get("organization_id") or "")
        org_name = str(ui.get("organization_name") or "")
    except Exception:
        pass

    account = QoderAccount({
        "uid": uid or ("q-" + uuid.uuid4().hex[:24]),
        "nickname": nickname or ("u" + (uid[-8:] if uid else "")),
        "domain": cfg["domain"],
        "realm": realm,
        "platform": "CLI",
        "accessToken": token,
        "refreshToken": data.get("refresh_token") or "",
        "expiresAt": device_expiry(data),
        "source": "oauth",
        "enabled": True,
        "userType": user_type,
        "organizationId": org_id,
        "organizationName": org_name,
    })
    account.save()
    print("\n✅ 登录成功")
    print(f"   用户: {account.display} ({cfg['name']})")
    print(f"   凭证: {account.path}")
    print(f"   Token 有效期: {human_delta((account.expires_at or 0) - time.time())}"
          "（refreshToken 可自动续期）")
    return 0


# ---------------------------------------------------------------------------
# 签到（青龙模式）
# ---------------------------------------------------------------------------
def _fmt_seconds(seconds):
    """把秒数格式化为时/分/秒，便于倒计时展示。"""
    if seconds <= 0:
        return "立即执行"
    h, rem = divmod(int(seconds), 3600)
    m, s = divmod(rem, 60)
    if h > 0:
        return f"{h}小时{m}分{s}秒"
    if m > 0:
        return f"{m}分{s}秒"
    return f"{s}秒"


def _random_delay(label=""):
    """每个账号签到前独立随机延时，带倒计时打印，避免青龙面板判定任务卡死。"""
    if not RANDOM_SIGNIN or MAX_RANDOM_DELAY <= 0:
        return
    who = f"[{label}] " if label else ""
    delay = random.randint(0, MAX_RANDOM_DELAY)
    print(f"{who}⏳ 随机延时 {_fmt_seconds(delay)} 后开始签到")
    remaining = delay
    while remaining > 0:
        if remaining <= 10 or remaining % 10 == 0:
            print(f"   倒计时: {_fmt_seconds(remaining)}")
        step = 1 if remaining <= 10 else min(10, remaining)
        time.sleep(step)
        remaining -= step
    print(f"{who}随机延时结束，开始签到")


def run_account(acc, do_delay=True):
    """单账号签到闭环：token 保活 -> 签到 -> Pro 福利 -> 额度/套餐。"""
    name = f"{acc.display} · {acc.realm_name}"
    lines = []

    def log(msg):
        print(f"  {msg}")
        lines.append(msg)

    print(f"\n[{name}]")
    if do_delay:
        _random_delay(name)

    if not acc.access_token:
        log("! 无 accessToken，请重新 login / import")
        return {"ok": False, "name": name, "lines": lines, "earned": 0}

    # -- token 保活：临期先刷新 --
    if acc.needs_refresh():
        print("  Token 临期，尝试刷新...")
        if not acc.refresh():
            log(f"! Token 刷新失败: {acc.last_error}（请重新登录）")
            acc.save()
            return {"ok": False, "name": name, "lines": lines, "earned": 0}
        log(f"✓ Token 已刷新，剩余 {human_delta(acc.expires_at - time.time())}")
    elif not acc.expires_at:
        log("— Token 过期时间未知，直接尝试签到（401 将自动刷新重试）")

    ok_any, earned = True, 0

    # -- 每日签到（campaigns 框架，仅国内版；官方能力门控） --
    if get_realm_config(acc.realm)["has_checkin"]:
        r = acc.checkin()
        if r.get("ok"):
            if r.get("claimed"):
                for item in r["claimed"]:
                    if item.get("error"):
                        ok_any = False
                        log(f"! [{item['title']}] 领取失败: {item['error']}")
                    else:
                        extra = f"，{item['days']} 天有效" if item.get("days") else ""
                        log(f"✓ [{item['title']}] +{item['amount']} 积分{extra}")
                earned += r.get("earned") or 0
            elif r.get("already"):
                titles = "、".join(r.get("claimed_titles") or [])
                log(f"✓ {r.get('msg')}" + (f"（{titles}）" if titles else ""))
            else:
                log(f"— {r.get('msg')}")
        else:
            ok_any = False
            log(f"! 签到失败: {r.get('error')}")

        time.sleep(REQUEST_GAP)
    else:
        log("— 国际版官方无签到/福利接口，仅刷新额度与套餐")

    time.sleep(REQUEST_GAP)

    # -- 额度与套餐 --
    c = acc.fetch_credits()
    if c.get("ok"):
        cr = acc.credits or {}
        pkgs = cr.get("packages") or []
        detail = " / ".join(
            f"{p.get('name')} {p.get('remain')}" for p in pkgs[:2]) or "-"
        log(f"额度余额: {cr.get('remain')}（{detail}，已用 {cr.get('used')}）"
            + ("  ⚠️ 已超额" if cr.get("exceeded") else ""))
    else:
        log(f"! 额度查询失败: {c.get('error')}")
    acc.fetch_plan()
    if acc.plan:
        log(f"套餐: {acc.plan}")

    acc.save()
    return {"ok": ok_any, "name": name, "lines": lines, "earned": earned}


def do_checkin():
    all_accounts = load_accounts()
    accounts = usable_accounts(all_accounts)
    skipped = len(all_accounts) - len(accounts)
    if not accounts:
        msg = "auths/ 下没有可用账号。请先执行 login（OAuth 设备授权）或 import（导入本机凭证）。"
        print(f"⚠️  {msg}")
        notify("Qoder 签到", f"⚠️ {msg}")
        return 1

    print(f"== Qoder 签到  共 {len(accounts)} 个账号"
          + (f"（跳过 {skipped} 个禁用/无效）" if skipped else "") + " ==")
    all_ok, total_earned, lines = True, 0, []
    for i, acc in enumerate(accounts):
        try:
            res = run_account(acc)
        except Exception as exc:
            res = {"ok": False, "name": acc.display, "earned": 0,
                   "lines": [f"! 发生异常: {exc}"]}
            print(f"  ! 发生异常: {exc}")
        all_ok = all_ok and res["ok"]
        total_earned += res.get("earned") or 0
        lines.append(f"[{res['name']}]")
        lines.extend("  " + l for l in res.get("lines") or [])
        if i < len(accounts) - 1:
            time.sleep(INTER_ACCOUNT_GAP)

    summary = "\n".join(lines) + f"\n\n累计新增积分: +{total_earned}"
    print("\n== 完成 ==")
    notify("Qoder 签到完成", summary)
    return 0 if all_ok else 2


def do_list():
    accounts = load_accounts()
    if not accounts:
        print(f"auths/（{AUTH_DIR}）下没有账号。")
        return 1
    print(f"== Qoder 账号  共 {len(accounts)} 个 ==")
    for acc in accounts:
        state = "启用" if acc.enabled else "停用"
        print(f"  [{acc.display}] {acc.realm_name}  {state}"
              f"  Token剩余={human_delta(acc.expires_at - time.time()) if acc.expires_at else '未知'}"
              f"  套餐={acc.plan or '-'}"
              f"  额度={(acc.credits or {}).get('remain', '-')}"
              f"  文件={os.path.basename(acc.path) if acc.path else '-'}")
    return 0


def usage():
    print(__doc__)
    print("用法:")
    print("  python qoder-checkin.py login [cn|intl]  OAuth 设备授权登录并保存凭证")
    print("  python qoder-checkin.py import           探测并导入本机已登录凭证")
    print("  python qoder-checkin.py list             列出已保存账号")
    print("  python qoder-checkin.py checkin          执行签到（默认，可不带参数）")
    return 1


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "checkin"
    if cmd == "login":
        return do_login(sys.argv[2] if len(sys.argv) > 2 else None)
    if cmd == "import":
        return do_import()
    if cmd == "list":
        return do_list()
    if cmd == "checkin":
        return do_checkin()
    return usage()


if __name__ == "__main__":
    sys.exit(main())
