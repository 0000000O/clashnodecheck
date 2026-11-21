"""经由指定 HTTP 代理检测 YouTube 自动生成字幕（ASR）翻译为简体中文的可用性。

检测流程（纯 Python 标准库，单节点每次实时拉取字幕轨，不跨节点复用 baseUrl）：
  1. 请求带有稳定英文 ASR 自动生成字幕的公开 YouTube 播放页（默认 dQw4w9WgXcQ，可配置）；
     携带 Chrome UA、Accept-Language（默认不塞固定 SOCS Cookie，仅在命中欧区 GDPR 同意墙时补带 SOCS 重试一次）；
  2. 从 HTML 解析 captionTracks，严格筛选 kind == "asr" 的自动生成字幕轨（优先英文，不误取人工轨）；
  3. 对该 asr 轨的 baseUrl 拼接 &tlang=zh-Hans&fmt=json3，附带 Origin / Referer 发 1 次探测请求：
     - HTTP 200 且非异常 HTML 页（即使无 PO Token 返回空响应体 len=0 也属正常） -> ok（可用）
     - HTTP 429 或命中 Google Sorry / /sorry/ 限流页                          -> rate_limited（429 限流）
     - 播放页或字幕接口触发 403/451、LOGIN_REQUIRED / bot 验证 / 验证码拦截     -> blocked（被拦截）
     - 超时、代理异常、未提取到 asr 轨或其他异常                                -> error（检测失败）

可单独运行：
  python youtube.py http://127.0.0.1:7897 [可选_视频ID]
"""
from __future__ import annotations

import gzip
import http.cookiejar
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib

DEFAULT_VIDEO_ID = "dQw4w9WgXcQ"
TARGET_LANG = "zh-Hans"

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
)
SOCS_VALUE = "CAISOAgBEitib3FfaWRlbnRpdHlmcm9udGVuZHVpc2VydmVyXzIwMjQwODExLjA4X3AwGgJlbiACGgYIgOfvtQY"

STATUS_LABELS = {
    "ok": "可用",
    "rate_limited": "429 限流",
    "blocked": "被拦截",
    "error": "检测失败",
}

_SORRY_MARKERS = (
    "<title>sorry",
    "our systems have detected unusual traffic",
    "unusual traffic from your computer network",
    "/sorry/index",
)
_BOT_BLOCK_MARKERS = (
    "sign in to confirm you're not a bot",
    "sign in to confirm you’re not a bot",
    "sign in to confirm you&#39;re not a bot",
    'id="captcha-form"',
)
_VIDEO_ID_RE = re.compile(r"^[A-Za-z0-9_-]{11}$")


def normalize_video_id(raw: str | None) -> str:
    """支持直接填 11 位视频 ID 或完整 YouTube URL，空值回退到默认视频 ID。"""
    s = (raw or "").strip()
    if not s:
        return DEFAULT_VIDEO_ID
    if _VIDEO_ID_RE.match(s):
        return s
    try:
        u = urllib.parse.urlparse(s if "://" in s else "https://" + s)
        host = (u.hostname or "").lower()
        if "youtu.be" in host:
            cand = u.path.strip("/").split("/")[0]
            if cand:
                return cand
        if "youtube.com" in host or "youtube-nocookie.com" in host:
            qs = urllib.parse.parse_qs(u.query)
            if qs.get("v"):
                return qs["v"][0]
            parts = [p for p in u.path.split("/") if p]
            if len(parts) >= 2 and parts[0] in ("shorts", "embed", "live", "v"):
                return parts[1]
    except Exception:
        pass
    return s


def _build_opener(proxy_url: str | None, with_socs: bool = False):
    """为单次节点检测创建独立 opener（不读取系统代理；仅在需要跳过 GDPR 同意墙时注入 SOCS Cookie）。"""
    jar = http.cookiejar.CookieJar()
    if with_socs:
        for domain in (".youtube.com", ".google.com"):
            jar.set_cookie(http.cookiejar.Cookie(
                version=0, name="SOCS", value=SOCS_VALUE,
                port=None, port_specified=False,
                domain=domain, domain_specified=True, domain_initial_dot=True,
                path="/", path_specified=True,
                secure=True, expires=None, discard=True,
                comment=None, comment_url=None, rest={}, rfc2109=False,
            ))
    handlers = [
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.ProxyHandler(
            {"http": proxy_url, "https": proxy_url} if proxy_url else {}
        ),
    ]
    return urllib.request.build_opener(*handlers)


def _is_consent_url(url: str) -> bool:
    u = url.lower()
    return "consent.youtube.com" in u or "consent.google.com" in u


def _decode_bytes(resp) -> bytes:
    raw = resp.read()
    enc = (resp.headers.get("Content-Encoding") or "").lower()
    if enc == "gzip":
        raw = gzip.decompress(raw)
    elif enc == "deflate":
        raw = zlib.decompress(raw)
    return raw


def _request(
    opener,
    url: str,
    timeout: float,
    headers: dict[str, str],
) -> tuple[int, str, dict[str, str], bytes, int, str | None]:
    """发单次 GET，返回 (http_code, final_url, lower_headers, body_bytes, latency_ms, err)。"""
    req = urllib.request.Request(url, headers=headers, method="GET")
    t0 = time.perf_counter()
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = _decode_bytes(resp)
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, resp.geturl(), hdrs, raw, int((time.perf_counter() - t0) * 1000), None
    except urllib.error.HTTPError as e:
        raw = b""
        try:
            raw = _decode_bytes(e)
        except Exception:
            pass
        hdrs = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
        return e.code, e.geturl(), hdrs, raw, int((time.perf_counter() - t0) * 1000), None
    except Exception as e:
        return 0, url, {}, b"", int((time.perf_counter() - t0) * 1000), f"{type(e).__name__}: {e}"


def _extract_json_field(html: str, key: str, expected_type: type):
    """在 YouTube HTML 中定位 `"key":` 并用 raw_decode 安全解码对应 JSON 结构。"""
    token = f'"{key}":'
    dec = json.JSONDecoder()
    pos = 0
    while True:
        idx = html.find(token, pos)
        if idx == -1:
            return None
        start = idx + len(token)
        while start < len(html) and html[start] in " \t\r\n":
            start += 1
        try:
            obj, _ = dec.raw_decode(html, start)
            if isinstance(obj, expected_type):
                return obj
        except Exception:
            pass
        pos = start


def _pick_asr_track(tracks: list) -> dict | None:
    """严格筛选 kind == 'asr' 的自动生成字幕轨（优先英文，不取人工字幕轨）。"""
    asr_tracks = [
        t for t in tracks
        if isinstance(t, dict) and t.get("kind") == "asr" and t.get("baseUrl")
    ]
    if not asr_tracks:
        return None
    for t in asr_tracks:
        if str(t.get("languageCode") or "").lower().startswith("en"):
            return t
    return asr_tracks[0]


def _build_translate_url(base_url: str, target_lang: str = TARGET_LANG) -> str:
    """保留原始 baseUrl 签名参数原样，仅追加 tlang 与 fmt=json3。"""
    url = base_url.strip()
    if url.startswith("/"):
        url = "https://www.youtube.com" + url
    existing = {k.lower() for k, _ in urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query)}
    extras = []
    if "tlang" not in existing:
        extras.append(f"tlang={urllib.parse.quote(target_lang, safe='-')}")
    if "fmt" not in existing:
        extras.append("fmt=json3")
    if not extras:
        return url
    sep = "&" if "?" in url else "?"
    return url + sep + "&".join(extras)


def _is_sorry(code: int, final_url: str, body_lower: str) -> bool:
    if code == 429 or "/sorry/" in final_url.lower():
        return True
    return any(m in body_lower for m in _SORRY_MARKERS)


def _is_bot_block(body_lower: str) -> bool:
    return any(m in body_lower for m in _BOT_BLOCK_MARKERS)


def _result(status: str, code: int, detail: str, total_ms: int, extra: dict) -> dict:
    extra["status"] = status
    extra["label"] = STATUS_LABELS.get(status, status)
    extra["http_status"] = code
    extra["detail"] = detail
    extra["latency_ms"] = total_ms
    return {
        "yt_translate_status": status,
        "yt_translate_code": code,
        "yt_translate_detail": detail,
        "yt_translate_ms": total_ms,
        "yt_translate_extra": extra,
    }


def check(
    proxy_url: str | None,
    timeout: float = 12.0,
    video_id: str = DEFAULT_VIDEO_ID,
) -> dict:
    """经由 proxy_url 检测 YouTube ASR 字幕自动翻译（简体中文）可用性。"""
    vid = normalize_video_id(video_id)
    watch_url = f"https://www.youtube.com/watch?v={urllib.parse.quote(vid, safe='')}"
    opener = _build_opener(proxy_url, with_socs=False)
    t0 = time.perf_counter()

    extra: dict = {
        "video_id": vid,
        "target_lang": TARGET_LANG,
        "watch": {},
        "track": None,
        "timedtext": {},
    }

    # ------------------------------------------------------------------ 1. 拉取播放页
    watch_headers = {
        "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Cache-Control": "no-cache",
    }
    w_code, w_url, w_hdrs, w_raw, w_ms, w_err = _request(opener, watch_url, timeout, headers=watch_headers)

    # 仅在欧洲/EEA 等节点命中 GDPR 同意墙时补带 SOCS Cookie 重试一次，避免非欧区发送固定 SOCS
    socs_retry = False
    if not w_err and _is_consent_url(w_url):
        socs_retry = True
        opener = _build_opener(proxy_url, with_socs=True)
        w_code2, w_url2, w_hdrs2, w_raw2, w_ms2, w_err2 = _request(opener, watch_url, timeout, headers=watch_headers)
        w_code, w_url, w_hdrs, w_raw, w_err = w_code2, w_url2, w_hdrs2, w_raw2, w_err2
        w_ms += w_ms2

    extra["watch"] = {"http_status": w_code, "latency_ms": w_ms, "final_url": w_url[:120]}
    if socs_retry:
        extra["watch"]["socs_retry"] = True

    if w_err:
        total_ms = int((time.perf_counter() - t0) * 1000)
        return _result("error", 0, f"播放页请求失败: {w_err}", total_ms, extra)

    w_html = w_raw.decode("utf-8", "replace")
    w_lower = w_html.lower()

    if _is_sorry(w_code, w_url, w_lower):
        total_ms = int((time.perf_counter() - t0) * 1000)
        return _result("rate_limited", w_code, f"播放页触发限流/Sorry (HTTP {w_code})", total_ms, extra)

    if w_code in (403, 451):
        total_ms = int((time.perf_counter() - t0) * 1000)
        return _result("blocked", w_code, f"播放页拒绝访问 (HTTP {w_code})", total_ms, extra)

    if _is_consent_url(w_url):
        total_ms = int((time.perf_counter() - t0) * 1000)
        return _result("blocked", w_code, "播放页被重定向至 GDPR 同意墙", total_ms, extra)

    playability = _extract_json_field(w_html, "playabilityStatus", dict) or {}
    p_status = str(playability.get("status") or "")
    p_reason = str(playability.get("reason") or "")
    if p_status:
        extra["watch"]["playability"] = p_status
        if p_reason:
            extra["watch"]["reason"] = p_reason[:120]

    if p_status == "LOGIN_REQUIRED" or _is_bot_block(p_reason.lower()) or _is_bot_block(w_lower):
        total_ms = int((time.perf_counter() - t0) * 1000)
        msg = p_reason[:80] if p_reason else "LOGIN_REQUIRED / 人机验证"
        return _result("blocked", w_code, f"播放页风控拦截: {msg}", total_ms, extra)

    if w_code != 200:
        total_ms = int((time.perf_counter() - t0) * 1000)
        return _result("error", w_code, f"播放页异常 HTTP {w_code}", total_ms, extra)

    tracks = _extract_json_field(w_html, "captionTracks", list) or []
    asr = _pick_asr_track(tracks)
    if not asr:
        total_ms = int((time.perf_counter() - t0) * 1000)
        if p_status and p_status != "OK":
            return _result("error", w_code, f"视频不可播放 ({p_status}: {p_reason[:60]})", total_ms, extra)
        return _result(
            "error",
            w_code,
            f"未提取到 ASR 自动生成字幕轨（视频 {vid}，共 {len(tracks)} 条非 ASR 轨）",
            total_ms,
            extra,
        )

    extra["track"] = {
        "languageCode": asr.get("languageCode") or "",
        "kind": asr.get("kind") or "",
        "vssId": asr.get("vssId") or "",
        "isTranslatable": bool(asr.get("isTranslatable")),
    }

    # ------------------------------------------------------------------ 2. 探测自动翻译接口
    t_url = _build_translate_url(asr["baseUrl"], TARGET_LANG)
    t_code, t_final, t_hdrs, t_raw, t_ms, t_err = _request(
        opener,
        t_url,
        timeout,
        headers={
            "User-Agent": UA,
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
            "Origin": "https://www.youtube.com",
            "Referer": watch_url,
            "Cache-Control": "no-cache",
        },
    )
    total_ms = int((time.perf_counter() - t0) * 1000)

    acao = t_hdrs.get("access-control-allow-origin", "")
    ct = t_hdrs.get("content-type", "")
    body_len = len(t_raw)
    extra["timedtext"] = {
        "http_status": t_code,
        "latency_ms": t_ms,
        "acao": acao,
        "has_acao": bool(acao),
        "content_type": ct,
        "body_len": body_len,
    }

    if t_err:
        return _result("error", 0, f"字幕翻译请求失败: {t_err}", total_ms, extra)

    t_text = t_raw.decode("utf-8", "replace") if body_len else ""
    t_lower = t_text.lower()

    if _is_sorry(t_code, t_final, t_lower):
        acao_note = "缺失 ACAO 头" if not acao else f"ACAO={acao}"
        return _result("rate_limited", t_code, f"HTTP {t_code} 限流（Google Sorry，{acao_note}）", total_ms, extra)

    if t_code in (403, 451) or _is_bot_block(t_lower):
        return _result("blocked", t_code, f"字幕翻译被风控拦截 (HTTP {t_code})", total_ms, extra)

    if t_code == 200:
        if body_len == 0:
            acao_note = "ACAO✓" if acao else "无 ACAO"
            return _result("ok", 200, f"支持翻译 (HTTP 200, 空响应/无PO Token, {acao_note})", total_ms, extra)

        stripped = t_lower.lstrip()
        is_html = ("text/html" in ct.lower()) or stripped.startswith("<html") or stripped.startswith("<!doctype html")
        if is_html:
            if "consent.youtube.com" in t_final.lower() or "consent.google.com" in t_final.lower():
                return _result("blocked", 200, "字幕接口被重定向至同意页", total_ms, extra)
            return _result("error", 200, f"字幕接口返回异常 HTML 页面 ({body_len}B)", total_ms, extra)

        acao_note = "ACAO✓" if acao else "无 ACAO"
        return _result("ok", 200, f"支持翻译 (HTTP 200, {body_len}B, {acao_note})", total_ms, extra)

    return _result("error", t_code, f"字幕接口异常 HTTP {t_code}", total_ms, extra)


def format_summary(y: dict) -> str:
    """供运行日志使用的单行摘要。"""
    st = y.get("yt_translate_status") or ""
    if not st:
        return ""
    label = STATUS_LABELS.get(st, st)
    code = y.get("yt_translate_code")
    if st == "ok":
        return f"{label}(200)"
    if st == "rate_limited":
        return f"{label}" if code == 429 else f"{label}({code})"
    if code:
        return f"{label}({code})"
    return label


if __name__ == "__main__":
    import sys

    proxy = sys.argv[1] if len(sys.argv) > 1 else None
    vid = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_VIDEO_ID
    print(json.dumps(check(proxy, video_id=vid), ensure_ascii=False, indent=2))
