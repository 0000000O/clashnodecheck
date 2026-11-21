"""经由指定 HTTP 代理检测节点的 Gemini 支持程度。

并发执行 4 项轻量探测（仅依赖 Python 标准库，每次请求使用独立连接）：
  1. Gemini 网页版 (gemini.google.com) —— 提取 Google 自身判定的出口国家/地区并检查是否拦截或提示不支持；
  2. Google 风控检测 (www.google.com/search) —— 检查该出口 IP 是否触发 429 / Sorry 人机验证，同时作为 Google 识别地区的兜底来源；
  3. Google AI Studio (aistudio.google.com) —— 检查是否重定向至地区不支持页面或被拦截；
  4. Gemini API (generativelanguage.googleapis.com) ——
       - 未填 API Key：探测 API 网关可达性与地区拦截；
       - 填写 API Key：通过 x-goog-api-key 发送极简请求 (maxOutputTokens=1) 实测该出口是否被
         `User location is not supported for the API use` 拒绝。

综合输出分级 (`gemini_level`)：
  - full        完全支持（网页可用 + 地区支持 + 无 Google 风控 + AI Studio/API 正常）
  - risk        可用(风控)（Gemini 网页可用，但 Google 搜索触发验证码/429 风控）
  - web_only    仅网页可用（Gemini 网页可用，但 API 实测或 AI Studio 被地区/机房拒绝）
  - unsupported 地区不支持（Google 将该出口判为 CN/HK/MO/RU 等不支持地区，或返回地区不支持）
  - blocked     被拦截（Gemini 本身返回 403/451 或直接触发人机验证拦截）
  - error       检测失败（网络超时、代理错误等）

可单独运行：
  python gemini.py http://127.0.0.1:7897 [可选_API_KEY]
"""
from __future__ import annotations

import concurrent.futures
import gzip
import http.cookiejar
import json
import re
import time
import urllib.error
import urllib.request
import zlib

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
)
# 用于跳过欧洲/EEA 节点的 Google GDPR 隐私同意墙（不含任何会话/地区标记）
SOCS_COOKIE = (
    "SOCS=CAISOAgBEitib3FfaWRlbnRpdHlmcm9udGVuZHVpc2VydmVyXzIwMjQwODExLjA4X3AwGgJlbiACGgYIgOfvtQY"
)
DEFAULT_API_MODEL = "gemini-3.5-flash-lite"

LEVEL_LABELS = {
    "full": "完全支持",
    "risk": "可用(风控)",
    "web_only": "仅网页可用",
    "unsupported": "地区不支持",
    "blocked": "被拦截",
    "error": "检测失败",
}

# 官方 Google AI Studio / Gemini API & Gemini 支持国家/地区（ISO 3166-1 alpha-2）
# 不含 CN, HK, MO, RU, BY, KP, IR, SY, CU, AF 等受限地区
SUPPORTED_COUNTRIES = frozenset({
    "AD", "AE", "AG", "AI", "AL", "AM", "AO", "AQ", "AR", "AS", "AT", "AU", "AW", "AX", "AZ",
    "BA", "BB", "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BL", "BM", "BN", "BO", "BQ", "BR",
    "BS", "BT", "BW", "BZ", "CA", "CC", "CD", "CF", "CG", "CH", "CI", "CK", "CL", "CM", "CO",
    "CR", "CV", "CW", "CX", "CY", "CZ", "DE", "DJ", "DK", "DM", "DO", "DZ", "EC", "EE", "EG",
    "EH", "ER", "ES", "ET", "FI", "FJ", "FK", "FM", "FO", "FR", "GA", "GB", "GD", "GE", "GF",
    "GG", "GH", "GI", "GL", "GM", "GN", "GP", "GQ", "GR", "GS", "GT", "GU", "GW", "GY", "HM",
    "HN", "HR", "HT", "HU", "ID", "IE", "IL", "IM", "IN", "IO", "IQ", "IS", "IT", "JE", "JM",
    "JO", "JP", "KE", "KG", "KH", "KI", "KM", "KN", "KR", "KW", "KY", "KZ", "LA", "LB", "LC",
    "LI", "LK", "LR", "LS", "LT", "LU", "LV", "LY", "MA", "MC", "MD", "ME", "MF", "MG", "MH",
    "MK", "ML", "MN", "MP", "MQ", "MR", "MS", "MT", "MU", "MV", "MW", "MX", "MY", "MZ", "NA",
    "NC", "NE", "NF", "NG", "NI", "NL", "NO", "NP", "NR", "NU", "NZ", "OM", "PA", "PE", "PF",
    "PG", "PH", "PK", "PL", "PM", "PN", "PR", "PS", "PT", "PW", "PY", "QA", "RE", "RO", "RS",
    "RW", "SA", "SB", "SC", "SD", "SE", "SG", "SH", "SI", "SJ", "SK", "SL", "SM", "SN", "SO",
    "SR", "SS", "ST", "SV", "SX", "SZ", "TC", "TD", "TF", "TG", "TH", "TJ", "TK", "TL", "TM",
    "TN", "TO", "TR", "TT", "TV", "TW", "TZ", "UA", "UG", "UM", "US", "UY", "UZ", "VA", "VC",
    "VE", "VG", "VI", "VN", "VU", "WF", "WS", "XK", "YE", "YT", "ZA", "ZM", "ZW",
})

# 完整 ISO 3166-1 alpha-3 -> alpha-2 映射表（含 XKX -> XK）
ISO3_TO_ISO2 = {
    "ABW": "AW", "AFG": "AF", "AGO": "AO", "AIA": "AI", "ALA": "AX", "ALB": "AL", "AND": "AD",
    "ARE": "AE", "ARG": "AR", "ARM": "AM", "ASM": "AS", "ATA": "AQ", "ATF": "TF", "ATG": "AG",
    "AUS": "AU", "AUT": "AT", "AZE": "AZ", "BDI": "BI", "BEL": "BE", "BEN": "BJ", "BES": "BQ",
    "BFA": "BF", "BGD": "BD", "BGR": "BG", "BHR": "BH", "BHS": "BS", "BIH": "BA", "BLM": "BL",
    "BLR": "BY", "BLZ": "BZ", "BMU": "BM", "BOL": "BO", "BRA": "BR", "BRB": "BB", "BRN": "BN",
    "BTN": "BT", "BVT": "BV", "BWA": "BW", "CAF": "CF", "CAN": "CA", "CCK": "CC", "CHE": "CH",
    "CHL": "CL", "CHN": "CN", "CIV": "CI", "CMR": "CM", "COD": "CD", "COG": "CG", "COK": "CK",
    "COL": "CO", "COM": "KM", "CPV": "CV", "CRI": "CR", "CUB": "CU", "CUW": "CW", "CXR": "CX",
    "CYM": "KY", "CYP": "CY", "CZE": "CZ", "DEU": "DE", "DJI": "DJ", "DMA": "DM", "DNK": "DK",
    "DOM": "DO", "DZA": "DZ", "ECU": "EC", "EGY": "EG", "ERI": "ER", "ESH": "EH", "ESP": "ES",
    "EST": "EE", "ETH": "ET", "FIN": "FI", "FJI": "FJ", "FLK": "FK", "FRA": "FR", "FRO": "FO",
    "FSM": "FM", "GAB": "GA", "GBR": "GB", "GEO": "GE", "GGY": "GG", "GHA": "GH", "GIB": "GI",
    "GIN": "GN", "GLP": "GP", "GMB": "GM", "GNB": "GW", "GNQ": "GQ", "GRC": "GR", "GRD": "GD",
    "GRL": "GL", "GTM": "GT", "GUF": "GF", "GUM": "GU", "GUY": "GY", "HKG": "HK", "HMD": "HM",
    "HND": "HN", "HRV": "HR", "HTI": "HT", "HUN": "HU", "IDN": "ID", "IMN": "IM", "IND": "IN",
    "IOT": "IO", "IRL": "IE", "IRN": "IR", "IRQ": "IQ", "ISL": "IS", "ISR": "IL", "ITA": "IT",
    "JAM": "JM", "JEY": "JE", "JOR": "JO", "JPN": "JP", "KAZ": "KZ", "KEN": "KE", "KGZ": "KG",
    "KHM": "KH", "KIR": "KI", "KNA": "KN", "KOR": "KR", "KWT": "KW", "LAO": "LA", "LBN": "LB",
    "LBR": "LR", "LBY": "LY", "LCA": "LC", "LIE": "LI", "LKA": "LK", "LSO": "LS", "LTU": "LT",
    "LUX": "LU", "LVA": "LV", "MAC": "MO", "MAF": "MF", "MAR": "MA", "MCO": "MC", "MDA": "MD",
    "MDG": "MG", "MDV": "MV", "MEX": "MX", "MHL": "MH", "MKD": "MK", "MLI": "ML", "MLT": "MT",
    "MMR": "MM", "MNE": "ME", "MNG": "MN", "MNP": "MP", "MOZ": "MZ", "MRT": "MR", "MSR": "MS",
    "MTQ": "MT", "MUS": "MU", "MWI": "MW", "MYS": "MY", "MYT": "YT", "NAM": "NA", "NCL": "NC",
    "NER": "NE", "NFK": "NF", "NGA": "NG", "NIC": "NI", "NIU": "NU", "NLD": "NL", "NOR": "NO",
    "NPL": "NP", "NRU": "NR", "NZL": "NZ", "OMN": "OM", "PAK": "PK", "PAN": "PA", "PCN": "PN",
    "PER": "PE", "PHL": "PH", "PLW": "PW", "PNG": "PG", "POL": "PL", "PRI": "PR", "PRK": "KP",
    "PRT": "PT", "PRY": "PY", "PSE": "PS", "PYF": "PF", "QAT": "QA", "REU": "RE", "ROU": "RO",
    "RUS": "RU", "RWA": "RW", "SAU": "SA", "SDN": "SD", "SEN": "SN", "SGP": "SG", "SGS": "GS",
    "SHN": "SH", "SJM": "SJ", "SLB": "SB", "SLE": "SL", "SLV": "SV", "SMR": "SM", "SOM": "SO",
    "SPM": "PM", "SRB": "RS", "SSD": "SS", "STP": "ST", "SUR": "SR", "SVK": "SK", "SVN": "SI",
    "SWE": "SE", "SWZ": "SZ", "SXM": "SX", "SYC": "SC", "SYR": "SY", "TCA": "TC", "TCD": "TD",
    "TGO": "TG", "THA": "TH", "TJK": "TJ", "TKL": "TK", "TKM": "TM", "TLS": "TL", "TON": "TO",
    "TTO": "TT", "TUN": "TN", "TUR": "TR", "TUV": "TV", "TWN": "TW", "TZA": "TZ", "UGA": "UG",
    "UKR": "UA", "UMI": "UM", "URY": "UY", "USA": "US", "UZB": "UZ", "VAT": "VA", "VCT": "VC",
    "VEN": "VE", "VGB": "VG", "VIR": "VI", "VNM": "VN", "VUT": "VU", "WLF": "WF", "WSM": "WS",
    "XKX": "XK", "YEM": "YE", "ZAF": "ZA", "ZMB": "ZM", "ZWE": "ZW",
}
# 修正 MTQ -> MQ（马提尼克）
ISO3_TO_ISO2["MTQ"] = "MQ"
ISO2_CODES = frozenset(ISO3_TO_ISO2.values())

_RE_GEMINI_ISO3_PRIMARY = re.compile(r',2,1,200,"([A-Z]{3})"')
_RE_GEMINI_ISO3_SECONDARY = re.compile(r',\d{4,6},\d{2,4},"([A-Z]{3})","[a-z]{2}(?:-[A-Za-z]+)?"')
_RE_GOOGLE_LANG_REGION = re.compile(r'<html[^>]*\blang="[a-z]{2}-([A-Z]{2})"', re.I)
_RE_CONSENT_GL = re.compile(r'[?&]gl=([A-Z]{2})\b')

_CAPTCHA_BODY_MARKERS = (
    'id="captcha-form"',
    "our systems have detected unusual traffic",
    "unusual traffic from your computer network",
    "/sorry/index",
)
_UNSUPPORTED_BODY_MARKERS = (
    "gemini isn't currently supported in your country",
    "gemini is not available in your country",
    "isn’t currently supported in your country",
    "not currently available in your country",
    "your region may not be supported",
)


def _opener(proxy_url: str | None):
    handlers = [
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
        urllib.request.ProxyHandler(
            {"http": proxy_url, "https": proxy_url} if proxy_url else {}
        ),
    ]
    return urllib.request.build_opener(*handlers)


def _decode_body(resp) -> str:
    raw = resp.read()
    enc = (resp.headers.get("Content-Encoding") or "").lower()
    if enc == "gzip":
        raw = gzip.decompress(raw)
    elif enc == "deflate":
        raw = zlib.decompress(raw)
    return raw.decode("utf-8", "replace")


def _request(
    proxy_url: str | None,
    url: str,
    timeout: float,
    *,
    method: str = "GET",
    headers: dict | None = None,
    data: bytes | None = None,
) -> tuple[int, str, str, int, str | None]:
    """发起单次 HTTP 请求，返回 (http_status, final_url, body, latency_ms, err_msg)。"""
    opener = _opener(proxy_url)
    hdrs = {
        "User-Agent": UA,
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Cache-Control": "no-cache",
    }
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    t0 = time.perf_counter()
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = _decode_body(resp)
            return resp.status, resp.geturl(), body, int((time.perf_counter() - t0) * 1000), None
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = _decode_body(e)
        except Exception:
            pass
        return e.code, e.geturl(), body, int((time.perf_counter() - t0) * 1000), None
    except Exception as e:
        return 0, url, "", int((time.perf_counter() - t0) * 1000), f"{type(e).__name__}: {e}"


def _has_captcha(status: int, final_url: str, body_lower: str) -> bool:
    if status == 429 or "/sorry/" in final_url.lower():
        return True
    return any(m in body_lower for m in _CAPTCHA_BODY_MARKERS)


# ------------------------------------------------------------------ 4 项子探测
def _probe_web(proxy_url: str | None, timeout: float) -> dict:
    """探测 Gemini 网页版 (gemini.google.com) 及 Google 自身识别的国家/地区。"""
    status, final_url, body, ms, err = _request(
        proxy_url,
        "https://gemini.google.com/?hl=en",
        timeout,
        headers={
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Cookie": SOCS_COOKIE,
        },
    )
    out = {
        "status": "error",
        "region": "",
        "region_iso3": "",
        "http_status": status,
        "latency_ms": ms,
        "detail": "",
    }
    if err:
        out["detail"] = err
        return out

    final_lower = final_url.lower()
    body_lower = body.lower()

    # 提取 Google 判定的 ISO-3 国家代码
    iso3 = ""
    m = _RE_GEMINI_ISO3_PRIMARY.search(body) or _RE_GEMINI_ISO3_SECONDARY.search(body)
    if m:
        iso3 = m.group(1).upper()
    iso2 = ISO3_TO_ISO2.get(iso3, "")
    if not iso2:
        m_gl = _RE_CONSENT_GL.search(final_url)
        if m_gl and m_gl.group(1).upper() in ISO2_CODES:
            iso2 = m_gl.group(1).upper()
    out["region_iso3"] = iso3
    out["region"] = iso2

    if _has_captcha(status, final_url, body_lower):
        out["status"] = "captcha"
        out["detail"] = f"触发 Google 验证码/限流 (HTTP {status})"
        return out
    if status in (403, 451):
        out["status"] = "blocked"
        out["detail"] = f"HTTP {status} 拒绝访问"
        return out

    # 显式地区不支持重定向或页面提示
    if (
        "/faq" in final_lower
        or "unavailable" in final_lower
        or "available-regions" in final_lower
        or any(m in body_lower for m in _UNSUPPORTED_BODY_MARKERS)
    ):
        out["status"] = "unsupported"
        out["detail"] = f"页面提示地区不支持 ({iso2 or '未知地区'})"
        return out

    if status == 200:
        if iso2:
            if iso2 in SUPPORTED_COUNTRIES:
                out["status"] = "ok"
                out["detail"] = f"正常 (Google 识别为 {iso2})"
            else:
                out["status"] = "unsupported"
                out["detail"] = f"Google 识别地区 {iso2} 不在 Gemini 支持列表"
            return out
        # 没提取到国家码时，检查是否至少正常渲染了 Gemini 前端或遇到了 GDPR 墙
        if "consent.google.com" in final_lower:
            out["status"] = "ok"
            out["detail"] = "遇到 GDPR 同意页（通常为欧洲支持地区）"
            return out
        if "bardchatui" in body_lower or "45631641,null,true" in body or "45617354,null,true" in body:
            out["status"] = "ok"
            out["detail"] = "页面可正常加载（未解析出地区码）"
            return out
        out["status"] = "unsupported"
        out["detail"] = f"返回 200 但未检测到 Gemini 正常内容 ({final_url[:60]})"
        return out

    out["status"] = "error"
    out["detail"] = f"异常 HTTP {status}"
    return out


def _probe_google_risk(proxy_url: str | None, timeout: float) -> dict:
    """探测 Google 搜索风控状态（429 / Sorry 人机验证）并提取兜底地区码。"""
    status, final_url, body, ms, err = _request(
        proxy_url,
        "https://www.google.com/search?q=test&hl=en",
        timeout,
        headers={
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Cookie": SOCS_COOKIE,
        },
    )
    out = {
        "status": "error",
        "region": "",
        "http_status": status,
        "latency_ms": ms,
        "detail": "",
    }
    if err:
        out["detail"] = err
        return out

    m = _RE_GOOGLE_LANG_REGION.search(body[:2048])
    if m and m.group(1).upper() in ISO2_CODES:
        out["region"] = m.group(1).upper()

    body_lower = body.lower()
    if _has_captcha(status, final_url, body_lower):
        out["status"] = "captcha"
        out["detail"] = f"触发 Google 验证码/429 风控 (HTTP {status})"
    elif status in (403, 451):
        out["status"] = "blocked"
        out["detail"] = f"Google 搜索拒绝访问 (HTTP {status})"
    elif status == 200:
        out["status"] = "ok"
        out["detail"] = "正常（未触发验证码）"
    else:
        out["status"] = "error"
        out["detail"] = f"异常 HTTP {status}"
    return out


def _probe_aistudio(proxy_url: str | None, timeout: float) -> dict:
    """探测 Google AI Studio (aistudio.google.com) 可达性与地区拦截。"""
    status, final_url, body, ms, err = _request(
        proxy_url,
        "https://aistudio.google.com/",
        timeout,
        headers={
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Cookie": SOCS_COOKIE,
        },
    )
    out = {
        "status": "error",
        "http_status": status,
        "latency_ms": ms,
        "detail": "",
    }
    if err:
        out["detail"] = err
        return out

    final_lower = final_url.lower()
    body_lower = body.lower()
    if _has_captcha(status, final_url, body_lower):
        out["status"] = "captcha"
        out["detail"] = f"触发验证码/限流 (HTTP {status})"
    elif status in (403, 451):
        out["status"] = "blocked"
        out["detail"] = f"HTTP {status} 拒绝访问"
    elif "available-regions" in final_lower or "unavailable" in final_lower:
        out["status"] = "unsupported"
        out["detail"] = "重定向至地区不支持页面"
    elif status == 200:
        out["status"] = "ok"
        out["detail"] = "页面可达"
    else:
        out["status"] = "error"
        out["detail"] = f"异常 HTTP {status}"
    return out


def _parse_api_error(body: str) -> tuple[str, str, str]:
    """从 Google API 错误 JSON 提取 (status, reason, message)。"""
    try:
        j = json.loads(body)
        err = j.get("error") or {}
        st = str(err.get("status") or "")
        msg = str(err.get("message") or "")
        reason = ""
        for d in err.get("details") or []:
            if isinstance(d, dict) and d.get("reason"):
                reason = str(d["reason"])
                break
        return st, reason, msg
    except Exception:
        return "", "", body[:160].strip()


def _probe_api(
    proxy_url: str | None,
    timeout: float,
    api_key: str = "",
    api_model: str = DEFAULT_API_MODEL,
) -> dict:
    """探测 Gemini API (generativelanguage.googleapis.com)。

    - 提供 api_key 时：向 generateContent 发送极简请求 (maxOutputTokens=1) 实测；
      注意 API Key 仅通过请求头 x-goog-api-key 传递，绝不写入 URL 或返回结果。
    - 未提供 api_key 时：探测 API 网关可达性与边缘地区拦截。
    """
    key = (api_key or "").strip()
    model = (api_model or DEFAULT_API_MODEL).strip()
    if model.startswith("models/"):
        model = model[len("models/"):]

    out = {
        "status": "error",
        "verified": bool(key),
        "http_status": 0,
        "latency_ms": 0,
        "detail": "",
    }

    if key:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
        payload = json.dumps({
            "contents": [{"parts": [{"text": "hi"}]}],
            "generationConfig": {"maxOutputTokens": 1},
        }).encode("utf-8")
        status, final_url, body, ms, err = _request(
            proxy_url,
            url,
            timeout,
            method="POST",
            headers={"Content-Type": "application/json", "x-goog-api-key": key},
            data=payload,
        )
        # 若指定模型名不存在 (404)，退回 countTokens/models 列表探测以区分模型名问题和地区问题
        if not err and status == 404:
            status2, final_url2, body2, ms2, err2 = _request(
                proxy_url,
                "https://generativelanguage.googleapis.com/v1beta/models?pageSize=1",
                timeout,
                headers={"x-goog-api-key": key},
            )
            ms += ms2
            if not err2 and status2 != 404:
                status, final_url, body, err = status2, final_url2, body2, err2
                if status == 200:
                    out["http_status"] = status
                    out["latency_ms"] = ms
                    out["status"] = "ok"
                    out["detail"] = f"API 可调用（模型 {model} 不存在，已通过 models 列表验证）"
                    return out
    else:
        url = "https://generativelanguage.googleapis.com/v1beta/models"
        status, final_url, body, ms, err = _request(
            proxy_url,
            url,
            timeout,
            headers={"x-goog-api-key": "AIzaSyProbeOnlyInvalidKey0000000000000"},
        )

    out["http_status"] = status
    out["latency_ms"] = ms
    if err:
        out["detail"] = err
        return out

    err_status, reason, msg = _parse_api_error(body)
    msg_lower = msg.lower()
    body_lower = body.lower()

    if status == 200:
        out["status"] = "ok"
        out["detail"] = f"API 实测成功 ({model})"
        return out

    # 最关键的地区/机房封锁判断
    if (
        "location is not supported" in msg_lower
        or "user location" in msg_lower
        or (status == 400 and err_status == "FAILED_PRECONDITION")
    ):
        out["status"] = "unsupported"
        out["detail"] = msg or "User location is not supported for the API use"
        return out

    if reason == "API_KEY_INVALID" or "api key not valid" in msg_lower:
        if key:
            out["status"] = "key_invalid"
            out["detail"] = "配置的 API Key 无效（网关可达）"
        else:
            out["status"] = "reachable"
            out["detail"] = "API 网关可达（未填 Key，未实测地区放行）"
        return out

    if status == 429 or err_status == "RESOURCE_EXHAUSTED":
        if key:
            out["status"] = "quota"
            out["detail"] = "API 地区放行，但 Key 触发配额限制 (429)"
        else:
            out["status"] = "blocked"
            out["detail"] = "API 网关触发限流 (HTTP 429)"
        return out

    if status in (403, 451):
        if key and reason in ("API_KEY_SERVICE_BLOCKED", "SERVICE_DISABLED", "ACCESS_DENIED"):
            out["status"] = "key_invalid"
            out["detail"] = f"API Key 权限受限: {reason}"
        else:
            out["status"] = "blocked"
            out["detail"] = f"HTTP {status}: {msg or '拒绝访问'}"
        return out

    if _has_captcha(status, final_url, body_lower):
        out["status"] = "blocked"
        out["detail"] = f"触发 Google 风控拦截 (HTTP {status})"
        return out

    out["status"] = "error"
    out["detail"] = f"HTTP {status}: {msg or err_status or '未知响应'}"
    return out


# ------------------------------------------------------------------ 汇总与分级
def check(
    proxy_url: str | None,
    timeout: float = 12.0,
    api_key: str = "",
    api_model: str = DEFAULT_API_MODEL,
    ipcx_country: str = "",
) -> dict:
    """对指定代理执行完整 Gemini 支持程度检测，返回扁平字段 + detail 字典。"""
    t0 = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        f_web = pool.submit(_probe_web, proxy_url, timeout)
        f_risk = pool.submit(_probe_google_risk, proxy_url, timeout)
        f_studio = pool.submit(_probe_aistudio, proxy_url, timeout)
        f_api = pool.submit(_probe_api, proxy_url, timeout, api_key, api_model)

        web = f_web.result()
        risk = f_risk.result()
        studio = f_studio.result()
        api = f_api.result()

    total_ms = int((time.perf_counter() - t0) * 1000)

    # Google 实际识别的国家/地区（优先 gemini.google.com，其次 google.com/search）
    g_region = (web.get("region") or risk.get("region") or "").upper()
    ipcx_cc = (ipcx_country or "").upper()

    # 若 Google 明确判为不支持地区，校正无 Key 场景下仅返回静态页/网关的 studio 与 api 结果，避免误报
    region_unsupported = bool(g_region and g_region not in SUPPORTED_COUNTRIES)
    if region_unsupported:
        if studio["status"] == "ok":
            studio["status"] = "unsupported"
            studio["detail"] = f"首页可达，但 Google 识别地区 {g_region} 不受支持"
        if not api["verified"] and api["status"] == "reachable":
            api["status"] = "unsupported"
            api["detail"] = f"网关可达，但 Google 识别地区 {g_region} 不受支持"
        if web["status"] == "ok":
            web["status"] = "unsupported"
            web["detail"] = f"Google 识别地区 {g_region} 不在 Gemini 支持列表"

    # 计算综合支持程度等级
    ws = web["status"]
    as_ = api["status"]
    ss = studio["status"]
    rs = risk["status"]

    if ws == "error":
        if as_ == "unsupported" or region_unsupported:
            level = "unsupported"
        elif as_ == "blocked" or rs == "blocked":
            level = "blocked"
        else:
            level = "error"
    elif ws in ("blocked", "captcha"):
        level = "blocked"
    elif ws == "unsupported" or region_unsupported:
        level = "unsupported"
    else:  # web == ok
        if as_ in ("unsupported", "blocked") or ss in ("unsupported", "blocked"):
            level = "web_only"
        elif rs in ("captcha", "blocked"):
            level = "risk"
        else:
            level = "full"

    detail = {
        "level": level,
        "label": LEVEL_LABELS.get(level, level),
        "region": g_region,
        "ipcx_country": "",
        "drift": "",
        "api_verified": api["verified"],
        "web": web,
        "risk": risk,
        "aistudio": studio,
        "api": api,
        "latency_ms": total_ms,
    }

    res = {
        "gemini_level": level,
        "gemini_region": g_region,
        "gemini_web": ws,
        "gemini_api": as_,
        "gemini_risk": rs,
        "gemini_latency_ms": total_ms,
        "gemini_detail": detail,
    }
    return apply_ipcx_country(res, ipcx_cc)


def apply_ipcx_country(g: dict, ipcx_country: str) -> dict:
    """结合 ip.cx 识别的国家代码补全地区漂移 / 送中标记（支持与 ipcx 并发执行后回填）。"""
    detail = g.get("gemini_detail")
    if not isinstance(detail, dict):
        return g
    g_region = (g.get("gemini_region") or detail.get("region") or "").upper()
    ipcx_cc = (ipcx_country or "").upper()
    drift = ""
    if g_region and ipcx_cc and g_region != ipcx_cc:
        if g_region == "CN":
            drift = "送中"
        else:
            drift = f"漂移({ipcx_cc}→{g_region})"
    elif g_region == "CN":
        drift = "中国区"
    detail["ipcx_country"] = ipcx_cc
    detail["drift"] = drift
    return g


def format_summary(g: dict) -> str:
    """供运行日志使用的单行摘要。"""
    level = g.get("gemini_level") or ""
    if not level:
        return ""
    label = LEVEL_LABELS.get(level, level)
    region = g.get("gemini_region") or ""
    detail = g.get("gemini_detail") or {}
    parts = [label]
    if region:
        parts.append(region)
    if detail.get("drift"):
        parts.append(detail["drift"])
    if detail.get("api_verified"):
        api_st = g.get("gemini_api")
        if api_st == "ok":
            parts.append("API实测✓")
        elif api_st == "unsupported":
            parts.append("API地区被拒")
        elif api_st == "key_invalid":
            parts.append("API Key无效")
        elif api_st == "quota":
            parts.append("API配额满")
    return " · ".join(parts)


if __name__ == "__main__":
    import sys

    proxy = sys.argv[1] if len(sys.argv) > 1 else None
    key = sys.argv[2] if len(sys.argv) > 2 else ""
    res = check(proxy, api_key=key)
    print(json.dumps(res, ensure_ascii=False, indent=2))
