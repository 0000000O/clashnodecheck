"""通过指定的 HTTP 代理访问 https://ip.cx/ 并解析出口 IP 信息。

ip.cx 首页是服务端渲染的：直接 GET 就会把「访问者 IP」的归属、ISP、ASN、
威胁/代理情报、IP 评分等写在 HTML 里，不需要人机验证（查别的 IP 才需要）。
所以只要让这次请求从某个节点出去，拿到的就是该节点出口 IP 的信息。
"""
from __future__ import annotations

import gzip
import html
import json
import re
import time
import urllib.error
import urllib.request
import zlib

IPCX_URL = "https://ip.cx/"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36")

# ip.cx 行标签 -> 本地字段名
LABEL_MAP = {
    "IP 类型": "ip_type",
    "ISP": "isp",
    "所属组织": "org",
    "ASN": "asn",
    "关联域名": "domain",
    "注册机构": "registry",
    "数据中心": "is_dc",
    "威胁状态": "threat",
    "代理状态": "proxy_status",
    "IP 评分": "score",
    "国家/地区": "country",
    "省/州": "region",
    "城市": "city",
    "经纬度": "latlon",
    "时区": "timezone",
    "大洲": "continent",
}

_ROW_RE = re.compile(
    r'<div class="row">\s*<span class="row__label">(.*?)</span>\s*'
    r'<span class="row__value">(.*?)</span>\s*</div>',
    re.S,
)
_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")


def _text(fragment: str) -> str:
    return _WS_RE.sub(" ", html.unescape(_TAG_RE.sub(" ", fragment))).strip()


def _first(pattern: str, s: str, flags=re.S) -> str:
    m = re.search(pattern, s, flags)
    return html.unescape(m.group(1)).strip() if m else ""


def parse_home(page: str) -> dict:
    """解析 ip.cx 首页 HTML，返回字段字典。"""
    out: dict = {"fields": {}}
    out["ip"] = _first(r'id="current-ip"[^>]*>(.*?)<', page)
    out["host"] = _first(r'class="current__host[^"]*"[^>]*>(.*?)<', page)

    for label_html, value_html in _ROW_RE.findall(page):
        label = _text(label_html)
        if not label or "geo__note" in value_html:
            continue
        text = _text(value_html)
        out["fields"][label] = text
        key = LABEL_MAP.get(label)
        if not key:
            continue

        if key == "asn":
            out["asn"] = _first(r'class="asn-link[^"]*"[^>]*>(.*?)<', value_html) or text.split(" ")[0]
            human = _first(r'botratio__human">(.*?)<', value_html)
            bot = _first(r'botratio__bot">(.*?)<', value_html)
            out["bot_ratio"] = f"{human} | {bot}".strip(" |") if (human or bot) else ""
        elif key == "score":
            num = _first(r'score__num[^"]*">\s*(\d+)', value_html)
            out["score"] = int(num) if num.isdigit() else None
        elif key == "country":
            cc = _first(r'class="dim mono">([A-Z]{2})<', value_html)
            flag = _first(r'class="flag">(.*?)<', value_html)
            name = text
            for part in (flag, cc):
                if part:
                    name = name.replace(part, "")
            out["country"] = name.strip()
            out["country_code"] = cc
            out["flag"] = flag
        elif key == "timezone":
            out["timezone"] = _first(r'class="mono">(.*?)<', value_html) or text
        else:
            out[key] = text
    return out


def _decode_body(resp) -> str:
    raw = resp.read()
    enc = (resp.headers.get("Content-Encoding") or "").lower()
    if enc == "gzip":
        raw = gzip.decompress(raw)
    elif enc == "deflate":
        raw = zlib.decompress(raw)
    return raw.decode("utf-8", "replace")


def _opener(proxy_url: str | None):
    import http.cookiejar

    handlers = [urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())]
    # 显式指定代理；proxy_url 为空时也传空字典，避免 urllib 自动读取系统代理
    handlers.append(urllib.request.ProxyHandler(
        {"http": proxy_url, "https": proxy_url} if proxy_url else {}))
    return urllib.request.build_opener(*handlers)


def fetch(proxy_url: str | None, timeout: float = 15.0, with_geo_api: bool = False) -> dict:
    """经由 proxy_url 访问 ip.cx，返回解析结果。失败时 ok=False 并带 error。

    每次调用都新建 opener（urllib 不复用连接），确保这次请求在 Clash
    里是一条新连接，会按当前选中的节点出去。
    """
    opener = _opener(proxy_url)
    headers = {
        "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Cache-Control": "no-cache",
    }
    t0 = time.perf_counter()
    try:
        with opener.open(urllib.request.Request(IPCX_URL, headers=headers), timeout=timeout) as resp:
            page = _decode_body(resp)
            status = resp.status
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = _decode_body(e)
        except Exception:
            pass
        err = f"HTTP {e.code}"
        if "Just a moment" in body or "cf-chl" in body or "challenge-platform" in body:
            err += " (Cloudflare 质询，该出口 IP 可能被风控)"
        return {"ok": False, "error": err, "latency_ms": int((time.perf_counter() - t0) * 1000)}
    except Exception as e:  # 超时、连接被重置、代理拒绝等
        return {"ok": False, "error": f"{type(e).__name__}: {e}",
                "latency_ms": int((time.perf_counter() - t0) * 1000)}

    latency = int((time.perf_counter() - t0) * 1000)
    data = parse_home(page)
    data["latency_ms"] = latency
    data["http_status"] = status
    if not data.get("ip"):
        snippet = _text(page)[:200]
        return {"ok": False, "error": f"页面里没有解析到 IP：{snippet}", "latency_ms": latency}
    data["ok"] = True

    if with_geo_api:
        # ip.cx 自己的多库定位接口（IP2Location / DB-IP / IPinfo），同一出口、同一 Cookie
        try:
            req = urllib.request.Request(
                "https://ip.cx/geo/api?ip=" + urllib.request.quote(data["ip"]),
                headers={"User-Agent": UA, "Accept": "application/json", "Referer": IPCX_URL},
            )
            with opener.open(req, timeout=timeout) as resp:
                geo = json.loads(_decode_body(resp))
            data["geo"] = geo.get("sources") if geo.get("ok") else {"error": geo.get("error")}
        except Exception as e:
            data["geo"] = {"error": str(e)}
    return data


if __name__ == "__main__":
    import sys

    proxy = sys.argv[1] if len(sys.argv) > 1 else None
    print(json.dumps(fetch(proxy, with_geo_api=True), ensure_ascii=False, indent=2))
