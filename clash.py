"""Clash / Mihomo 外部控制器（RESTful API）的极简客户端。"""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

# 这些类型是策略组或内置出站，不是真正的代理节点
GROUP_TYPES = {"Selector", "URLTest", "Fallback", "LoadBalance", "Relay"}
BUILTIN_TYPES = {"Direct", "Reject", "RejectDrop", "Pass", "PassRule", "Compatible", "Dns"}


class ClashError(RuntimeError):
    pass


class ClashAPI:
    def __init__(self, base_url: str, secret: str = "", timeout: float = 10.0):
        self.base = base_url.rstrip("/")
        self.secret = secret
        self.timeout = timeout
        # 控制器在本机，绝不能走系统代理
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def _req(self, method: str, path: str, body=None, params=None, timeout=None):
        url = self.base + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        if self.secret:
            req.add_header("Authorization", f"Bearer {self.secret}")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with self._opener.open(req, timeout=timeout or self.timeout) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as e:
            msg = e.read().decode("utf-8", "replace")
            raise ClashError(f"{method} {path} -> HTTP {e.code}: {msg}") from None
        except urllib.error.URLError as e:
            raise ClashError(f"无法连接 Clash 控制器 {self.base}: {e.reason}") from None
        return json.loads(raw) if raw.strip() else None

    @staticmethod
    def q(name: str) -> str:
        return urllib.parse.quote(name, safe="")

    # ---- 基本信息
    def version(self) -> dict:
        return self._req("GET", "/version")

    def configs(self) -> dict:
        return self._req("GET", "/configs")

    def set_mode(self, mode: str) -> None:
        self._req("PATCH", "/configs", {"mode": mode})

    # ---- 节点 / 策略组
    def proxies(self) -> dict:
        return self._req("GET", "/proxies")["proxies"]

    def proxy(self, name: str) -> dict:
        return self._req("GET", f"/proxies/{self.q(name)}")

    def select(self, group: str, name: str) -> None:
        self._req("PUT", f"/proxies/{self.q(group)}", {"name": name})

    def delay(self, name: str, url: str, timeout_ms: int = 5000) -> int | None:
        """调用 Clash 自带的延迟测试；节点不通返回 None。"""
        try:
            r = self._req("GET", f"/proxies/{self.q(name)}/delay",
                          params={"url": url, "timeout": timeout_ms},
                          timeout=timeout_ms / 1000 + 3)
            return r.get("delay") if r else None
        except ClashError:
            return None

    def nodes_and_groups(self):
        """返回 (节点列表, 策略组字典)。节点保持 GLOBAL 中的顺序。"""
        allp = self.proxies()
        nodes = [k for k, v in allp.items()
                 if v.get("type") not in GROUP_TYPES and v.get("type") not in BUILTIN_TYPES]
        order = allp.get("GLOBAL", {}).get("all") or []
        pos = {n: i for i, n in enumerate(order)}
        nodes.sort(key=lambda n: pos.get(n, 1 << 30))
        groups = {k: {"type": v["type"], "now": v.get("now"), "all": v.get("all", [])}
                  for k, v in allp.items() if v.get("type") in GROUP_TYPES}
        node_info = {n: {"type": allp[n].get("type"), "alive": allp[n].get("alive"),
                         "udp": allp[n].get("udp")} for n in nodes}
        return nodes, node_info, groups
