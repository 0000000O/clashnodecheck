"""ip.cx 节点出口记录器 —— 本地 Web 界面。

运行：python app.py   然后浏览器打开 http://127.0.0.1:8866
只依赖 Python 标准库。
"""
from __future__ import annotations

import csv
import io
import json
import os
import sys
import threading
import time
import traceback
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import gemini
import youtube
from clash import ClashAPI, ClashError
from runner import Runner
from store import COLUMNS, Store

BASE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE, "config.json")
STATIC = os.path.join(BASE, "static")

DEFAULT_CONFIG = {
    "clash_api": "http://127.0.0.1:9097",
    "secret": "123",
    "proxy_url": "",               # 留空则自动使用 Clash 的 mixed-port
    "test_group": "GLOBAL",        # 用来切换节点的策略组
    "force_global_mode": True,     # 测试期间临时切到 global 模式
    "precheck_delay": True,        # 先用 Clash 延迟测试，不通的节点直接跳过
    "delay_url": "https://www.gstatic.com/generate_204",
    "delay_timeout_ms": 5000,
    "timeout_sec": 15,
    "retries": 1,
    "switch_wait_sec": 0.3,
    "interval_sec": 0.5,
    "with_geo_api": False,         # 额外请求 ip.cx 的多库定位接口
    "check_gemini": True,          # 同时检测 Gemini 支持程度
    "gemini_timeout_sec": 12,      # Gemini 检测超时 (秒)
    "gemini_api_key": "",          # 可选：填入 Gemini API Key 实测 API 调用（留空仅探测网关）
    "gemini_api_model": gemini.DEFAULT_API_MODEL,
    "check_yt_translate": True,    # 同时检测 YouTube 自动字幕翻译（简体中文）可用性
    "yt_video_id": youtube.DEFAULT_VIDEO_ID,  # 测试视频 ID（需带英文 ASR 自动字幕）
    "yt_timeout_sec": 12,          # YouTube 字幕检测超时 (秒)
    "auto_interval_min": 0,        # >0 时每隔 N 分钟自动测试一次
    "auto_nodes": [],              # 自动测试的节点；空 = 全部节点
    "listen_host": "127.0.0.1",
    "listen_port": 8866,
}

_cfg_lock = threading.Lock()


def load_config() -> dict:
    cfg = dict(DEFAULT_CONFIG)
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, encoding="utf-8") as f:
                cfg.update(json.load(f))
        except Exception as e:
            print("config.json 读取失败，使用默认值：", e)
    return cfg


CONFIG = load_config()


def get_config() -> dict:
    with _cfg_lock:
        return dict(CONFIG)


def save_config(patch: dict) -> dict:
    with _cfg_lock:
        for k, v in patch.items():
            if k in DEFAULT_CONFIG:
                CONFIG[k] = v
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(CONFIG, f, ensure_ascii=False, indent=2)
        return dict(CONFIG)


store = Store(os.path.join(BASE, "ipcx_records.db"))
runner = Runner(store, get_config)


def clash() -> ClashAPI:
    c = get_config()
    return ClashAPI(c["clash_api"], c.get("secret", ""))


def all_node_names() -> list[str]:
    return clash().nodes_and_groups()[0]


# ---------------------------------------------------------------------- 定时任务
def scheduler():
    last = time.time()
    while True:
        time.sleep(15)
        try:
            cfg = get_config()
            minutes = float(cfg.get("auto_interval_min") or 0)
            if minutes <= 0:
                last = time.time()
                continue
            if runner.state["running"] or time.time() - last < minutes * 60:
                continue
            last = time.time()
            nodes = cfg.get("auto_nodes") or all_node_names()
            runner.start(nodes, trigger="auto")
        except Exception as e:
            print("定时任务出错：", e)


# ---------------------------------------------------------------------- HTTP
class Handler(BaseHTTPRequestHandler):
    server_version = "ipcx-recorder/1.0"

    def log_message(self, fmt, *args):  # 安静一点
        pass

    def _send(self, code: int, body: bytes, ctype: str, extra: dict | None = None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        if not n:
            return {}
        return json.loads(self.rfile.read(n).decode("utf-8"))

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def _dispatch(self, method: str):
        u = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        try:
            route = ROUTES.get((method, u.path))
            if route:
                return route(self, q)
            if method == "GET" and u.path in ("/", "/index.html"):
                with open(os.path.join(STATIC, "index.html"), "rb") as f:
                    return self._send(200, f.read(), "text/html; charset=utf-8")
            self._json({"error": "not found"}, 404)
        except ClashError as e:
            self._json({"error": str(e)}, 502)
        except Exception as e:
            traceback.print_exc()
            self._json({"error": f"{type(e).__name__}: {e}"}, 500)

    # ---- API
    def api_overview(self, q):
        c = clash()
        info = {"config": get_config()}
        try:
            info["version"] = c.version()
            cc = c.configs()
            info["clash"] = {k: cc.get(k) for k in ("mode", "mixed-port", "port", "socks-port")}
            nodes, node_info, groups = c.nodes_and_groups()
            info["nodes"] = nodes
            info["node_info"] = node_info
            # 只把「直接包含节点」的策略组拿来做筛选
            ns = set(nodes)
            info["groups"] = {g: [n for n in v["all"] if n in ns] for g, v in groups.items()
                              if g != "GLOBAL" and any(n in ns for n in v["all"])}
            info["selectors"] = [g for g, v in groups.items() if v["type"] == "Selector"]
            info["clash_ok"] = True
        except ClashError as e:
            info["clash_ok"] = False
            info["clash_error"] = str(e)
            info["nodes"], info["groups"], info["node_info"], info["selectors"] = [], {}, {}, []
        self._json(info)

    def api_status(self, q):
        self._json(runner.status())

    def api_latest(self, q):
        self._json(store.latest_per_node())

    def api_runs(self, q):
        self._json(store.runs(int(q.get("limit", 100))))

    def api_run_results(self, q):
        self._json(store.results_of_run(int(q["id"])))

    def api_history(self, q):
        self._json(store.history(q["node"]))

    def api_ip(self, q):
        self._json(store.ip_lookup(q["ip"]))

    def api_start(self, q):
        body = self._body()
        nodes = body.get("nodes") or all_node_names()
        try:
            run_id = runner.start(nodes, trigger="manual")
        except RuntimeError as e:
            return self._json({"error": str(e)}, 409)
        self._json({"run_id": run_id})

    def api_stop(self, q):
        runner.stop()
        self._json({"ok": True})

    def api_config(self, q):
        self._json(save_config(self._body()))

    def api_delete_run(self, q):
        store.delete_run(int(self._body()["id"]))
        self._json({"ok": True})

    def api_export(self, q):
        run_id = int(q["run_id"]) if q.get("run_id") else None
        rows = store.latest_per_node() if q.get("latest") else store.all_results(run_id)
        cols = ["run_id", "node", "tested_at", "ok", "error", "delay_ms", "latency_ms",
                *COLUMNS, "gemini_label", "yt_translate_label"]
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(cols)
        for r in rows:
            r = dict(r)
            r["tested_at"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["tested_at"]))
            r["gemini_label"] = gemini.LEVEL_LABELS.get(r.get("gemini_level") or "", "")
            r["yt_translate_label"] = youtube.STATUS_LABELS.get(r.get("yt_translate_status") or "", "")
            w.writerow([r.get(c, "") for c in cols])
        name = f"ipcx_{'latest' if q.get('latest') else ('run' + str(run_id) if run_id else 'all')}.csv"
        # 带 BOM，Excel 直接打开不乱码
        self._send(200, ("\ufeff" + buf.getvalue()).encode("utf-8"), "text/csv; charset=utf-8",
                   {"Content-Disposition": f'attachment; filename="{name}"'})


ROUTES = {
    ("GET", "/api/overview"): Handler.api_overview,
    ("GET", "/api/status"): Handler.api_status,
    ("GET", "/api/latest"): Handler.api_latest,
    ("GET", "/api/runs"): Handler.api_runs,
    ("GET", "/api/run"): Handler.api_run_results,
    ("GET", "/api/history"): Handler.api_history,
    ("GET", "/api/ip"): Handler.api_ip,
    ("GET", "/api/export.csv"): Handler.api_export,
    ("POST", "/api/start"): Handler.api_start,
    ("POST", "/api/stop"): Handler.api_stop,
    ("POST", "/api/config"): Handler.api_config,
    ("POST", "/api/run/delete"): Handler.api_delete_run,
}


def main():
    if not os.path.exists(CONFIG_PATH):
        save_config({})
    cfg = get_config()
    host, port = cfg["listen_host"], int(cfg["listen_port"])
    srv = ThreadingHTTPServer((host, port), Handler)
    threading.Thread(target=scheduler, daemon=True).start()
    url = f"http://{host}:{port}/"
    print(f"ip.cx 节点出口记录器已启动：{url}  （Ctrl+C 退出）")
    if "--no-browser" not in sys.argv:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if runner.state["running"]:
            print("正在停止测试并恢复 Clash 状态…")
            runner.stop()
            if runner._thread:
                runner._thread.join(timeout=60)


if __name__ == "__main__":
    main()
