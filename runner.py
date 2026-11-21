"""批量测试：逐个切换节点 -> 经 Clash 混合端口访问 ip.cx -> 写入 SQLite。

原理
----
Clash 同一时刻一个策略组只能选一个节点，所以只能串行测试：
  1. 记下当前的运行模式和测试用策略组（默认 GLOBAL）的选中项；
  2. 临时把模式切到 global，这样所有流量（包括我们访问 ip.cx 的请求）都走 GLOBAL；
  3. 对每个节点：PUT /proxies/GLOBAL 选中它 -> 新建连接访问 ip.cx -> 记录；
  4. 结束（或出错 / 手动停止）后恢复原来的模式与选中项。
测试期间本机其它走 Clash 的流量也会跟着切换节点，测完自动恢复。
"""
from __future__ import annotations

import collections
import concurrent.futures
import threading
import time
import traceback

import gemini
import ipcx
import youtube
from clash import ClashAPI, ClashError
from store import Store


class Runner:
    def __init__(self, store: Store, get_config):
        self.store = store
        self.get_config = get_config
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.log = collections.deque(maxlen=400)
        self.state = self._blank_state()

    @staticmethod
    def _blank_state():
        return {"running": False, "run_id": None, "total": 0, "done": 0, "ok": 0, "fail": 0,
                "current": None, "started_at": None, "finished_at": None, "trigger": None,
                "last_error": None}

    def _log(self, msg: str, level: str = "info"):
        self.log.append({"t": time.time(), "level": level, "msg": msg})

    def status(self) -> dict:
        s = dict(self.state)
        s["log"] = list(self.log)[-150:]
        return s

    def start(self, nodes: list[str], trigger: str = "manual") -> int:
        with self._lock:
            if self.state["running"]:
                raise RuntimeError("已有测试正在进行")
            if not nodes:
                raise RuntimeError("没有选择节点")
            self._stop.clear()
            run_id = self.store.start_run(len(nodes), trigger)
            self.state = self._blank_state()
            self.state.update(running=True, run_id=run_id, total=len(nodes),
                              started_at=time.time(), trigger=trigger)
            self.log.clear()
            self._thread = threading.Thread(target=self._run, args=(run_id, list(nodes)), daemon=True)
            self._thread.start()
            return run_id

    def stop(self):
        self._stop.set()
        self._log("收到停止指令，当前节点测完后停止…", "warn")

    # ------------------------------------------------------------------ 主流程
    def _run(self, run_id: int, nodes: list[str]):
        cfg = self.get_config()
        clash = ClashAPI(cfg["clash_api"], cfg.get("secret", ""))
        group = cfg.get("test_group") or "GLOBAL"
        orig_mode = orig_sel = None
        mode_changed = False
        note = None
        try:
            ccfg = clash.configs()
            orig_mode = ccfg.get("mode")
            port = ccfg.get("mixed-port") or ccfg.get("port")
            proxy_url = cfg.get("proxy_url") or (f"http://127.0.0.1:{port}" if port else None)
            if not proxy_url:
                raise RuntimeError("Clash 没有开启 mixed-port / port，请在设置里手动填写代理地址")
            orig_sel = clash.proxy(group).get("now")
            extra_tips = []
            if cfg.get("check_gemini", True):
                extra_tips.append("Gemini：开启" + ("（API实测）" if (cfg.get("gemini_api_key") or "").strip() else "（无Key）"))
            if cfg.get("check_yt_translate", True):
                vid = youtube.normalize_video_id(str(cfg.get("yt_video_id") or ""))
                extra_tips.append(f"YT翻译：开启（{vid}）")
            tip_str = ("；" + "；".join(extra_tips)) if extra_tips else ""
            self._log(f"代理入口 {proxy_url}；测试组 [{group}] 原选中：{orig_sel}；原模式：{orig_mode}{tip_str}")

            if cfg.get("force_global_mode", True) and str(orig_mode).lower() != "global":
                clash.set_mode("global")
                mode_changed = True
                self._log("已临时切换到 global 模式")

            for i, node in enumerate(nodes):
                if self._stop.is_set():
                    note = "手动停止"
                    break
                self.state["current"] = node
                self._test_one(clash, group, proxy_url, run_id, node, cfg)
                self.state["done"] = i + 1
                gap = float(cfg.get("interval_sec", 0.5))
                if gap > 0 and i + 1 < len(nodes):
                    self._stop.wait(gap)
        except Exception as e:
            note = f"异常中止：{e}"
            self.state["last_error"] = str(e)
            self._log(note, "error")
            self._log(traceback.format_exc(), "error")
        finally:
            # 恢复现场
            try:
                if orig_sel:
                    clash.select(group, orig_sel)
                if mode_changed and orig_mode:
                    clash.set_mode(orig_mode)
                self._log(f"已恢复：[{group}] -> {orig_sel}；模式 -> {orig_mode}")
            except Exception as e:
                self._log(f"恢复原状态失败，请手动检查 Clash：{e}", "error")
            self.store.finish_run(run_id, self.state["ok"], self.state["fail"], note)
            self.state.update(running=False, current=None, finished_at=time.time())
            self._log(f"完成：成功 {self.state['ok']}，失败 {self.state['fail']}"
                      + (f"（{note}）" if note else ""))

    def _test_one(self, clash: ClashAPI, group: str, proxy_url: str, run_id: int, node: str, cfg):
        delay = None
        if cfg.get("precheck_delay", True):
            delay = clash.delay(node, cfg.get("delay_url", "https://www.gstatic.com/generate_204"),
                                int(cfg.get("delay_timeout_ms", 5000)))
            if delay is None:
                data = {"ok": False, "error": "Clash 延迟测试失败（节点不可用），已跳过"}
                self.store.add_result(run_id, node, data, None)
                self.state["fail"] += 1
                self._log(f"✗ {node}：延迟测试失败，跳过", "warn")
                return

        try:
            clash.select(group, node)
        except ClashError as e:
            self.store.add_result(run_id, node, {"ok": False, "error": f"切换节点失败：{e}"}, delay)
            self.state["fail"] += 1
            self._log(f"✗ {node}：切换失败 {e}", "error")
            return
        now = clash.proxy(group).get("now")
        if now != node:
            self.store.add_result(run_id, node, {"ok": False, "error": f"切换后 {group} 实际为 {now}"}, delay)
            self.state["fail"] += 1
            self._log(f"✗ {node}：切换未生效（当前 {now}）", "error")
            return
        wait = float(cfg.get("switch_wait_sec", 0.3))
        if wait > 0:
            time.sleep(wait)

        retries = int(cfg.get("retries", 1))
        check_gem = bool(cfg.get("check_gemini", True)) and not self._stop.is_set()
        check_yt = bool(cfg.get("check_yt_translate", True)) and not self._stop.is_set()

        def _run_ipcx() -> dict:
            res = {}
            for attempt in range(retries + 1):
                res = ipcx.fetch(proxy_url, float(cfg.get("timeout_sec", 15)), bool(cfg.get("with_geo_api", False)))
                if res.get("ok") or self._stop.is_set():
                    break
                self._log(f"… {node}：第 {attempt + 1} 次失败（{res.get('error')}），重试", "warn")
                time.sleep(1)
            return res

        def _run_gemini() -> dict:
            try:
                return gemini.check(
                    proxy_url,
                    timeout=max(1.0, float(cfg.get("gemini_timeout_sec") or 12)),
                    api_key=str(cfg.get("gemini_api_key") or ""),
                    api_model=str(cfg.get("gemini_api_model") or gemini.DEFAULT_API_MODEL),
                )
            except Exception as e:
                return {
                    "gemini_level": "error",
                    "gemini_detail": {
                        "level": "error",
                        "label": "检测失败",
                        "error": f"{type(e).__name__}: {e}",
                    },
                }

        def _run_yt() -> dict:
            try:
                return youtube.check(
                    proxy_url,
                    timeout=max(1.0, float(cfg.get("yt_timeout_sec") or 12)),
                    video_id=str(cfg.get("yt_video_id") or youtube.DEFAULT_VIDEO_ID),
                )
            except Exception as e:
                msg = f"{type(e).__name__}: {e}"
                return {
                    "yt_translate_status": "error",
                    "yt_translate_code": 0,
                    "yt_translate_detail": msg,
                    "yt_translate_ms": 0,
                    "yt_translate_extra": {
                        "status": "error",
                        "label": "检测失败",
                        "http_status": 0,
                        "detail": msg,
                    },
                }

        # 阶段 1：ip.cx 与 YouTube 字幕翻译并发执行（不同域名互不干扰，且让 YouTube 在最干净的状态下先测）
        # 若未开启 YouTube，则让 ip.cx 与 Gemini 直接并发；若两者都开启，则将 Gemini 错峰放在阶段 2，
        # 避免同一节点同一毫秒并发轰炸 6 个 Google 接口互相牵连限流。
        if check_yt:
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                f_ipcx = pool.submit(_run_ipcx)
                f_yt = pool.submit(_run_yt)
                data = f_ipcx.result()
                data.update(f_yt.result())

            if check_gem and not self._stop.is_set():
                node_reachable = (
                    bool(data.get("ok"))
                    or str(data.get("error") or "").startswith("HTTP ")
                    or bool(data.get("yt_translate_code"))
                )
                if node_reachable:
                    g = _run_gemini()
                    gemini.apply_ipcx_country(g, str(data.get("country_code") or ""))
                    data.update(g)
        elif check_gem:
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                f_ipcx = pool.submit(_run_ipcx)
                f_gem = pool.submit(_run_gemini)
                data = f_ipcx.result()
                g = f_gem.result()
                gemini.apply_ipcx_country(g, str(data.get("country_code") or ""))
                data.update(g)
        else:
            data = _run_ipcx()

        self.store.add_result(run_id, node, data, delay)
        gem_str = f" | Gemini: {gemini.format_summary(data)}" if data.get("gemini_level") else ""
        yt_str = f" | YT翻译: {youtube.format_summary(data)}" if data.get("yt_translate_status") else ""
        if data.get("ok"):
            self.state["ok"] += 1
            self._log(f"✓ {node} → {data.get('ip')}  {data.get('flag', '')}{data.get('country', '')} "
                      f"{data.get('city', '')} | {data.get('isp', '')} | {data.get('ip_type', '')} | "
                      f"评分 {data.get('score')}{gem_str}{yt_str}")
        else:
            self.state["fail"] += 1
            self._log(f"✗ {node}：{data.get('error')}{gem_str}{yt_str}", "error")
