# ip.cx 节点出口记录器

逐个切换 Clash（Mihomo）节点，经由该节点访问 https://ip.cx/，解析出口 IP 的
归属地、ISP、ASN、IP 类型（数据中心/住宅）、代理/威胁状态、IP 评分等信息，并记录到本地 SQLite。
自带网页界面，**只依赖 Python 标准库**（不用 pip 安装任何东西）。

## 启动

双击 `start.bat`，或：

```
python app.py            # 自动打开浏览器 http://127.0.0.1:8866
python app.py --no-browser
```

首次运行会生成 `config.json`（默认 Clash 控制器 `http://127.0.0.1:9097`，密钥 `123`），
也可以在网页「设置」页修改。

## 工作原理

1. 记下 Clash 当前的运行模式和 `GLOBAL` 组的选中项；
2. 临时切到 `global` 模式；
3. 对每个节点：（可选）先用 Clash 自带延迟测试跳过死节点 → `PUT /proxies/GLOBAL` 选中该节点 →
   通过 Clash 的 mixed-port 新建连接访问 ip.cx → 解析页面并写入数据库；
4. 结束、出错或手动停止后，恢复原来的模式和选中项。

> 因为一个策略组同一时刻只能选一个节点，测试只能**串行**进行。测试期间本机其它走 Clash 的
> 流量也会跟着切换节点，测完会自动恢复。62 个节点大约需要 1～3 分钟。

## 功能

- 按策略组筛选、搜索、勾选节点；一键「选失败/未测」重测
- 实时进度和日志，可随时停止
- **Gemini 支持程度综合检测**（设置里默认开启，可关闭）：并发探测 Gemini 网页版、Google 实际识别地区（自动识别「送中」/地区漂移）、Google 风控/验证码、AI Studio 及 Gemini API（支持可选填 API Key 实测），分 6 级展示并支持筛选、排序与点击查看分项详情
- **YouTube 自动生成字幕翻译检测**（设置里默认开启，可关闭）：实时拉取公开视频的 `kind=="asr"` 自动生成英文字幕轨，探测 `/api/timedtext` 简体中文自动翻译是否触发 HTTP 429 限流或风控拦截，与 ip.cx / Gemini 并发执行，支持筛选、排序、详情弹窗与 CSV 导出
- 最新结果表：可排序、过滤；标记**多个节点共用同一出口 IP**、**IP 较上次变化**
- 点节点名看该节点全部历史；点 IP 看哪些节点出现过这个 IP
- 每次测试的记录，可查看 / 删除 / 导出
- 导出 CSV（带 BOM，Excel 直接打开）
- 定时自动测试（设置里填间隔分钟数，程序需保持运行）

## 文件

| 文件 | 说明 |
| --- | --- |
| `app.py` | Web 服务、API、定时任务 |
| `runner.py` | 批量测试流程（切换节点、恢复现场） |
| `clash.py` | Clash/Mihomo RESTful API 客户端 |
| `ipcx.py` | 访问并解析 ip.cx；可单独运行：`python ipcx.py http://127.0.0.1:7897` |
| `gemini.py` | 检测 Gemini 支持程度；可单独运行：`python gemini.py http://127.0.0.1:7897 [API_KEY]` |
| `youtube.py` | 检测 YouTube 自动字幕翻译可用性；可单独运行：`python youtube.py http://127.0.0.1:7897 [视频ID]` |
| `store.py` | SQLite 存储（自动无损迁移新增字段） |
| `static/index.html` | 前端页面 |
| `ipcx_records.db` | 记录数据库（运行后生成） |
