# SecEventMonitor

面向单管理员场景的轻量安全监控平台，当前采用 `FastAPI + Jinja2 + SQLite` 单体架构，聚焦漏洞列表、钉钉/飞书推送配置和基础系统初始化。

## 当前骨架

```text
.
├── seceventmonitor
│   ├── __main__.py        # 模块启动入口
│   ├── config.py          # 全局配置
│   ├── extensions.py      # SQLAlchemy 兼容层
│   ├── jinja_ui.py        # Jinja2 页面与路由
│   ├── models             # SQLite3 表模型
│   ├── services           # 采集器、推送器、系统初始化
│   ├── static             # 后台样式资源
│   ├── templates          # Jinja2 模板
│   ├── db                 # 数据库脚本预留
│   ├── schemas           # 数据结构预留
│   └── utils             # 工具函数
├── data                   # 运行时 SQLite 数据目录
├── tests                  # 基础烟雾测试
├── requirements.txt
├── .env.example
└── selfproject            # 参考项目资料
```

## 一期已落地内容

- 单管理员初始化页与登录页
- `FastAPI + Jinja2` 单体后台
- SQLite3 表模型与服务层
- 服务端渲染后台：概览、漏洞列表、推送配置、系统设置
- 漏洞采集器与推送器模块
- `NVD 2.0 API` 增量采集已接入
- 钉钉、飞书 webhook 测试发送接口已接入
- 当前漏洞采集来源已移除阿里云漏洞库

## 接口

- `GET /api/health`

其余初始化、登录、同步、规则管理和推送配置均通过 `Jinja2` 服务端页面完成，不再依赖单独前端工程。

## 采集说明

### NVD

- 当前接入官方 `2.0` 接口：`https://services.nvd.nist.gov/rest/json/cves/2.0`
- 采用 `lastModStartDate / lastModEndDate` 做增量同步
- 首次没有历史成功记录时，只会回溯最近 `24` 小时并全量分页拉取
- 后续增量同步会按 `startIndex / resultsPerPage` 全量翻页，直到窗口内数据抓取完成
- 手动同步改为后台异步执行，不阻塞主界面；监控页会根据后台任务状态展示当前拉取进度
- 可在监控配置中配置 `nvd_api_key`

## 推送说明

- 钉钉：支持 webhook + 加签 secret
- 飞书：支持 webhook/token + 签名 secret
- 推送配置页已提供“测试发送”按钮

## 本地启动

```bash
python3 -m venv .venv
./.venv/bin/pip install -r requirements.txt
cp .env.example .env
./.venv/bin/python -m seceventmonitor
```

默认监听 `http://127.0.0.1:20000`

默认数据库路径为当前运行目录下的 `data/sec_event_monitor.db`，也可通过 `SQLITE_DB_PATH` 覆盖。

## 验证

```bash
./.venv/bin/python -m unittest tests.test_jinja_ui
```

## 下一步建议

1. 完善 `NVD` 的筛选策略、分页上限和字段映射
2. 增加 APScheduler 定时任务和 `sync_job_logs` 写入
3. 为敏感配置增加加密存储与前端掩码展示
4. 增加漏洞详情页、事件历史和推送日志页
