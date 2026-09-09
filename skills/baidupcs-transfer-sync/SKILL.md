---
name: baidupcs-transfer-sync
description: 转存百度网盘公开分享文件并使用 BaiduPCS-Go 进行安装、配置、登录、目录规划与增量同步下载到本地或远程服务器。适用于从零安装与配置 BaiduPCS-Go CLI、提取 BDUSS/STOKEN 凭据安全登录、管理 /research 科研目录树、转存新版本公开资料并进行非覆盖式增量下载的任务。
---

# BaiduPCS-Go 转存、配置与增量同步技能

本技能涵盖从零安装与配置 `BaiduPCS-Go` CLI、基于 Cookie 凭据的安全登录、百度网盘科研数据架构（`/research`）治理、以及利用分享链接进行增量转存与服务器端非覆盖式增量下载的完整工作流。

## 安全边界

- 只使用用户当场提供或本机浏览器会话中的 Cookie；**禁止**把 `BDUSS`、`STOKEN`、完整 Cookie 写入仓库、日志、计划 JSON 或聊天记录。
- `scripts/login.sh` 只把凭据传给 `BaiduPCS-Go login`，不要 `echo` 完整 Cookie。
- 默认不做破坏性覆盖：增量比对后只下载本地缺失文件；覆盖、整目录替换或删除需用户另行确认。
- 本技能不捆绑账号、Cookie 或本机绝对路径；`BaiduPCS-Go` 路径用 `PCS_BIN`、`--pcs-bin` 或 `~/bin/BaiduPCS-Go`。

## 适用场景
- 用户需要指导在 Linux / WSL / 远程服务器上安装、配置并登录 `BaiduPCS-Go`。
- 处理登录认证问题（提取 `BDUSS` + `STOKEN`、规避官方 v4.0.2 的 `-cookies` panic 崩溃、解决 `ls` 返回 `-6` 等故障）。
- 规划或整理百度网盘科研目录结构（遵循 `/research` 八大规范分类）。
- 接收到更新版本分享链接，需要增量归集到现有网盘目录并下载到服务器，杜绝破坏性覆盖。

---

## 核心流程与步骤

### 阶段 1：CLI 安装与安全登录配置

1. **安装推荐版本**：
   - 优先选择 GitHub [qjfoidnh/BaiduPCS-Go](https://github.com/qjfoidnh/BaiduPCS-Go) 发行版（内置分享转存功能），推荐安装 `v4.0.2` linux-amd64 版本。
   - 规范软链接至 `~/bin/BaiduPCS-Go` 并加入 `$PATH`。

2. **凭据提取与登录（必须 BDUSS + STOKEN）**：
   - 打开浏览器访问已登录的 `pan.baidu.com`，打开 F12 DevTools -> **Network** 面板，勾选 **Fetch/XHR** 并刷新；
   - 选择一个状态为 200 的接口请求（如 `tasklist` 或 `contentFe`，切勿选 `abclite` 等静态文件），复制其 **Request Headers -> Cookie**。
   - **执行安全登录**（调用随附脚本 `scripts/login.sh` 自动解析，或显式传入双参数）：
     ```bash
     BaiduPCS-Go login -bduss="<BDUSS>" -stoken="<STOKEN>"
     ```
   - ⚠️ **避坑硬规则**：
     - 切勿仅传入 `BDUSS`，否则执行 `who` 正常，但执行 `ls` 或下载时会报 `-6 请重新登录`。
     - 避免直接使用官方 `-cookies` 命令行参数：若 `BDUSS` 位于字符串末尾缺少分号，会触发 Go 运行时 `panic: index out of range [1]`。

3. **并发与网络调优**：
   ```bash
   BaiduPCS-Go config set -max_parallel 10 -max_download_load 1
   ```

---

### 阶段 2：网盘端科研目录规范与增量转存

1. **遵循 `/research` 科研目录架构**（详见 `references/directory_schema.md`）：
   - 顶层划分：`00-inbox`、`01-rawdata`、`02-references`、`03-software`、`04-courses`、`05-projects`、`06-literature`、`07-personal`。
2. **转存与增量整理**：
   - 使用浏览器或 CDP 注入凭据后打开分享链接，保存至个人网盘；
   - 通过 `BaiduPCS-Go ls` 探测差异：
     - 新增模块：直接使用 `BaiduPCS-Go mv <src> <dest>` 归入对应分类；
     - 存在同名重叠的目录：深入子目录比对，仅迁移新增的数据文件与脚本，保留原有整理。

---

### 阶段 3：服务器端增量比对与下载

1. **双端清单比对**：
   - 运行随附脚本 `scripts/compare_manifest.py`：
     ```bash
     python3 scripts/compare_manifest.py \
       --pcs-bin ~/bin/BaiduPCS-Go \
       --remote-base "/research/04-courses/..." \
       --local-base "/path/to/local/..." \
       --output-json /tmp/incremental_plan.json
     ```
2. **执行增量下载与校验**：
   - 运行随附脚本 `scripts/incremental_download.py`，传入 `--plan-json /tmp/incremental_plan.json` 执行非覆盖下载；
   - 任务完成后遍历本地目标文件，断言 `missing_in_local` 清单 100% 存在且大小正常。

---

## 随附资源速查
- `scripts/login.sh`：自动解析 Cookie 并安全登录的 Shell 脚本（防 panic）。
- `scripts/compare_manifest.py`：网盘与本地文件清单递归扫描与差异比对工具。
- `scripts/incremental_download.py`：按目录聚合的增量下载与断言校验工具。
- `scripts/verify_skill.py`：离线结构校验（frontmatter、路径引用、禁止个人路径、解析夹具）。
- `references/best_practices.md`：详细故障排查表（排查 -6 错误、Cookie 加密、并发参数等）。
- `references/directory_schema.md`：个人网盘科研数据分类与归位标准指南。
