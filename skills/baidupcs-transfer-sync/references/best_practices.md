# BaiduPCS-Go 安装、配置、登录与避坑完全指南

本参考基于社区实操经验与 Notion 科研沉淀整理，适用于 Linux / WSL / 远程服务器环境。

---

## 1. 安装与路径规范

- **官方推荐发布分支**：GitHub [qjfoidnh/BaiduPCS-Go](https://github.com/qjfoidnh/BaiduPCS-Go)（原版基础上集成了分享链接、秒传转存功能）。
- **常用架构 Release 包**：
  - Linux x86_64 / WSL：`BaiduPCS-Go-v4.0.2-linux-amd64.zip`
- **建议安装布局**：
  - 解压路径：`~/.local/opt/BaiduPCS-Go/BaiduPCS-Go-v4.0.2-linux-amd64/BaiduPCS-Go`
  - PATH 符号链接：`~/bin/BaiduPCS-Go`（确保 `~/bin` 在 `$PATH` 中）
  - 配置文件目录：`~/.config/BaiduPCS-Go/pcs_config.json`

---

## 2. 登录认证机制（硬规则：必须 BDUSS + STOKEN）

> ⚠️ **重要警告**：
> 1. 百度已关闭账号密码交互式登录，必须通过提取 Cookie 中的凭据登录。
> 2. `BDUSS` 为 HttpOnly Cookie，且现代 Chrome/Edge 磁盘数据库采用 `v20 app-bound` 本地加密，**禁止直接从浏览器 sqlite 文件强解**。
> 3. 仅有 `BDUSS` 时：`who` 和 `quota` 可以执行，但执行 `ls`、`download`、`transfer` 会直接报错 `-6 请重新登录`。**必须同时提供 STOKEN**。

### 2.1 获取 Cookie 的正确姿势
1. 在浏览器打开并登录 [pan.baidu.com](https://pan.baidu.com)；
2. 按 `F12` 打开开发者工具，切换到 **Network (网络)** 面板；
3. 勾选 **Fetch/XHR** 筛选器，刷新页面；
4. 找到一个状态码为 200 的内部接口请求（**推荐**：`tasklist?clienttype=0...` 或 `contentFe?...`）；
   - ⚠️ **切勿选择** `abclite-2096-sjs`、前端静态脚本、png 图片或 WebSocket 请求。
5. 点击该请求，在右侧 **Request Headers (请求标头)** 中复制完整的 `Cookie` 字符串。

### 2.2 绕过官方 v4.0.2 的 `-cookies` Panic 缺陷
- **缺陷表现**：
  官方源码中正则匹配 `BDUSS=(.+?);`，如果复制出来的 Cookie 字符串中 `BDUSS` 位于末尾且没有分号结尾，会直接引发 Go 运行时崩溃：
  ```plain text
  panic: runtime error: index out of range [1] with length 0
  ```
- **避坑方案**：
  使用技能内置的 `scripts/login.sh`，或者在 shell 中先手动提取字段，改用 `-bduss` 和 `-stoken` 参数分别指定：
  ```bash
  BaiduPCS-Go login -bduss="<BDUSS_VALUE>" -stoken="<STOKEN_VALUE>"
  ```

---

## 3. 常用配置参数与调优

为避免触发百度网盘高频并发风控并提高下载吞吐量，建议设置：
```bash
# 设置最大并发连接数和下载并发负载
BaiduPCS-Go config set -max_parallel 10 -max_download_load 1

# 查看当前配置
BaiduPCS-Go config
```

---

## 4. 常见故障排查表 (Troubleshooting)

| 现象 | 根因分析 | 解决措施 |
|---|---|---|
| `panic: index out of range [1]` | 使用 `-cookies` 参数时，字符串末尾的 `BDUSS` 缺少分号导致正则越界 | 使用 `scripts/login.sh` 或改用 `-bduss` + `-stoken` 参数 |
| `who` 显示正常，但 `ls` 报错 `-6` | 缺失 `STOKEN`，只有只读简易权限 | 补齐 `STOKEN` 参数后重新执行 login |
| 控制台 JS 无法提取 `BDUSS` | `BDUSS` 具有 `HttpOnly` 安全属性 | 从 DevTools Network 请求标头或 Cookie 扩展中提取 |
| 从本地 Chrome 文件解密失败 | Windows/Chrome v20 应用绑定加密机制阻止第三方读取 | 不硬解磁盘文件，改用网络请求抓取或浏览器自动化 CDP 会话注入 |
| `transfer` 转存命令返回空列表 | 百度分享转存接口风控或链接解析限制 | 优先在已认证的宿主浏览器前端页面点击“保存到网盘”，随后在 CLI 整理 |
