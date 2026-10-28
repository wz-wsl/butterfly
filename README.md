# Butterfly

网站信息收集命令行工具。v0.2 将目标解析、HTTP 请求、查询适配、检查逻辑和结果输出分离，保留原有命令参数。

| 功能 | 参数 | 实际行为 |
| --- | --- | --- |
| TCP 端口查询 | `-ps` | 将主机名和端口提交给 `tool.box3.cn`，不在本机实现端口探测 |
| 子域名查询 | `-do` | 将指定基域和字典前缀提交给 `phpinfo.me` |
| 目录/文件检查 | `-ds`、`-f` | 本机向目标发送 HTTP GET，按字典逐项检查 |
| 页面链接提取 | `-js` | 本机读取一次入口 HTML，提取标签和内联脚本中的静态链接 |

第三方服务会收到所查询的目标；其内部是否主动探测未经核实，不能保证为被动收集。原服务可能改版、限流或停止运营；v0.2 的自动化测试使用离线样本，未证明服务当前可用。服务返回异常时会明确报错，不把失败解释成没有结果。

## 安装与运行

需要 **Python 3.10 或以上版本**，运行和测试都只使用 Python 标准库。

直接从仓库运行：

```bash
python butterfly.py --help
python -m butterfly --version
```

也可以安装命令行入口：

```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell 使用 .venv\Scripts\Activate.ps1
python -m pip install -e .
butterfly --help
```

## 使用示例

下面的 `example.com` 是占位域名，运行前换成要检查的站点。裸主机名默认使用 HTTPS；HTTP 站点需要显式填写 `http://`。

```bash
# 使用原有常用端口列表查询 TCP 端口
python butterfly.py -ps example.com

# 原有闭区间参数继续支持
python butterfly.py -ps example.com -psm 79 -dsm 81

# 也可使用端口列表；与 -psm/-dsm 不能混用
butterfly -ps example.com --ports 80,443,8000-8002

# 子域名查询：完整保留指定基域，不自动删除 www 或其他标签
butterfly -do example.com
butterfly -do a.example.co.uk --subdomain-wordlist prefixes.txt

# 目录字典以输入 URL 的路径作为基路径
butterfly -ds https://example.com/app/ -f paths.txt

# 单页面静态链接提取，导出 JSON
butterfly -js https://example.com/ --format json -o links.json

# 可同时指定多个模块
butterfly -ps example.com --ports 443 -js https://example.com/ --format csv -o report.csv
```

URL 支持域名、IDNA 国际化域名、IPv4、方括号 IPv6（如 `http://[::1]:8080/`）和显式端口。子域名查询只接受域名。端口只能是 `1..65535`；端口查询报告 TCP，不推断 UDP 状态。`-do www.example.com` 的基域就是 `www.example.com`；要查询 `example.com` 下的名称，应明确输入 `example.com`。

### 字典规则

目录字典为 UTF-8 文本，每行一个路径，支持空行、以 `#` 开头的注释和 UTF-8 BOM；重复条目只检查一次。例如：

```text
# paths.txt
admin/
robots.txt
/login
```

以上字典配合 `https://example.com/app/` 时分别检查 `/app/admin/`、`/app/robots.txt`、`/app/login`。单个前导 `/` 兼容旧字典，仍相对于指定基路径。绝对 URL、协议相对外域地址、反斜线、父目录跳转和 URL 片段会被拒绝。输入 URL 自带的查询参数不自动复制到每个字典条目。

子域名字典每行一个 DNS 标签前缀，例如 `www`、`mail`、`api`；默认使用从旧版迁移、去重并修复 `mail`/`ftp` 拼接问题的内置字典。`--subdomain-wordlist` 可以覆盖默认字典。

### 网络选项

| 参数 | 默认值 | 含义 |
| --- | --- | --- |
| `--timeout` | `10` | 单次 socket 操作超时秒数，非整个任务的总时限 |
| `--retries` | `1` | GET 暂态网络错误及 429/502/503/504 的重试次数；POST 不自动重试 |
| `--max-bytes` | `2097152` | 单个响应体大小上限，超过后报告失败 |
| `--insecure` | 关闭 | 显式跳过 HTTPS 证书验证，报告中记录此状态 |

HTTPS 默认验证证书；使用系统代理配置。请求串行执行，第三方查询连续三次失败后停止该模块并说明后续条目未检查。3xx 响应只报告、不自动跟随；检查重定向目标时，需要显式使用报告中的新 URL。标准库实现没有连接池复用。

### 结果含义

目录检查会先请求两个随机不存在的路径。只有两个响应的状态及规范化内容一致时，才启用软 404 相似性判断；基准不可用时在报告中说明。

| 状态 | 含义 |
| --- | --- |
| `found` | 收到 2xx，且未命中软 404 启发式；不保证一定是独立有效资源 |
| `not_found` | HTTP 404 或 410 |
| `restricted` | HTTP 401 或 403，不能据此确认资源存在 |
| `redirect` | HTTP 3xx，记录 Location，不跟随 |
| `server_error` | HTTP 5xx，路径可能存在但服务端出错，需要人工复查 |
| `suspected_soft_404` | 内容接近不存在路径的响应模板，需要人工复查 |
| `error` | HTTP 异常或其他检查失败，原因保留在错误列表中 |

页面链接结果为 `discovered`，包含来源 URL 和引用位置。外部 JS 不会下载，链接也不会被进一步请求验证；未实现递归爬取或 JS 运行时分析。

## 输出与退出码

`--format table|json|csv` 使用同一份检查结果；`-o/--output` 在完整写入临时文件后原子替换目标文件。JSON 输出包含 `schema_version`、工具版本、UTC 时间，以及每个模块的 `status`、`checked`、`findings`、`warnings`、`errors`。模块状态区分：

- `success`：已完成检查，没有错误；可以没有发现。
- `partial`：部分检查完成，另有错误。
- `failed`：没有成功完成的检查，存在错误。

CSV 使用 `summary`、`finding`、`warning`、`error` 行保留相同信息，避免空结果文件掩盖查询失败。文件写入提示发送到 stderr，不污染 JSON/CSV 的 stdout。

退出码：`0` 完成且无错误；`1` 查询失败、部分失败或输出失败；`2` 参数/输入错误；`130` 用户中断。基准和功能边界提示属于 warning，不单独导致退出码 1。

## 开发与测试

```bash
python -m unittest discover -s tests -v
python -m compileall -q butterfly butterfly.py
```

测试通过固定响应和内存 HTTP transport 覆盖目标解析、TLS/超时/重试、第三方响应校验、目录判定、链接提取、旧命令参数及 JSON/CSV 导出，不依赖真实目标或第三方服务。GitHub Actions 配置了 Python 3.10、3.12、3.13 测试矩阵。

```text
butterfly.py             原命令兼容入口
butterfly/
  cli.py                参数、调用和退出码
  targets.py            URL、主机与字典路径
  http_client.py        有界 HTTP 请求
  providers.py          第三方服务适配
  scanners.py           目录检查、页面链接提取
  models.py             统一结果结构
  output.py             文本、JSON、CSV 和文件输出
  resources/            内置字典
tests/                  离线回归测试
```

原版截图仍保留在仓库中，展示的是旧版界面。仓库尚未声明开源许可证，外部复用的授权范围需由作者明确。
