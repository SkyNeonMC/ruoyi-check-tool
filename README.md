# RuoYi 弱口令检测工具

针对 RuoYi（若依）后台登录接口的轻量级弱口令检测脚本。直接请求 JSON 接口，不依赖浏览器，支持验证码自动识别、批量目标、防锁号保护。

> **免责声明**
>
> 本工具仅供**自有靶场**、**已获得书面授权**的安全测试或教学演示使用。
> 未经授权对他人系统进行弱口令测试属于违法行为，使用者需自行承担全部法律责任。
> 脚本默认采用低速、小字典、遇锁定即停止的策略，请勿修改为高频攻击用途。

## 功能特性

- **直连 API**：绕过前端页面，直接调用 `/captchaImage` 和 `/login` 接口，速度远快于浏览器自动化
- **前缀自适应**：自动识别 `/prod-api`、`/dev-api` 或无前缀的部署方式
- **验证码处理**：验证码关闭时直接登录；开启时优先使用 [ddddocr](https://github.com/sml2h3/ddddocr) 识别，识别错误自动换图重试，未安装时可手动输入
- **防锁号保护**：返回信息包含"锁定"时立即停止该目标，避免继续累计失败次数
- **批量目标**：支持从文件读取多个目标地址
- **多种凭据来源**：内置常见弱口令、`user:pass` 凭据文件、用户名字典 × 密码字典
- **结果留存**：命中结果同时写入文本和 JSON，便于后续整理
- **中断友好**：`Ctrl+C` 中断后仍会输出统计汇总

## 环境要求

- Python 3.8+
- 可访问目标站点的网络环境

## 安装

```bash
git clone https://github.com/SkyNeonMC/ruoyi-check-tool.git
cd ruoyi-check-tool
pip install -r requirements.txt
```

目标开启验证码时，额外安装识别库：

```bash
pip install ddddocr
```

## 快速开始

```bash
# 1. 先探测目标是否可访问、接口前缀与验证码配置（不会尝试登录）
python ruoyi_check.py -u http://127.0.0.1:8080 --probe

# 2. 使用内置常见弱口令测试单个目标
python ruoyi_check.py -u http://127.0.0.1:8080

# 3. 使用自己的凭据文件
python ruoyi_check.py -u http://127.0.0.1:8080 -c creds.txt

# 4. 用户名 + 密码字典组合测试
python ruoyi_check.py -u http://127.0.0.1:8080 -U users.txt -P passwords.txt --delay 2

# 5. 批量目标
python ruoyi_check.py -t targets.txt --delay 2
```

## 参数说明

| 参数 | 说明 |
| --- | --- |
| `-u, --url` | 单个目标地址，可写根地址或登录页地址 |
| `-t, --targets` | 目标列表文件，每行一个地址，`#` 开头为注释 |
| `-c, --creds` | 凭据文件，每行 `user:pass` 或 `user,pass` |
| `-U, --users` | 用户名字典文件，需与 `-P` 同时使用 |
| `-P, --passwords` | 密码字典文件 |
| `--delay` | 每次尝试的间隔秒数，默认 `1.5` |
| `--timeout` | 单次请求超时秒数，默认 `10` |
| `--manual` | 未安装 ddddocr 时手动输入验证码 |
| `--probe` | 只探测接口与验证码配置，不尝试登录 |
| `--out` | 命中结果文本文件，默认 `ruoyi_hit.txt` |
| `--json` | 命中结果 JSON 文件，默认 `ruoyi_hit.json` |
| `-v, --version` | 查看版本号 |

## 文件格式

`creds.txt`：

```text
admin:admin123
ruoyi:admin123
test,test123
```

`targets.txt`：

```text
http://127.0.0.1:8080
http://10.0.0.5:8081/login
# 这一行会被忽略
```

## 输出示例

```text
[!] 本工具仅用于自有靶场或已获得授权的目标，请遵守当地法律法规。
[INFO] 目标数：1，凭据：内置常见弱口令（共 5 组），间隔 1.5s

[INFO] 目标：http://127.0.0.1:8080
[INFO] 接口前缀：http://127.0.0.1:8080/prod-api
[INFO] 验证码：关闭
[1/5] admin:admin123 -> success | 操作成功
[+] 命中，已保存到 ruoyi_hit.txt 和 ruoyi_hit.json
```

## 工作原理

```text
GET  {api}/captchaImage            -> 获取验证码开关、uuid、base64 图片
     验证码开启时：ddddocr 识别     -> 得到 4 位字符
POST {api}/login  (JSON)           -> {"username","password","code","uuid"}
     根据返回 code / msg 判断      -> 成功 / 密码错误 / 验证码错误 / 锁定
```

结果判断不依赖响应长度，而是读取接口返回的 `code` 与 `msg`，因此误报率低。

## 常见问题

**Q：提示"未探测到 /captchaImage 接口"？**
确认地址可访问、协议（http/https）正确，且目标确实是 RuoYi 系后台。部分二次开发版本会修改接口前缀，可用浏览器开发者工具抓包确认后反馈。

**Q：目标开启验证码，识别率不高？**
`ddddocr` 对 RuoYi 默认算术/字符验证码识别率较高。若目标使用滑块、点选类验证码，本工具不适用。也可用 `--manual` 手动输入。

**Q：为什么只测几组就停了？**
RuoYi 默认连续 5 次密码错误会锁定账号 10 分钟。脚本检测到"锁定"关键词会主动停止，避免把账号锁死。

**Q：提示"非 JSON 响应"？**
通常是地址错误落到前端页面，或网关返回了 HTML 错误页。先用 `--probe` 确认接口是否正常。

## 致谢

思路参考了 Weakiller 弱口令自动化测试项目，本工具针对 RuoYi 的 JSON 登录接口重写，独立实现。

## License

本项目基于 [MIT License](LICENSE) 开源，可自由使用、修改和分发，但需保留版权声明。
使用者因使用本工具产生的一切后果由使用者自行承担。
