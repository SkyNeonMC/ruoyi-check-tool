#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""RuoYi 弱口令检测工具

仅用于自有靶场或已获得明确授权的环境。

工作流程：
  1. 自动探测 API 前缀（/prod-api、/dev-api 或无前缀）
  2. 读取验证码开关：关闭时直接登录；开启时用 ddddocr 识别或手动输入
  3. POST /login 校验凭据，依据返回 JSON 的 code / msg 判断结果
  4. 命中后保存结果；检测到账号锁定立即停止该目标

依赖：requests；验证码识别可选 ddddocr
"""

import argparse
import base64
import csv
import json
import sys
import time
from datetime import datetime

import requests

__version__ = "1.1.0"

DEFAULT_CREDS = [
    ("admin", "admin123"),
    ("ruoyi", "admin123"),
    ("admin", "ruoyi123"),
    ("admin", "123456"),
    ("test", "test123"),
]

LOCK_HINTS = ("锁定", "lock")
CAPTCHA_HINTS = ("验证码", "captcha")

_ocr = None
_ocr_failed = False


def load_ocr():
    """惰性加载 ddddocr，避免未开启验证码时白白加载模型。"""
    global _ocr, _ocr_failed
    if _ocr is not None or _ocr_failed:
        return _ocr
    try:
        import ddddocr

        _ocr = ddddocr.DdddOcr(show_ad=False)
    except Exception as exc:
        _ocr_failed = True
        print(f"[WARN] ddddocr 不可用：{exc}")
    return _ocr


def new_session():
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0",
            "Accept": "application/json, text/javascript, */*; q=0.01",
        }
    )
    return session


def detect_api(target, session, timeout):
    """探测 RuoYi 接口前缀，返回 (api_base, captcha_data)。"""
    target = target.rstrip("/")
    if target.endswith("/login"):
        target = target[: -len("/login")]
    for api in (target + "/prod-api", target + "/dev-api", target):
        try:
            resp = session.get(api + "/captchaImage", timeout=timeout)
            data = resp.json()
        except Exception:
            continue
        if isinstance(data, dict) and "captchaEnabled" in data:
            return api, data
    return None, None


def load_creds(path):
    """读取 user:pass 或 user,pass 格式的凭据文件。"""
    creds = []
    with open(path, "r", encoding="utf-8-sig") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                user, pwd = line.split(":", 1)
            elif "," in line:
                user, pwd = line.split(",", 1)
            else:
                continue
            creds.append((user.strip(), pwd.strip()))
    return creds


def build_creds(args):
    if args.creds:
        return load_creds(args.creds), f"文件 {args.creds}"
    if args.users or args.passwords:
        if not (args.users and args.passwords):
            print("[ERROR] -U 与 -P 需要同时指定。")
            sys.exit(1)
        users = [u.strip() for u in open(args.users, encoding="utf-8-sig") if u.strip() and not u.startswith("#")]
        pwds = [p.strip() for p in open(args.passwords, encoding="utf-8-sig") if p.strip() and not p.startswith("#")]
        return [(u, p) for u in users for p in pwds], f"用户 {len(users)} × 密码 {len(pwds)}"
    return DEFAULT_CREDS, "内置常见弱口令"


def read_targets(args):
    if args.url:
        return [args.url.strip()]
    targets = []
    with open(args.targets, "r", encoding="utf-8-sig") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)
    return targets


def get_captcha(api, session, timeout, manual):
    """获取验证码文本，返回 (code, uuid)；无法处理时返回 (None, None)。"""
    data = session.get(api + "/captchaImage", timeout=timeout).json()
    if not data.get("captchaEnabled"):
        return "", ""
    img = data.get("img", "")
    uuid = data.get("uuid", "")
    if not img:
        return "", uuid
    ocr = load_ocr()
    if ocr is not None:
        return ocr.classification(base64.b64decode(img)), uuid
    if manual:
        return input("请输入验证码图片中的字符: ").strip(), uuid
    return None, None


def attempt_login(api, user, pwd, session, timeout, captcha_enabled, manual):
    """返回 (状态, 提示信息)；状态：success/fail/captcha/locked/error"""
    code, uuid = "", ""
    if captcha_enabled:
        code, uuid = get_captcha(api, session, timeout, manual)
        if code is None:
            return "error", "需要识别验证码，请安装 ddddocr 或加 --manual"

    payload = {"username": user, "password": pwd}
    if captcha_enabled:
        payload.update({"code": code, "uuid": uuid})

    try:
        resp = session.post(api + "/login", json=payload, timeout=timeout)
    except requests.RequestException as exc:
        return "error", f"请求异常：{exc}"

    try:
        data = resp.json()
    except ValueError:
        return "error", f"非 JSON 响应（HTTP {resp.status_code}）：{resp.text[:120]}"

    msg = str(data.get("msg", ""))
    if data.get("code") == 200:
        return "success", msg
    if any(k in msg.lower() for k in LOCK_HINTS):
        return "locked", msg
    if any(k in msg.lower() for k in CAPTCHA_HINTS):
        return "captcha", msg
    return "fail", msg


def save_hit(out_path, json_path, hit):
    with open(out_path, "a", encoding="utf-8") as f:
        f.write(f"{hit['target']}\nusername:{hit['username']}, password:{hit['password']}\n")
    hits = []
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            hits = json.load(f)
    except (FileNotFoundError, ValueError):
        pass
    hits.append(hit)
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(hits, f, ensure_ascii=False, indent=2)


def run_target(target, creds, args, session, hits, records):
    record = {
        "target": target,
        "api": "",
        "captcha": "",
        "status": "",
        "attempts": 0,
        "hit": "",
        "last_msg": "",
    }
    records.append(record)

    api, meta = detect_api(target, session, args.timeout)
    if not api:
        record["status"] = "error"
        record["last_msg"] = "未探测到 /captchaImage 接口"
        print(f"[ERROR] {target} 未探测到 /captchaImage 接口，跳过。")
        return "error"

    record["api"] = api
    captcha_enabled = bool(meta.get("captchaEnabled"))
    record["captcha"] = "开启" if captcha_enabled else "关闭"
    print(f"[INFO] 目标：{target}")
    print(f"[INFO] 接口前缀：{api}")
    print(f"[INFO] 验证码：{'开启' if captcha_enabled else '关闭'}")

    if captcha_enabled and args.skip_captcha:
        record["status"] = "skipped"
        record["last_msg"] = "开启验证码，按 --skip-captcha 跳过"
        print("[SKIP] 目标开启验证码，已跳过（加 --skip-captcha 时不尝试）。")
        return "skipped"

    if captcha_enabled and load_ocr() is None and not args.manual:
        record["status"] = "error"
        record["last_msg"] = "ddddocr 不可用且未指定 --manual"
        print("[ERROR] 目标开启验证码，但 ddddocr 不可用。安装：pip install ddddocr，或加 --manual。")
        return "error"

    if args.probe:
        record["status"] = "probe"
        return "probe"

    for idx, (user, pwd) in enumerate(creds, 1):
        status, msg = attempt_login(api, user, pwd, session, args.timeout, captcha_enabled, args.manual)

        retry = 0
        while status == "captcha" and retry < 3:
            retry += 1
            print(f"[WARN] 验证码错误，重试第 {retry} 次")
            status, msg = attempt_login(api, user, pwd, session, args.timeout, captcha_enabled, args.manual)

        record["attempts"] = idx
        record["last_msg"] = msg
        print(f"[{idx}/{len(creds)}] {user}:{pwd} -> {status} | {msg}")

        if status == "success":
            hit = {
                "target": target,
                "api": api,
                "username": user,
                "password": pwd,
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
            hits.append(hit)
            save_hit(args.out, args.json, hit)
            record["status"] = "hit"
            record["hit"] = f"{user} / {pwd}"
            print(f"[+] 命中，已保存到 {args.out} 和 {args.json}")
            return "hit"
        if status == "locked":
            record["status"] = "locked"
            print("[!] 账号已锁定，停止该目标。")
            return "locked"
        if status == "error":
            record["status"] = "error"
            return "error"

        time.sleep(args.delay)

    record["status"] = "done"
    return "done"


STATUS_CN = {
    "hit": "命中",
    "locked": "锁定",
    "error": "异常",
    "done": "完成无命中",
    "probe": "仅探测",
    "skipped": "跳过验证码",
}


def write_csv_report(records, path):
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["目标", "接口前缀", "验证码", "状态", "尝试次数", "命中凭据", "最后提示"])
        for r in records:
            writer.writerow(
                [
                    r["target"],
                    r["api"],
                    r["captcha"],
                    STATUS_CN.get(r["status"], r["status"]),
                    r["attempts"],
                    r["hit"],
                    r["last_msg"],
                ]
            )


def write_html_report(records, stats, hits, path):
    cards = "".join(
        f'<div class="card"><div class="num">{stats.get(k, 0)}</div><div class="label">{label}</div></div>'
        for k, label in [
            ("hit", "命中"),
            ("locked", "锁定"),
            ("error", "异常"),
            ("done", "完成无命中"),
            ("skipped", "跳过验证码"),
            ("probe", "仅探测"),
        ]
    )
    rows = ""
    for r in records:
        cls = "hit" if r["status"] == "hit" else ("err" if r["status"] in ("error", "locked") else "")
        rows += (
            f'<tr class="{cls}"><td>{r["target"]}</td><td>{r["api"]}</td>'
            f'<td>{r["captcha"]}</td><td>{STATUS_CN.get(r["status"], r["status"])}</td>'
            f'<td>{r["attempts"]}</td><td>{r["hit"]}</td><td>{r["last_msg"]}</td></tr>'
        )
    hit_rows = "".join(
        f'<tr><td>{h["target"]}</td><td>{h["username"]}</td><td>{h["password"]}</td><td>{h["time"]}</td></tr>'
        for h in hits
    ) or '<tr><td colspan="4">无</td></tr>'
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html = f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>RuoYi 检测报告</title>
<style>
 body{{font-family:Segoe UI,Microsoft YaHei,sans-serif;margin:24px;color:#222}}
 h2{{margin-top:32px}}
 .cards{{display:flex;gap:12px;flex-wrap:wrap}}
 .card{{min-width:110px;padding:14px 18px;border-radius:8px;background:#f5f7fa;border:1px solid #e4e7ed}}
 .card .num{{font-size:26px;font-weight:700}}
 .card .label{{color:#666;font-size:13px;margin-top:4px}}
 table{{border-collapse:collapse;width:100%;margin-top:12px;font-size:14px}}
 th,td{{border:1px solid #e4e7ed;padding:8px 10px;text-align:left}}
 th{{background:#f5f7fa}}
 tr.hit td{{background:#f0f9eb}}
 tr.err td{{background:#fef0f0}}
 .muted{{color:#999;font-size:13px}}
</style></head><body>
<h1>RuoYi 弱口令检测报告</h1>
<div class="muted">生成时间：{now} ｜ 目标总数：{len(records)}</div>
<div class="cards">{cards}</div>
<h2>目标结果</h2>
<table><thead><tr><th>目标</th><th>接口前缀</th><th>验证码</th><th>状态</th><th>尝试次数</th><th>命中凭据</th><th>最后提示</th></tr></thead>
<tbody>{rows}</tbody></table>
<h2>命中列表</h2>
<table><thead><tr><th>目标</th><th>用户名</th><th>密码</th><th>时间</th></tr></thead><tbody>{hit_rows}</tbody></table>
</body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)


def generate_reports(args, records, stats, hits):
    if args.report == "none":
        return
    name = args.report_name
    written = []
    if args.report in ("html", "both"):
        write_html_report(records, stats, hits, name + ".html")
        written.append(name + ".html")
    if args.report in ("csv", "both"):
        write_csv_report(records, name + ".csv")
        written.append(name + ".csv")
    if written:
        print(f"[INFO] 报告已生成：{'、'.join(written)}")


def main():
    parser = argparse.ArgumentParser(
        description="RuoYi 弱口令检测工具（仅限自有靶场或已授权环境）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-u", "--url", help="单个目标地址，如 http://127.0.0.1:8080")
    parser.add_argument("-t", "--targets", help="目标列表文件，每行一个地址")
    parser.add_argument("-c", "--creds", help="凭据文件，每行 user:pass 或 user,pass")
    parser.add_argument("-U", "--users", help="用户名字典文件")
    parser.add_argument("-P", "--passwords", help="密码字典文件")
    parser.add_argument("--delay", type=float, default=1.5, help="每次尝试间隔秒数，默认 1.5")
    parser.add_argument("--timeout", type=float, default=10, help="请求超时秒数，默认 10")
    parser.add_argument("--manual", action="store_true", help="未安装 ddddocr 时手动输入验证码")
    parser.add_argument("--probe", action="store_true", help="只探测接口和验证码配置，不尝试登录")
    parser.add_argument("--out", default="ruoyi_hit.txt", help="命中结果文本文件，默认 ruoyi_hit.txt")
    parser.add_argument("--json", default="ruoyi_hit.json", help="命中结果 JSON 文件，默认 ruoyi_hit.json")
    parser.add_argument("--skip-captcha", action="store_true", help="目标开启验证码时直接跳过，不尝试登录")
    parser.add_argument(
        "--report", choices=["none", "html", "csv", "both"], default="both", help="跑完自动生成报告，默认 both"
    )
    parser.add_argument("--report-name", default="ruoyi_report", help="报告文件名前缀，默认 ruoyi_report")
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args()

    if not args.url and not args.targets:
        parser.print_help()
        sys.exit(1)

    print("[!] 本工具仅用于自有靶场或已获得授权的目标，请遵守当地法律法规。")
    creds, desc = build_creds(args)
    targets = read_targets(args)
    session = new_session()

    print(f"[INFO] 目标数：{len(targets)}，凭据：{desc}（共 {len(creds)} 组），间隔 {args.delay}s\n")

    hits = []
    records = []
    stats = {"hit": 0, "locked": 0, "error": 0, "done": 0, "probe": 0, "skipped": 0}
    try:
        for target in targets:
            result = run_target(target, creds, args, session, hits, records)
            stats[result] = stats.get(result, 0) + 1
            if result == "hit":
                print(f"[+] {target} 命中，跳过该目标的剩余凭据。")
            print()
    except KeyboardInterrupt:
        print("\n[!] 已手动中断。")
    finally:
        generate_reports(args, records, stats, hits)

    print("===== 统计 =====")
    print(
        f"目标 {len(targets)} 个：命中 {stats['hit']}，锁定 {stats['locked']}，异常 {stats['error']}，"
        f"完成 {stats['done']}，跳过验证码 {stats['skipped']}，仅探测 {stats['probe']}"
    )
    for hit in hits:
        print(f"  {hit['target']}  {hit['username']} / {hit['password']}")


if __name__ == "__main__":
    main()
