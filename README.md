# SQL Injection Tester

用于在授权环境中对目标 URL 的 GET 参数进行基础 SQL 注入测试。默认配置面向本机 DVWA 风格测试环境。

## 运行

```bash
./venv/Scripts/python.exe sqli_tester.py
```

## 自定义目标

```bash
./venv/Scripts/python.exe sqli_tester.py --url "http://127.0.0.1/vulnerabilities/sqli/?id=1&Submit=submit#" --cookie "PHPSESSID=...; security=low"
```

## 文件

- `config.py`: 默认 Cookie、目标 URL、超时和请求间隔。
- `sqli_tester.py`: 命令行测试工具。
