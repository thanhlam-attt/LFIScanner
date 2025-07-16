import requests
import json
import sys
import urllib3
import argparse
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from termcolor import cprint

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

KEYWORDS = [
    # Linux
    "/bin/bash",
    "/bin/sh",
    "/usr/sbin",
    "/usr/sbin/nologin",
    "root:x:0:0:",
    "daemon:",
    "nobody:",
    ":$6$",
    ":$1$",
    ":$2a$",
    "ssh-rsa",
    "BEGIN RSA PRIVATE KEY",
    "PermitRootLogin",
    "[mysqld]",
    "[global]",
    "localhost",
    "127.0.0.1",
    "access.log",
    "error.log",
    # Windows
    "[boot loader]",
    "[operating systems]",
    "WINDOWS\\SYSTEM32",
    "C:\\Windows",
    "C:\\boot.ini",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "<configuration>",
    "<connectionStrings>",
    "<appSettings>",
    "MZ",
    "This program cannot be run in DOS mode",
    "[fonts]",
    "[extensions]",
    "NT AUTHORITY",
    "Administrator"
]


def banner():
    cprint("┌───────────────────────────────┐", "cyan")
    cprint("│   PATH TRAVERSAL/LFI SCANNER  │", "cyan")
    cprint("│       Dev by: ThanhLam17      │", "cyan")
    cprint("│              _                │", "yellow")
    cprint("│            >(.)__             │", "yellow", attrs=['bold'])
    cprint("│             (___/             │", "yellow")
    cprint("│           ~~~~~~~~~           │", "cyan")
    cprint("└───────────────────────────────┘\n", "cyan")


def load_request_from_file(filename):
    with open(filename, "r") as f:
        lines = f.read().splitlines()

    method_line = lines[0]
    headers = {}
    body = None

    if "" in lines:
        idx = lines.index("")
        header_lines = lines[1:idx]
        body = "\n".join(lines[idx+1:])
    else:
        header_lines = lines[1:]

    for line in header_lines:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()

    method, path, _ = method_line.split()
    return method, path, headers, headers["Host"], body


def load_payloads(filename):
    with open(filename, "r") as f:
        return [line.strip() for line in f if line.strip()]


def inject_payload(url, body, payload, target_param):
    parsed = urlparse(url)
    q = parse_qs(parsed.query)

    new_q = q.copy()
    if target_param in new_q:
        new_q[target_param] = [payload]
    new_query = urlencode(new_q, doseq=True)
    new_url = urlunparse(parsed._replace(query=new_query))

    new_body = body
    if body:
        if body.strip().startswith("{") and body.strip().endswith("}"):
            try:
                b = json.loads(body)
                if target_param in b:
                    b[target_param] = payload
                new_body = json.dumps(b)
            except:
                pass
        elif "=" in body:
            b = parse_qs(body)
            if target_param in b:
                b[target_param] = [payload]
            new_body = urlencode(b, doseq=True)

    return new_url, new_body


def main():
    parser = argparse.ArgumentParser(description="LFI/Path Traversal Scanner")
    parser.add_argument("-u", "--url", help="Target URL")
    parser.add_argument("-r", "--request", default="request.txt", help="Request file")
    parser.add_argument("-l", "--payloads", default="LFI_payloads.txt", help="Payloads file")
    parser.add_argument("-s", "--ssl", action="store_true", help="Force HTTPS")
    parser.add_argument("-p", "--proxy", help="Proxy IP:port")
    parser.add_argument("-o", "--outfile", default="./results.txt", help="Write result to outfile")
    parser.add_argument("-H", "--header", action="append", help="Custom header, e.g., -H 'Authorization: Bearer token'")
    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    payloads = load_payloads(args.payloads)

    if args.url:
        method = "GET"
        url = args.url
        headers = {}
        body = args.body
    else:
        method, path, headers, host, body = load_request_from_file(args.request)
        scheme = "https" if args.ssl else "http"
        url = f"{scheme}://{host}{path}"

    if args.header:
        for h in args.header:
            if ":" not in h:
                cprint(f"⚠️ Invalid header format: {h}", "yellow", attrs=["bold"])
                continue
            key, value = h.split(":", 1)
            headers[key.strip()] = value.strip()

    parsed = urlparse(url)
    query_params = list(parse_qs(parsed.query).keys())

    body_params = []
    if body:
        if body.strip().startswith("{") and body.strip().endswith("}"):
            try:
                b = json.loads(body)
                body_params = list(b.keys())
            except:
                pass
        elif "=" in body:
            b = parse_qs(body)
            body_params = list(b.keys())

    if not query_params and not body_params:
        cprint("⚠️ No parameters detected to inject!", "yellow", attrs=["bold"])
        sys.exit(0)

    proxies = None
    if args.proxy:
        proxies = {
            "http": f"http://{args.proxy}",
            "https": f"http://{args.proxy}"
        }

    for payload in payloads:
        for param in query_params + body_params:
            inject_url, new_body = inject_payload(url, body, payload, target_param=param)
            cprint(f"\n[⏳] Testing payload '{payload}' in parameter '{param}'", "green", attrs=["bold"])
            try:
                if method == "GET":
                    r = requests.get(
                        inject_url,
                        headers=headers,
                        proxies=proxies,
                        timeout=10,
                        verify=False
                    )
                elif method == "POST":
                    r = requests.post(
                        inject_url,
                        headers=headers,
                        data=new_body,
                        proxies=proxies,
                        timeout=10,
                        verify=False
                    )
                else:
                    cprint(f"⚠️ Unsupported method: {method}", "yellow", attrs=["bold"])
                    continue

                response_text = r.text.lower()
                if any(keyword in response_text for keyword in KEYWORDS):
                    cprint("[🫣] POSSIBLE VULNERABILITY FOUND!", "red", attrs=["bold"])
                    lines = response_text.splitlines()
                    matched_lines = []
                    for line in lines:
                        if any(keyword in line for keyword in KEYWORDS):
                            cprint(" " * 4 + line.strip(), "red")
                            matched_lines.append(line.strip())
                    if args.outfile:
                        with open(f"{args.outfile}", "a", encoding="utf-8") as f:
                            f.write("============ VULNERABILITY DETECTED ============\n")
                            f.write(f"Parameter: {param}\n")
                            f.write(f"Payload: {payload}\n")
                            f.write("Matched lines:\n")
                            for m in matched_lines:
                                f.write(f"    {m}\n")
                            f.write("===============================================\n\n")
                else:
                    cprint("[✅] No vulnerability detected.", "yellow", attrs=["bold"])

            except Exception as e:
                print(f"Error: {e}")


if __name__ == "__main__":
    banner()
    main()
