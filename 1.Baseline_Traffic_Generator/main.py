import random
import subprocess
import time
import shutil
import sys

HTTP_TARGET = "http://192.168.20.10"
HTTPS_TARGET = "https://192.168.20.10"

HTTPS_RATIO = 0.7
TOTAL_ACTIONS = 30
VERIFY_TLS = False

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
]

ACCEPT_LANGUAGES = [
    "it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7",
    "en-US,en;q=0.9",
    "it-IT,it;q=0.8",
]

EXISTING_PATHS = [
    "/mfolder/index.html",
    "/mfolder/about.html",
    "/mfolder/contact.html",
    "/mfolder/info.json",
    "/mfolder/robots.txt",
    "/mfolder/status.txt",
    "/mfolder/cat.jpg",
]

MISSING_PATHS = [
    "/mfolder/favicon.ico",
    "/mfolder/app.js",
    "/mfolder/style.css",
    "/mfolder/missing.jpg",
    "/mfolder/api/data.json",
    "/mfolder/old-page.html",
]

MISSING_PROB = 0.12
CHROME_RATIO = 0.25


def pick_base_target():
    if random.random() < HTTPS_RATIO:
        return HTTPS_TARGET
    return HTTP_TARGET


def pick_path():
    if random.random() < MISSING_PROB:
        return random.choice(MISSING_PATHS)
    return random.choice(EXISTING_PATHS)


def sample_delay():
    r = random.random()
    if r < 0.70:
        return random.uniform(0.4, 1.5)
    if r < 0.90:
        return random.uniform(1.5, 4.0)
    return random.uniform(4.0, 8.0)


def find_chrome_binary():
    candidates = [
        "google-chrome",
        "chromium",
        "chromium-browser",
        "chrome",
    ]
    for name in candidates:
        path = shutil.which(name)
        if path:
            return path
    return None


def run_curl(url, user_agent, accept_language):
    cmd = [
        "curl",
        "-A", user_agent,
        "-H", f"Accept-Language: {accept_language}",
        "-L",
        "-s",
        "-o", "/dev/null",
        "-w", "%{http_code} %{size_download} %{content_type}\n",
    ]

    if url.startswith("https://") and not VERIFY_TLS:
        cmd.append("-k")

    cmd.append(url)

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=30
    )

    output = result.stdout.strip() if result.stdout else ""
    error = result.stderr.strip() if result.stderr else ""

    if result.returncode == 0:
        print(f"[curl]   {url} -> {output}")
    else:
        print(f"[curl]   {url} -> ERROR rc={result.returncode} {error}")


def run_chrome(url, chrome_bin):
    cmd = [
        chrome_bin,
        "--headless",
        "--disable-gpu",
        "--dump-dom",
        "--no-sandbox",
    ]

    if url.startswith("https://") and not VERIFY_TLS:
        cmd.append("--ignore-certificate-errors")

    cmd.append(url)

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=45
    )

    if result.returncode == 0:
        dom_size = len(result.stdout or "")
        print(f"[chrome] {url} -> DOM {dom_size} bytes")
    else:
        error = result.stderr.strip() if result.stderr else ""
        print(f"[chrome] {url} -> ERROR rc={result.returncode} {error}")


def main():
    if shutil.which("curl") is None:
        print("[!] curl non trovato nel PATH", file=sys.stderr)
        sys.exit(1)

    chrome_bin = find_chrome_binary()
    if chrome_bin is None:
        print("[!] Chrome/Chromium non trovato nel PATH", file=sys.stderr)
        sys.exit(1)

    print(f"[+] curl trovato: {shutil.which('curl')}")
    print(f"[+] browser headless trovato: {chrome_bin}")
    print(f"[+] azioni totali: {TOTAL_ACTIONS}")

    for i in range(1, TOTAL_ACTIONS + 1):
        base = pick_base_target()
        path = pick_path()
        url = f"{base}{path}"

        user_agent = random.choice(USER_AGENTS)
        accept_language = random.choice(ACCEPT_LANGUAGES)

        client = "chrome" if random.random() < CHROME_RATIO else "curl"

        print(f"\n=== ACTION {i:03d} | client={client} ===")

        try:
            if client == "curl":
                run_curl(url, user_agent, accept_language)
            else:
                run_chrome(url, chrome_bin)
        except subprocess.TimeoutExpired:
            print(f"[{client}] {url} -> TIMEOUT")
        except Exception as exc:
            print(f"[{client}] {url} -> ERROR: {exc}")

        if i < TOTAL_ACTIONS:
            delay = sample_delay()
            print(f"--- pausa {delay:.2f}s ---")
            time.sleep(delay)


if __name__ == "__main__":
    main()