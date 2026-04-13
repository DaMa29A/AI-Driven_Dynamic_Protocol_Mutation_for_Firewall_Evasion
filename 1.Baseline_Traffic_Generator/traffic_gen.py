import random
import string
import time
import requests
import urllib3
from urllib.parse import urlencode

HTTP_TARGET = "http://192.168.20.10"
HTTPS_TARGET = "https://192.168.20.10"

HTTPS_RATIO = 0.7
VERIFY_TLS = False  # self-signed nel lab

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
]

ACCEPT_BY_TYPE = {
    "html": [
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "text/html,application/xml;q=0.9,*/*;q=0.8",
    ],
    "json": [
        "application/json,text/plain;q=0.9,*/*;q=0.8",
        "application/json,*/*;q=0.8",
    ],
    "txt": [
        "text/plain,*/*;q=0.8",
        "*/*",
    ],
    "jpg": [
        "image/avif,image/webp,image/apng,image/*,*/*;q=0.8",
        "image/jpeg,image/*;q=0.8,*/*;q=0.5",
    ],
    "bin": [
        "*/*",
        "application/octet-stream,*/*;q=0.8",
    ],
}

ACCEPT_LANGUAGES = [
    "it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7",
    "en-US,en;q=0.9",
    "it-IT,it;q=0.8",
]

CONNECTIONS = ["keep-alive", "close"]

RESOURCES = [
    {"path": "/mfolder/index.html",   "type": "html", "weight": 30},
    {"path": "/mfolder/about.html",   "type": "html", "weight": 15},
    {"path": "/mfolder/contact.html", "type": "html", "weight": 15},
    {"path": "/mfolder/info.json",    "type": "json", "weight": 10},
    {"path": "/mfolder/robots.txt",   "type": "txt",  "weight": 8},
    {"path": "/mfolder/status.txt",   "type": "txt",  "weight": 8},
    {"path": "/mfolder/cat.jpg",      "type": "jpg",  "weight": 14},
]

HTML_PAGES = [r for r in RESOURCES if r["type"] == "html"]
STATIC_RESOURCES = [r for r in RESOURCES if r["type"] in ("jpg", "json", "txt")]

MISSING_RESOURCES = [
    {"path": "/mfolder/favicon.ico", "type": "bin"},
    {"path": "/mfolder/app.js", "type": "bin"},
    {"path": "/mfolder/style.css", "type": "txt"},
    {"path": "/mfolder/missing.jpg", "type": "jpg"},
    {"path": "/mfolder/api/data.json", "type": "json"},
    {"path": "/mfolder/old-page.html", "type": "html"},
]

QUERY_KEYS = ["id", "page", "lang", "ref", "v", "session"]

MISSING_RESOURCE_PROB = 0.06
TYPO_QUERY_PROB = 0.03
EXTRA_404_AFTER_PAGE_PROB = 0.12


def weighted_choice(resources):
    population = [r["path"] for r in resources]
    weights = [r["weight"] for r in resources]
    chosen_path = random.choices(population=population, weights=weights, k=1)[0]
    for r in resources:
        if r["path"] == chosen_path:
            return r
    return resources[0]


def random_query(max_params=2, noisy=False):
    n = random.randint(0, max_params)
    params = {}
    for _ in range(n):
        k = random.choice(QUERY_KEYS)
        params[k] = "".join(
            random.choices(string.ascii_letters + string.digits, k=random.randint(3, 8))
        )

    if noisy and random.random() < TYPO_QUERY_PROB:
        noisy_key = random.choice(["debug", "utm_test", "foo", "badparam"])
        params[noisy_key] = "".join(
            random.choices(string.ascii_letters + string.digits, k=random.randint(2, 6))
        )

    return urlencode(params)


def build_url(base_target, resource, query_probability=0.55, max_params=2, noisy_query=False):
    query = random_query(max_params=max_params, noisy=noisy_query)
    if query and random.random() < query_probability:
        return f"{base_target}{resource['path']}?{query}"
    return f"{base_target}{resource['path']}"


def choose_method(resource_type):
    if resource_type in ("jpg", "txt", "json", "bin"):
        return random.choices(["GET", "HEAD"], weights=[85, 15], k=1)[0]
    return random.choices(["GET", "HEAD"], weights=[92, 8], k=1)[0]


def make_headers(resource_type, referer=None, session_profile=None):
    headers = {
        "User-Agent": session_profile["user_agent"] if session_profile else random.choice(USER_AGENTS),
        "Accept": random.choice(ACCEPT_BY_TYPE.get(resource_type, ["*/*"])),
        "Accept-Language": session_profile["accept_language"] if session_profile else random.choice(ACCEPT_LANGUAGES),
        "Connection": random.choice(CONNECTIONS),
    }

    if referer:
        headers["Referer"] = referer

    if random.random() < 0.30:
        headers["Cache-Control"] = random.choice(["max-age=0", "no-cache"])
    if resource_type == "html" and random.random() < 0.25:
        headers["Upgrade-Insecure-Requests"] = "1"

    return headers


def choose_target():
    if random.random() < HTTPS_RATIO:
        return HTTPS_TARGET, True
    return HTTP_TARGET, False


def sample_short_delay():
    r = random.random()
    if r < 0.70:
        return random.uniform(0.05, 0.35)
    if r < 0.92:
        return random.uniform(0.35, 0.90)
    return random.uniform(0.90, 1.80)


def sample_page_delay():
    r = random.random()
    if r < 0.55:
        return random.uniform(1.0, 3.5)
    if r < 0.85:
        return random.uniform(3.5, 8.0)
    return random.uniform(8.0, 18.0)


def sample_session_gap():
    r = random.random()
    if r < 0.65:
        return random.uniform(5.0, 15.0)
    if r < 0.90:
        return random.uniform(15.0, 35.0)
    return random.uniform(35.0, 90.0)


def maybe_embedded_resources(page_resource):
    resources = []

    if page_resource["path"].endswith("index.html"):
        if random.random() < 0.85:
            resources.append(next(r for r in RESOURCES if r["path"] == "/mfolder/cat.jpg"))
        if random.random() < 0.40:
            resources.append(next(r for r in RESOURCES if r["path"] == "/mfolder/info.json"))

    elif page_resource["path"].endswith("about.html"):
        if random.random() < 0.55:
            resources.append(next(r for r in RESOURCES if r["path"] == "/mfolder/info.json"))
        if random.random() < 0.25:
            resources.append(next(r for r in RESOURCES if r["path"] == "/mfolder/status.txt"))

    elif page_resource["path"].endswith("contact.html"):
        if random.random() < 0.50:
            resources.append(next(r for r in RESOURCES if r["path"] == "/mfolder/status.txt"))

    if random.random() < 0.10:
        resources.append(weighted_choice(STATIC_RESOURCES))

    return resources


def maybe_missing_resource():
    if random.random() < MISSING_RESOURCE_PROB:
        return random.choice(MISSING_RESOURCES)
    return None


def send_request(session, req_id, resource, session_profile, base_target, is_https, referer=None, noisy_query=False):
    method = choose_method(resource["type"])
    url = build_url(base_target, resource, noisy_query=noisy_query)
    headers = make_headers(resource["type"], referer=referer, session_profile=session_profile)
    timeout = random.uniform(2.0, 5.0)

    try:
        request_kwargs = {
            "headers": headers,
            "timeout": timeout,
            "allow_redirects": True,
        }

        if is_https:
            request_kwargs["verify"] = VERIFY_TLS

        if method == "GET":
            response = session.get(url, **request_kwargs)
            body_size = len(response.content)
        else:
            response = session.head(url, **request_kwargs)
            body_size = 0

        content_type = response.headers.get("Content-Type", "unknown")
        proto = "HTTPS" if is_https else "HTTP"

        print(
            f"[{req_id:04d}] {proto} {method} {url} -> {response.status_code} | "
            f"{content_type} | {body_size} bytes | referer={referer or '-'}"
        )

    except requests.RequestException as e:
        proto = "HTTPS" if is_https else "HTTP"
        print(f"[{req_id:04d}] {proto} {method} {url} -> ERROR: {e}")


def make_session_profile():
    return {
        "user_agent": random.choice(USER_AGENTS),
        "accept_language": random.choice(ACCEPT_LANGUAGES),
    }


def run_navigation_session(start_req_id, base_target, is_https, min_pages=1, max_pages=4):
    req_id = start_req_id
    session_profile = make_session_profile()

    with requests.Session() as session:
        pages_to_visit = random.randint(min_pages, max_pages)
        previous_page_url = None

        for page_index in range(pages_to_visit):
            page = weighted_choice(HTML_PAGES)
            page_url = f"{base_target}{page['path']}"

            send_request(
                session=session,
                req_id=req_id,
                resource=page,
                session_profile=session_profile,
                base_target=base_target,
                is_https=is_https,
                referer=previous_page_url,
                noisy_query=False,
            )
            req_id += 1

            embedded = maybe_embedded_resources(page)
            for res in embedded:
                time.sleep(sample_short_delay())
                send_request(
                    session=session,
                    req_id=req_id,
                    resource=res,
                    session_profile=session_profile,
                    base_target=base_target,
                    is_https=is_https,
                    referer=page_url,
                    noisy_query=False,
                )
                req_id += 1

            if random.random() < EXTRA_404_AFTER_PAGE_PROB:
                missing = random.choice(MISSING_RESOURCES)
                time.sleep(sample_short_delay())
                send_request(
                    session=session,
                    req_id=req_id,
                    resource=missing,
                    session_profile=session_profile,
                    base_target=base_target,
                    is_https=is_https,
                    referer=page_url,
                    noisy_query=True,
                )
                req_id += 1

            maybe_missing = maybe_missing_resource()
            if maybe_missing is not None:
                time.sleep(sample_short_delay())
                send_request(
                    session=session,
                    req_id=req_id,
                    resource=maybe_missing,
                    session_profile=session_profile,
                    base_target=base_target,
                    is_https=is_https,
                    referer=page_url if random.random() < 0.7 else previous_page_url,
                    noisy_query=True,
                )
                req_id += 1

            previous_page_url = page_url

            if page_index < pages_to_visit - 1:
                delay = sample_page_delay()
                print(f"--- pausa lettura pagina {delay:.2f}s ---")
                time.sleep(delay)

    return req_id


def main():
    total_sessions = 40
    req_id = 1

    for s in range(1, total_sessions + 1):
        base_target, is_https = choose_target()
        proto = "HTTPS" if is_https else "HTTP"

        print(f"\n=== SESSIONE {s:03d} ({proto}) ===")

        req_id = run_navigation_session(
            req_id,
            base_target,
            is_https,
            min_pages=1,
            max_pages=4,
        )

        if s < total_sessions:
            gap = sample_session_gap()
            print(f"=== pausa tra sessioni {gap:.2f}s ===")
            time.sleep(gap)


if __name__ == "__main__":
    main()