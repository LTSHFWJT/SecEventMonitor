import requests


DEFAULT_HEADERS = {
    "User-Agent": "SecEventMonitor/0.1",
}


def build_session(proxy_url="", headers=None):
    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)
    if headers:
        session.headers.update(headers)

    proxy_url = (proxy_url or "").strip()
    if proxy_url:
        session.proxies.update(
            {
                "http": proxy_url,
                "https": proxy_url,
            }
        )
    return session
