import requests


def resolve_final_url(url: str):

    try:
        r = requests.get(url, allow_redirects=True, timeout=10)
        return r.url
    except Exception:
        return url
