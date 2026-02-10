import re


def extract_urls(text: str) -> list:

    regex = r"(https?://[^\s]+)"

    return re.findall(regex, text)
