import whois
from datetime import datetime


def get_domain_age(url: str):

    try:
        domain = url.split("//")[-1].split("/")[0]

        w = whois.whois(domain)

        created = w.creation_date

        if isinstance(created, list):
            created = created[0]

        if not created:
            return None

        age_days = (datetime.now() - created).days

        return age_days

    except Exception:
        return None
