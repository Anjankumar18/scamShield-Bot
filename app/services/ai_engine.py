import httpx

async def analyze_url_ai(url: str):
    hf_url = "https://huggingface.co/spaces/Anjan18/scamshield-url-ai"

    payload = {
        "data": [url]
    }

    async with httpx.AsyncClient(timeout=10) as client:
        res = await client.post(hf_url, json=payload)
        output = res.json()

    return output["data"][0]
