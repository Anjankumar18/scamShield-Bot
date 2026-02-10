from transformers import pipeline

# Load once (important for performance)
classifier = pipeline(
    "text-classification",
    model="distilbert-base-uncased-finetuned-sst-2-english"
)


def analyze_nlp(text: str) -> dict:

    result = classifier(text)[0]

    return {
        "label": result["label"],
        "confidence": round(result["score"], 2)
    }
