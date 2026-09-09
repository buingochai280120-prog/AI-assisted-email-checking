import re
import joblib
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier


def extract_url_features(url):
    url = str(url).strip()

    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
    except Exception:
        domain = ""
        path = ""

    return [
        len(url),
        len(domain),
        len(path),
        int("@" in url),
        int("-" in domain),
        int(re.search(r"\d", domain) is not None),
        int(domain.count(".") >= 3),
        int(domain.endswith((".xyz", ".top", ".click", ".tk", ".ml"))),
        int(parsed.scheme == "https"),
    ]


def train_url_model(urls, labels):
    X = [extract_url_features(url) for url in urls]

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42
    )

    model.fit(X, labels)

    joblib.dump(model, "models/url_model.pkl")

    print("URL Model saved to models/url_model.pkl")
    return model


if __name__ == "__main__":
    urls = [
        "https://google.com",
        "https://facebook.com",
        "http://example.xyz/login",
        "http://192.168.1.1/verify",
        "https://github.com",
        "http://secure-account.xyz/verify",
        "https://microsoft.com",
        "http://free-prize.click"
    ]

    labels = [0, 0, 1, 1, 0, 1, 0, 1]

    train_url_model(urls, labels)