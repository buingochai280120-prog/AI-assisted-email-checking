import joblib
from sklearn.linear_model import LogisticRegression


def train_meta_model():
    # Features:
    # [text_probability, url_probability, rule_score]
    X = [
        [0.95, 0.90, 0.90],
        [0.85, 0.80, 0.80],
        [0.90, 0.70, 0.85],
        [0.75, 0.90, 0.80],
        [0.10, 0.05, 0.10],
        [0.20, 0.10, 0.15],
        [0.15, 0.20, 0.10],
        [0.05, 0.10, 0.05],
    ]

    # 1 = phishing, 0 = normal
    y = [1, 1, 1, 1, 0, 0, 0, 0]

    model = LogisticRegression(random_state=42)
    model.fit(X, y)

    joblib.dump(model, "models/meta_model.pkl")

    print("Meta Model saved to models/meta_model.pkl")


if __name__ == "__main__":
    train_meta_model()