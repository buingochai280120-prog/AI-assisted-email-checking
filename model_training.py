"""Compatibility wrapper for the old project API."""
from models.text_model import phishing_probability as ml_phishing_probability
from models.text_model import get_metrics as get_model_metrics


def print_model_metrics():
    m = get_model_metrics()
    print("=" * 60)
    print("ĐÁNH GIÁ MODEL")
    print("=" * 60)
    print(f"Accuracy : {m['accuracy']*100:.2f}%")
    print(f"Precision: {m['precision']*100:.2f}%")
    print(f"Recall   : {m['recall']*100:.2f}%")
    print(f"F1-score : {m['f1']*100:.2f}%")
    print("Confusion Matrix:", m['confusion_matrix'])
    print(f"Samples after dedup: {m['samples_after_dedup']}")
