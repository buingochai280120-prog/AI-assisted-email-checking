import os, sys
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)
from training.train_text_model import train_and_save
from training.train_url_model import train as train_url

if __name__ == "__main__":
    _, text_metrics = train_and_save()
    print("Text model:", text_metrics)
    try:
        train_url()
    except FileNotFoundError:
        print("Bỏ qua URL model: chưa có data/url_dataset.csv")
