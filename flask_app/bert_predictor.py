import torch
import os
from transformers import BertTokenizer, BertForSequenceClassification

# -------------------------------------------------
# Load model & tokenizer (ONCE, when Flask starts)
# -------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "bert_model")

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

tokenizer = BertTokenizer.from_pretrained(MODEL_PATH)
model = BertForSequenceClassification.from_pretrained(MODEL_PATH)
model.to(device)
model.eval()

LABELS = {
    0: "🟢 LEGIT",
    1: "🔴 PHISHING"
}

# -------------------------------------------------
# Prediction function (used by Flask routes)
# -------------------------------------------------

def predict_email(text: str):
    """
    Predict whether an email is PHISHING or LEGIT
    Returns: (label, confidence_percentage)
    """

    inputs = tokenizer(
        text,
        return_tensors="pt",
        truncation=True,
        padding="max_length",
        max_length=512
    )

    inputs = {k: v.to(device) for k, v in inputs.items()}

    with torch.no_grad():
        outputs = model(**inputs)
        probs = torch.softmax(outputs.logits, dim=1)

    confidence, predicted_class = torch.max(probs, dim=1)

    label = LABELS[predicted_class.item()]
    confidence_pct = round(confidence.item() * 100, 2)

    return label, confidence_pct
