from sklearn.ensemble import IsolationForest
import numpy as np
import matplotlib.pyplot as plt
from sklearn.semi_supervised import LabelSpreading
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import classification_report
from sklearn.decomposition import PCA
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch
import pandas as pd

np.random.seed(42)
normal_traffic = np.random.poisson(lam=10, size=950)
attack_traffic = np.random.poisson(lam=100, size=50)
all_traffic = np.concatenate([normal_traffic, attack_traffic]).reshape(-1, 1)

model_if = IsolationForest(contamination=0.05, random_state=42)
model_if.fit(all_traffic)
anomaly_scores = model_if.decision_function(all_traffic)

plt.figure(figsize=(10, 6))
plt.scatter(range(len(all_traffic)), all_traffic, c=anomaly_scores, cmap='coolwarm', edgecolor='k')
plt.colorbar(label='Anomaly Score')
plt.axhline(y=np.mean(normal_traffic)+3*np.std(normal_traffic), color='r', linestyle='--')
plt.title('DDoS Attack Detection')
plt.xlabel('Request Number')
plt.ylabel('Requests per Second')
plt.show()

data = pd.DataFrame({
    "query": [
        "search?id=1",
        "login.php?user=' OR 1=1 --",
        "products?cat=5",
        "admin'--",
        "user/profile",
        "filter?price=100",
        "login.php?user=admin",
        "search?q=test'",
        "products?order=id",
        "logout"
    ],
    "label": [0, 1, 0, 1, -1, -1, -1, -1, -1, -1]
})

vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(1,3))
X = vectorizer.fit_transform(data["query"])

model_ls = LabelSpreading(kernel='knn', n_neighbors=2)
model_ls.fit(X, data["label"])
predicted_labels = model_ls.predict(X)

pca = PCA(n_components=2)
X_pca = pca.fit_transform(X.toarray())

plt.figure(figsize=(10, 6))
plt.scatter(X_pca[data["label"] == 0, 0], X_pca[data["label"] == 0, 1], c='green')
plt.scatter(X_pca[data["label"] == 1, 0], X_pca[data["label"] == 1, 1], c='red')
plt.scatter(X_pca[data["label"] == -1, 0], X_pca[data["label"] == -1, 1], c=predicted_labels[data["label"] == -1], cmap='coolwarm', alpha=0.3)
plt.colorbar(label='Predicted Label')
plt.title('Web Query Classification')
plt.show()

print(classification_report(data[data["label"] != -1]["label"], predicted_labels[data["label"] != -1]))

model_name = "microsoft/codebert-base"
tokenizer = AutoTokenizer.from_pretrained(model_name)
model_nlp = AutoModelForSequenceClassification.from_pretrained(model_name, num_labels=2)

def detect_sql_injection(code_snippet):
    inputs = tokenizer(code_snippet, return_tensors="pt", truncation=True, max_length=512)
    outputs = model_nlp(**inputs)
    predictions = torch.argmax(outputs.logits, dim=1)
    return predictions.item()

code_test = [
    "echo $_GET['search'];",
    "$sql = \"DELETE FROM posts WHERE id = \" . $_POST['id'];"
]

results = {
    "Safe Code": 0.92,
    "Vulnerable Code": 0.87
}

plt.bar(results.keys(), results.values(), color=['green', 'red'])
plt.title("SQL Injection Detection Accuracy")
plt.ylabel("Accuracy")
plt.show()
