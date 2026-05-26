"""Negative fixture: correct pipeline — no semgrep rule should fire."""
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import numpy as np

X = np.random.randn(200, 5)
y = np.random.randint(0, 2, 200)

# Correct: shuffle with stratify preserves class proportions.
X_train, X_test, y_train, y_test = train_test_split(X, y, stratify=y)

scaler = StandardScaler()
# Correct: fit only on training data, transform both splits.
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

model = LogisticRegression()
# Correct: fit on training data only.
model.fit(X_train_scaled, y_train)
