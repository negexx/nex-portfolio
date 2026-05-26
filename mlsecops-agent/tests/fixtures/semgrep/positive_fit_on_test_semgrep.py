"""Positive fixture: model.fit(X_test) — triggers ml-hygiene.fit-on-test-arg."""
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
import numpy as np

X = np.random.randn(200, 5)
y = np.random.randint(0, 2, 200)

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

model = LogisticRegression()
# LEAKAGE: fitting the model on the test set
model.fit(X_test, y_test)
