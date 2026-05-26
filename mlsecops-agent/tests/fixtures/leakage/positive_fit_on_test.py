"""Positive fixture: fit called on the test set — leakage.fit-on-test."""
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import numpy as np

X = np.random.randn(200, 10)
y = np.random.randint(0, 2, 200)

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)

# LEAKAGE: fitting the scaler on X_test instead of transforming it
X_test_scaled = scaler.fit(X_test)
