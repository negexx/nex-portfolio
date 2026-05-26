"""Positive fixture: train_test_split with shuffle=False and no stratify."""
from sklearn.model_selection import train_test_split
import numpy as np

X = np.random.randn(200, 5)
y = np.random.randint(0, 2, 200)

# Missing stratify= — class imbalance in test set possible.
X_train, X_test, y_train, y_test = train_test_split(X, y, shuffle=False)
