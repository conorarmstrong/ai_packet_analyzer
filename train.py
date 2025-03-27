# train.py
import argparse
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import joblib
import logging
import os

from packet_features import FEATURE_NAMES # Import to ensure consistency

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def train_model(data_path, model_save_path, scaler_save_path, test_size=0.3):
    """Loads data, trains a model, evaluates, and saves artifacts."""
    try:
        logging.info(f"Loading data from {data_path}...")
        df = pd.read_csv(data_path)
    except FileNotFoundError:
        logging.error(f"Data file not found: {data_path}")
        return
    except Exception as e:
        logging.error(f"Error loading data: {e}")
        return

    if df.empty:
        logging.error("Loaded dataframe is empty.")
        return

    # Define features (X) and target (y)
    if 'label' not in df.columns:
        logging.error("Label column 'label' not found in the dataset.")
        return

    # Ensure all expected feature columns are present
    missing_cols = [col for col in FEATURE_NAMES if col not in df.columns]
    if missing_cols:
        logging.error(f"Missing feature columns in CSV: {missing_cols}")
        return

    X = df[FEATURE_NAMES]
    y = df['label']

    logging.info(f"Data shape: {X.shape}, Label distribution:\n{y.value_counts(normalize=True)}")

    # Split data into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size, random_state=42, stratify=y)
    logging.info(f"Training set shape: {X_train.shape}, Test set shape: {X_test.shape}")

    # --- Preprocessing: Scaling ---
    logging.info("Scaling features using StandardScaler...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test) # Use transform, not fit_transform on test data

    # --- Model Training ---
    logging.info("Training RandomForestClassifier model...")
    # You can tune hyperparameters here (n_estimators, max_depth, etc.)
    model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1) # Use all available cores
    model.fit(X_train_scaled, y_train)
    logging.info("Model training complete.")

    # --- Evaluation ---
    logging.info("Evaluating model on the test set...")
    y_pred = model.predict(X_test_scaled)
    accuracy = accuracy_score(y_test, y_pred)
    report = classification_report(y_test, y_pred, target_names=['Benign (0)', 'Malicious (1)'])
    conf_matrix = confusion_matrix(y_test, y_pred)

    logging.info(f"Test Accuracy: {accuracy:.4f}")
    logging.info("Classification Report:\n" + report)
    logging.info("Confusion Matrix:\n" + str(conf_matrix))

    # --- Save Model and Scaler ---
    try:
        os.makedirs(os.path.dirname(model_save_path), exist_ok=True)
        joblib.dump(model, model_save_path)
        logging.info(f"Model saved successfully to {model_save_path}")

        os.makedirs(os.path.dirname(scaler_save_path), exist_ok=True)
        joblib.dump(scaler, scaler_save_path)
        logging.info(f"Scaler saved successfully to {scaler_save_path}")
    except Exception as e:
        logging.error(f"Error saving model or scaler: {e}")

def main():
    parser = argparse.ArgumentParser(description="Train a network packet classifier.")
    parser.add_argument('--data', required=True, help="Path to the input feature CSV file.")
    parser.add_argument('--model-out', required=True, help="Path to save the trained model (.joblib).")
    parser.add_argument('--scaler-out', required=True, help="Path to save the fitted scaler (.joblib).")
    parser.add_argument('--test-size', type=float, default=0.3, help="Proportion of data to use for testing.")

    args = parser.parse_args()

    train_model(args.data, args.model_out, args.scaler_out, args.test_size)

if __name__ == "__main__":
    main()
