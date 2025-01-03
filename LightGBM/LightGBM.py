import numpy as np
import pandas as pd
import lightgbm as lgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.preprocessing import LabelEncoder
import time

def evaluate_model(model, X_test, y_test, label_encoder):
    """Evaluate the model and print the performance metrics."""
    # Predict probabilities and convert them to class labels
    y_pred = model.predict(X_test)
    y_pred = [np.argmax(line) for line in y_pred]  # Convert probabilities to predicted classes
    
    # Convert labels back to original class labels
    y_test_classes = label_encoder.inverse_transform(y_test)
    y_pred_classes = label_encoder.inverse_transform(y_pred)
    
    # Compute accuracy
    accuracy = accuracy_score(y_test_classes, y_pred_classes)
    
    # Compute confusion matrix
    conf_matrix = confusion_matrix(y_test_classes, y_pred_classes, labels=label_encoder.classes_)
    
    # Calculate error rates per class
    class_totals = np.sum(conf_matrix, axis=1)
    class_errors = class_totals - np.diag(conf_matrix)
    class_error_rates = class_errors / class_totals
    class_error_rates_percentage = class_error_rates * 100
    
    # Calculate precision and recall
    precision = precision_score(y_test_classes, y_pred_classes, average=None)
    recall = recall_score(y_test_classes, y_pred_classes, average=None)
    
    # Create a DataFrame for class-wise performance
    accuracy_df = pd.DataFrame({
        'Class': label_encoder.classes_,
        'Accuracy (%)': 100 - class_error_rates_percentage,
        'Error Rate (%)': class_error_rates_percentage,
        'Precision (%)': precision * 100,
        'Recall (%)': recall * 100
    })
    
    print("\nClass-wise Performance Table:")
    print(accuracy_df)
    
    # Print overall accuracy
    print(f"\nOverall Accuracy: {accuracy:.4f}")
    
    # Compute and print F1 score
    f1 = f1_score(y_test_classes, y_pred_classes, average='weighted')
    print(f"F1 Score: {f1:.4f}")
    
    # Print confusion matrix
    print("\nConfusion Matrix:")
    print(conf_matrix)

def main():
    # Load dataset
    df = pd.read_csv('RecomposedESNI.csv', header=None, names=['target'] + [f'C{i:02}' for i in range(284)], low_memory=False)
    df = df.drop(0, axis=0)  # Drop the first row if it's unnecessary (extra header row)

    # Label encode the 'target' column (categorical target)
    label_encoder = LabelEncoder()
    df['target'] = label_encoder.fit_transform(df['target'])

    # Identify categorical columns
    categorical_columns = df.select_dtypes(include=['object']).columns.tolist()

    # Apply LabelEncoder to categorical columns
    for col in categorical_columns:
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col])

    # Convert the entire DataFrame (except target) to float32
    for col in df.columns:
        if col != 'target':
            df[col] = pd.to_numeric(df[col], errors='coerce')

    # Handle missing or non-numeric data by filling with 0
    df.fillna(0, inplace=True)

    # Split data into features (X) and target (y)
    X = df.drop('target', axis=1)
    y = df['target']

    # Split the data into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    # Initialize LightGBM Dataset
    train_data = lgb.Dataset(X_train, label=y_train)
    test_data = lgb.Dataset(X_test, label=y_test, reference=train_data)

    # Define parameters for LightGBM
    params = {
        'objective': 'multiclass',  # for multi-class classification
        'num_class': len(np.unique(y)),  # Number of classes
        'boosting_type': 'gbdt',  # Gradient boosting decision tree
        'metric': 'multi_logloss',  # Loss function for multi-class classification
        'learning_rate': 0.1,
        'num_leaves': 4,
        'max_depth': 3,
        'random_state': 42
    }

    # Measure training time
    start_time = time.time()
    
    # Train the LightGBM model
    gbm = lgb.train(params, train_data, valid_sets=[train_data, test_data], num_boost_round=50)
    
    training_time = time.time() - start_time
    print(f"Training Time: {training_time:.4f} seconds")

    # Measure prediction time
    start_time = time.time()
    
    # Evaluate the model
    y_pred_proba = gbm.predict(X_test)
    evaluate_model(gbm, X_test, y_test, label_encoder)
    
    prediction_time = time.time() - start_time
    print(f"Prediction Time: {prediction_time:.4f} seconds")

if __name__ == "__main__":
    main()
