import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn import model_selection
from sklearn.metrics import accuracy_score, confusion_matrix, precision_score, recall_score, f1_score,ConfusionMatrixDisplay
import joblib
from sklearn.model_selection import train_test_split
import pickle

def main():
    df=pd.read_csv('data_ransomware.csv',sep=',')
    #PREPROCESAMIENTO
    df.replace('unknown', np.nan, inplace=True)
    #Convertir nulos por "0"
    df.fillna(0, inplace=True)
    df.columns=df.columns.str.strip()
    df=df.select_dtypes(exclude=['object'])

    X = df.drop(columns=['BitcoinAddresses','Benign'])
    y = df['Benign']

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    rF=RandomForestClassifier(random_state=42)
    rF.fit(X_train, y_train)

    score=model_selection.cross_val_score(rF, X_train, y_train)
    print("\n\t[*] Cross Validation Score: ", round(score.mean()*100, 2), '%')

    y_pred = rF.predict(X_test)

    accuracy = accuracy_score(y_test, y_pred)
    f = f1_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    print("\t[*] Exactitud: ", round(accuracy * 100, 5), '%')
    print("\t[*] Precisión: ", round(precision * 100, 5), '%')
    print("\t[*] Recall: ", round(recall * 100, 5), '%')
    print("\t[*] F1 Score: ", round(f * 100, 5), '%')

    all_features = X.shape[1]
    features = []

    for feature in range(all_features):
        features.append(df.columns[feature])

    try:
        print("\n[+] Saving algorithm and feature list in classifier directory...")
        joblib.dump(rF, 'classifier/classifier.pkl')
        open('classifier/features.pkl', 'wb').write(pickle.dumps(features))
        print("\n[*] Saved.")
    except:
        print('\n[-] Error: Algorithm and feature list not saved correctly.\n')

if __name__ == '__main__':
    main()