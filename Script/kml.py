# Importo varie librerie Python
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import silhouette_score
import pandas as pd
import numpy as np
from sklearn.metrics import pairwise_distances
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, davies_bouldin_score, calinski_harabasz_score, roc_auc_score
from sklearn import metrics
import joblib
import sklearn
# Carico i dati dal file CSV relativi esclusivamente al traffico benigno
df_X = pd.read_csv('Dataset/benignoEtichettatoSplit.csv')

# Seleziono le colonne che voglio usare per il clustering (tutte tranne 'Label' in quanto i dati non sono etichettati)
X = df_X.drop('Label', axis=1)

# Standardizzo i dati
scaler = StandardScaler()
X = scaler.fit_transform(X)

print("\n")

scores = []
'''
for k in range(6, 15):
    kmeans = KMeans(n_clusters=k, n_init=100, init='k-means++', random_state=42)
    kmeans.fit(X)
    score = silhouette_score(X, kmeans.labels_)
    scores.append(score)
    print(f"Con {k} cluster ho un punteggio di Silhouette pari a {score} \n")

print("\n")

best_k = scores.index(max(scores)) + 2
'''
best_k = 6
print(f"Il valore migliore si ha con un numero di cluster pari a: {best_k} \n")


# Inizializzo l'oggetto KMeans con il numero di cluster ottimale fornito dal punteggio di Silhouette
kmeans_X = KMeans(n_clusters=best_k, n_init=100, init='k-means++', random_state=42)

# Addestro il modello utilizzando i dati letti
kmeans_X.fit(X)

# Prevedo a quali cluster appartengono i punti dei dati utilizzando il modello addestrato
predictions_X = kmeans_X.predict(X)

# Calcolo la distanza dei punti dai centroidi di tutti i cluster presenti
distances_X = pairwise_distances(X, kmeans_X.cluster_centers_, metric='euclidean')

distances_X=distances_X/2

# Scelgo una soglia basata sul valore massimo della distanza tra i punti dati e il relativo centroide per ogni cluster
distanceCluster_X = []
cluster_centroid = kmeans_X.cluster_centers_

dfC = pd.DataFrame(cluster_centroid)
dfC.to_csv('Dataset/centroidi.csv', index=False)

for i in range(len(X)):
    distanceCluster_X.append(np.min(distances_X[i, :]))
threshold = max(distanceCluster_X)

print("Il valore della soglia è: ", threshold)

# Valutazione dell'algoritmo

# Carica il dataset dal file CSV
datac = pd.read_csv('Dataset/malignoEtichettato.csv')

yc = datac["Label"]

# Seleziona solo le feature per il clustering (escludendo 'Label' in quanto i dati non sono etichettati)
Xc = datac.drop(columns=["Label"])

Xc = scaler.transform(Xc)

# Inizializza le variabili
y = 0
classPrediction = []

print("Valutazione dei dati nel dataset completo...")

for i in range(len(Xc)):
    features_instance = Xc[i, :].reshape(1, -1)
    distance_Y = np.min(pairwise_distances(features_instance, cluster_centroid, metric='euclidean'))

    if distance_Y > threshold:
        classPrediction.append(1)  # traffico anomalo
        print(f"Traffico anomalo rilevato - Data: {datac['Time'][i]}, Pacchetto No.: {datac['No.'][i]}")
    else:
        classPrediction.append(0)  # traffico benigno

predicted_labels = classPrediction

accuracy = accuracy_score(yc, predicted_labels)
precision = precision_score(yc, predicted_labels)
recall = recall_score(yc, predicted_labels)
f1 = f1_score(yc, predicted_labels)
#confusion = confusion_matrix(yc, predicted_labels)

# Calcola il punteggio di Silhouette, l'Adjusted Rand Index e l'Normalized Mutual Information
#silhouette = silhouette_score(Xc, predicted_labels)
#adjusted_rand = metrics.adjusted_rand_score(yc, predicted_labels)
#normalized_mutual_info = metrics.normalized_mutual_info_score(yc, predicted_labels)

print("Accuracy:", accuracy)
print("Precision:", precision)
print("Recall:", recall)
print("F1 Score:", f1)
# Calcola l'AUROC
auroc = roc_auc_score(yc, predicted_labels)
print(f'Area Under the ROC Curve (AUROC): {auroc}')

#print("Confusion Matrix:")
#rint(confusion)
#print(f'K-Means Silhouette Score: {silhouette}')
#print(f'K-Means Adjusted Rand Index: {adjusted_rand}')
#print(f'K-Means Normalized Mutual Information: {normalized_mutual_info}')

#print("joblib version: ", joblib.__version__)
#print("scikit version: ", sklearn.__version__)

# Salvo il modello K-Means e la soglia in un file con estensione .pkl
modello_e_soglia = {"kmeans_model": kmeans_X, "soglia": threshold}
joblib.dump(modello_e_soglia, "Dataset/modello_e_soglia.pkl")
