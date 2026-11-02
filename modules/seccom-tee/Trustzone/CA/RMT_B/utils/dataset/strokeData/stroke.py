import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from imblearn.over_sampling import SMOTE
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.preprocessing import LabelEncoder, MinMaxScaler

pd.set_option('display.max_columns', None)

random_state = 80

df = pd.read_csv('healthcare-dataset-stroke-data.csv', delimiter=',', encoding='utf-8')
df['bmi'] = df['bmi'].fillna(round(df['bmi'].median(), 2))
df.drop('id', axis=1, inplace=True)

categorical = ['gender', 'ever_married', 'work_type', 'Residence_type', 'smoking_status']
numerical = ['age', 'bmi', 'avg_glucose_level']

le = LabelEncoder()
for col in categorical:
    df[col] = le.fit_transform(df[col])

scaler = MinMaxScaler()
df[numerical] = scaler.fit_transform(df[numerical])
df[categorical] = scaler.fit_transform(df[categorical])

X = df.drop('stroke', axis=1)
y = df['stroke']

smote = SMOTE(random_state=random_state)
X_resample, y_resample = smote.fit_resample(X, y)

pos_idx = np.where(y_resample == 1)[0]
neg_idx = np.where(y_resample == 0)[0]

np.random.seed(random_state)
pos_samples = np.random.choice(pos_idx, size=600, replace=False)
neg_samples = np.random.choice(neg_idx, size=600, replace=False)

selected_samples = np.concatenate((pos_samples, neg_samples))
X_selected = X_resample.loc[selected_samples]
y_selected = y_resample.loc[selected_samples]

X_train, X_test, y_train, y_test = train_test_split(X_selected, y_selected, test_size=0.2, shuffle=True,
                                                    random_state=random_state)

logreg = LogisticRegression()
logreg.fit(X_train, y_train)
y_pred = logreg.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print("Accuracy:", accuracy)


def split_train_data(train_data, num_parts=3):
    part_size = len(train_data) // num_parts
    train_data = train_data[:part_size * num_parts]
    split_data = np.array_split(train_data, num_parts)
    return split_data


def save_to_txt(filename, data):
    np.savetxt(filename, data, delimiter=' ', fmt='%d' + ' %f' * (data.shape[1] - 1))


train_data = X_train.assign(stroke=y_train)
train_data = train_data[['stroke'] + list(X_train.columns)]
test_data = X_test.assign(stroke=y_test)
test_data = test_data[['stroke'] + list(X_test.columns)]


np.savetxt('stroke_train.txt', train_data.values, delimiter=' ', fmt='%d' + ' %f' * (train_data.shape[1] - 1))
np.savetxt('stroke_test.txt', test_data.values, delimiter=' ', fmt='%d' + ' %f' * (test_data.shape[1] - 1))

split_train_data_list = split_train_data(train_data)
for i, split_data in enumerate(split_train_data_list):
    save_to_txt(f'stroke_train_part_{i + 1}.txt', split_data)
