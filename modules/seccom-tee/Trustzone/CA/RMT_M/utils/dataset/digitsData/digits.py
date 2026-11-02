import numpy as np
from sklearn.datasets import load_digits
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score
from sklearn.preprocessing import MinMaxScaler

digits = load_digits()
X = digits.data
y = digits.target
df = pd.DataFrame(X)
df['y'] = y

df = df.sample(frac=1, random_state=6)
train_data = df.iloc[:900]
test_data = df.iloc[900:1100]

X_train = train_data.drop('y', axis=1)
y_train = train_data['y']
X_test = test_data.drop('y', axis=1)
y_test = test_data['y']

scaler = MinMaxScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

trainData = np.concatenate((np.array(y_train).reshape(-1, 1), X_train_scaled), axis=1)
testData = np.concatenate((np.array(y_test).reshape(-1, 1), X_test_scaled), axis=1)


def split_train_data(train_data, num_parts=3):
    part_size = len(train_data) // num_parts
    train_data = train_data[:part_size * num_parts]
    split_data = np.array_split(train_data, num_parts)
    return split_data


def save_to_txt(filename, data):
    np.savetxt(filename, data, delimiter=' ', fmt='%d' + ' %f' * (data.shape[1] - 1))


testData_df = pd.DataFrame(testData, columns=['y'] + X_test.columns.tolist())
np.savetxt('digits_test.txt', testData_df.values, delimiter=' ', fmt='%d' + ' %f' * (testData_df.shape[1] - 1))

trainData_df = pd.DataFrame(trainData, columns=['y'] + X_train.columns.tolist())
np.savetxt('digits_train.txt', trainData_df.values, delimiter=' ', fmt='%d' + ' %f' * (trainData_df.shape[1] - 1))
split_train_data_list = split_train_data(trainData_df)
for i, split_data in enumerate(split_train_data_list):
    save_to_txt(f'digits_train_part_{i + 1}.txt', split_data)


# 输出在测试集上的准确率
logreg = LogisticRegression(max_iter=1000)
logreg.fit(X_train_scaled, y_train)
y_pred = logreg.predict(X_test_scaled)
accuracy = accuracy_score(y_test, y_pred)
print("Accuracy:", accuracy)
