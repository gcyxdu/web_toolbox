import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
from sklearn.linear_model import LogisticRegression

pd.set_option('display.max_columns', None)

# 类别特征编码
dataset = pd.read_csv('bank.csv', delimiter=';')
cols = dataset.columns
num_cols = dataset._get_numeric_data().columns
cat_cols = list(set(cols) - set(num_cols))
dataset[cat_cols] = dataset[cat_cols].apply(LabelEncoder().fit_transform)

# 划分训练集和测试集
dataset = dataset.sample(frac=1, random_state=86)
train_data = dataset.iloc[:1200]
test_data = dataset.iloc[1200:1400]

X_train = train_data.drop('y', axis=1)
y_train = train_data['y']
X_test = test_data.drop('y', axis=1)
y_test = test_data['y']

# 归一化处理
scaler = MinMaxScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# 合并 X_train_scaled 和 y_train
trainData = np.concatenate((np.array(y_train).reshape(-1, 1), X_train_scaled), axis=1)
testData = np.concatenate((np.array(y_test).reshape(-1, 1), X_test_scaled), axis=1)

trainData_df = pd.DataFrame(trainData, columns=['y'] + X_train.columns.tolist())
testData_df = pd.DataFrame(testData, columns=['y'] + X_test.columns.tolist())

# 输出在测试集上的准确率
X_train = trainData_df.drop('y', axis=1)
y_train = trainData_df['y']

logreg = LogisticRegression(max_iter=1000)
logreg.fit(X_train, y_train)
y_pred = logreg.predict(X_test_scaled)
accuracy = accuracy_score(y_test, y_pred)
print("Accuracy:", accuracy)


def split_train_data(train_data, num_parts=3):
    part_size = len(train_data) // num_parts
    train_data = train_data[:part_size * num_parts]
    split_data = np.array_split(train_data, num_parts)
    return split_data


def save_to_txt(filename, data):
    np.savetxt(filename, data, delimiter=' ', fmt='%d' + ' %f' * (data.shape[1] - 1))


# 保存训练数据到txt文件，第一列为标签，后面为特征
np.savetxt('bank_test.txt', testData_df.values, delimiter=' ', fmt='%d' + ' %f' * (testData_df.shape[1] - 1))
np.savetxt('bank_train.txt', trainData_df.values, delimiter=' ', fmt='%d' + ' %f' * (trainData_df.shape[1] - 1))
split_train_data_list = split_train_data(trainData_df)
for i, split_data in enumerate(split_train_data_list):
    save_to_txt(f'bank_train_part_{i + 1}.txt', split_data)