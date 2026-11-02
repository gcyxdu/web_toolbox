import pandas as pd
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score
from sklearn.preprocessing import MinMaxScaler, LabelEncoder

# 加载Iris数据集
iris_df = pd.read_csv('Iris.csv')

# 归一化特征列（在Iris数据集中是前四列）
scaler = MinMaxScaler()
features = iris_df.columns[:4]
iris_df[features] = scaler.fit_transform(iris_df[features])

# 类别编码标签列
encoder = LabelEncoder()
label = iris_df.columns[-1]
iris_df[label] = encoder.fit_transform(iris_df[label])

# 处理后的数据集
iris_df = iris_df.sample(frac=1, random_state=90).reset_index(drop=True)

# 将标签列移动到第一列
label_column = iris_df.columns[-1]
feature_columns = iris_df.columns[:-1]
iris_df = iris_df[[label_column] + list(feature_columns)]


def split_train_data(train_data, num_parts=2):
    part_size = len(train_data) // num_parts
    train_data = train_data[:part_size * num_parts]
    split_data = np.array_split(train_data, num_parts)
    return split_data


def save_to_txt(filename, data):
    np.savetxt(filename, data, delimiter=' ', fmt='%d' + ' %f' * (data.shape[1] - 1))


train_data = iris_df.iloc[:120]
test_data = iris_df.iloc[120:]
np.savetxt('iris_train.txt', train_data.values, delimiter=' ', fmt='%d' + ' %f' * (train_data.shape[1] - 1))
np.savetxt('iris_test.txt', test_data.values, delimiter=' ', fmt='%d' + ' %f' * (test_data.shape[1] - 1))

split_train_data_list = split_train_data(train_data)
for i, split_data in enumerate(split_train_data_list):
    save_to_txt(f'iris_train_part_{i + 1}.txt', split_data)


X_train = train_data.iloc[:, 1:]
y_train = train_data.iloc[:, 0]
X_test = test_data.iloc[:, 1:]
y_test = test_data.iloc[:, 0]

model = LogisticRegression()
model.fit(X_train, y_train)
y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)
print(f'Logistic Regression Accuracy: {accuracy:.4f}')