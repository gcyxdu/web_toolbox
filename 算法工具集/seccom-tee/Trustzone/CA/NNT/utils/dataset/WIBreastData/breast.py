import numpy as np
from sklearn.datasets import load_breast_cancer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler


def load_and_process_data():
    data = load_breast_cancer()
    X, y = data.data, data.target
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    scaler = MinMaxScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    train_data = np.column_stack((y_train, X_train_scaled))
    test_data = np.column_stack((y_test, X_test_scaled))

    logreg = LogisticRegression()
    logreg.fit(X_train_scaled, y_train)
    y_pred = logreg.predict(X_test_scaled)
    accuracy = accuracy_score(y_test, y_pred)
    print("Accuracy:", accuracy)

    return train_data, test_data


def split_train_data(train_data, num_parts=3):
    part_size = len(train_data) // num_parts
    train_data = train_data[:part_size * num_parts]
    split_data = np.array_split(train_data, num_parts)
    return split_data


def save_to_txt(filename, data):
    np.savetxt(filename, data, delimiter=' ', fmt='%d' + ' %f' * (data.shape[1] - 1))


def main():
    train_data, test_data = load_and_process_data()

    split_train_data_list = split_train_data(train_data)
    for i, split_data in enumerate(split_train_data_list):
        save_to_txt(f'breast_cancer_train_part_{i + 1}.txt', split_data)
    save_to_txt('breast_cancer_test.txt', test_data)
    save_to_txt('breast_cancer_train.txt', train_data)
    print(train_data.shape)


if __name__ == '__main__':
    main()
