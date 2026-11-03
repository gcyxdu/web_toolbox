import csv
from typing import List


class DataProcessing:
    @staticmethod
    def read_data(filename: str, split_string: str, database: List[List[int]]) -> None:
        with open(filename, "r", encoding="utf-8") as f:
            reader = csv.reader(f, delimiter=split_string)
            next(reader, None)  # 跳过首行（对应 Java 中的第一次 readLine）
            for row in reader:
                if len(row) < 2:
                    continue
                temp_int = [round(float(row[0])), round(float(row[1]))]
                database.append(temp_int)

    @staticmethod
    def write_data(database: List[List[int]], output_file: str, split_string: str) -> None:
        with open(output_file, "w", encoding="utf-8") as f:
            for record in database:
                line = f"{record[0]}{split_string}{record[1]}\n"
                f.write(line)

    @staticmethod
    def combine_data_and_write_to_file() -> None:
        filenames = [
            "Jeans_5713.csv",
            "Shirts_11407.csv",
            "Sports Shoes_10571.csv",
            "Sportswear_6201.csv",
            "T-shirts and Polos_12735.csv",
            "Western Wear_15514.csv",
        ]
        split_string = ","
        database: List[List[int]] = []

        for name in filenames:
            file_path = f"src/{name}"
            DataProcessing.read_data(file_path, split_string, database)

        output_file = "src/cleanData.txt"
        DataProcessing.write_data(database, output_file, split_string)

    @staticmethod
    def read_data_limited(filename: str, split_string: str, n: int) -> List[List[int]]:
        database: List[List[int]] = []
        with open(filename, "r", encoding="utf-8") as f:
            reader = csv.reader(f, delimiter=split_string)
            count = 0
            for row in reader:
                if count >= n:
                    break
                if len(row) < 2:
                    continue
                temp_int = [round(float(row[0])), round(float(row[1]))]
                database.append(temp_int)
                count += 1
        return database


if __name__ == "__main__":
    from BuildingBlocks.util import Util
    filename = "cleanData.txt"
    split_string = ","
    n = 20000

    database = DataProcessing.read_data_limited(filename, split_string, n)
    print(len(database))

    for i in range(10):
        Util.print_int_vec(database[i])
