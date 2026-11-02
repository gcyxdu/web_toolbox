import random
import csv
from typing import List
from kdpb_class import Record
from util_plain import UtilPlain

class Data:
    
    @staticmethod
    def read_data(filename: str, split_string: str, n: int, d: int) -> List[List[int]]:
        database = []
        count = 0
        with open(filename, "r") as f:
            for line in f:
                if count >= n:
                    break
                line = line.strip()
                if not line:
                    continue
                temp_strings = line.split(split_string)
                temp_int = [round(float(x)) for x in temp_strings[:d]]

                if not Data.duplicate_check(temp_int, database):
                    database.append(temp_int)
                    count += 1
        return database

    @staticmethod
    def add_attribute_on_datalist(database: List[List[int]], l: int) -> List[Record]:
        record_list = []
        for data in database:
            attribute_vector = Data.get_attribute_vector(l)
            record = Record(data, attribute_vector)
            record_list.append(record)
        
        return record_list

    @staticmethod
    def get_attribute_vector(l: int) -> List[int]:
        attribute_vector = [0] * l
        for i in range(l):
            rnd = random.random()
            if rnd < 1.0 / 3:
                attribute_vector[i] = 2
            elif rnd > 2.0 / 3:
                attribute_vector[i] = 4
        
        return attribute_vector
    
    @staticmethod
    def duplicate_check(record: List[int], database: List[List[int]]) -> bool:
        flag = False
        if record in database:
            flag = True
        
        return flag
    
    @staticmethod
    def gen_synthetic_data(n: int, d: int) -> List[List[int]]:
        database = []

        while len(database) < n:
            data = [int(random.random() * 70) for _ in range(d)]
            flag = False
            
            if data in database:
                flag = True
            
            if flag == False:
                database.append(data)
            
        return database

if __name__ == "__main__":
    file_string = "EEGEyeState.txt"
    split_string = ","
    n = 9
    d = 2

    database = Data.gen_synthetic_data(n, d)
    for i in range(n):
            print(",".join(str(database[i][j]) for j in range(d)))
    print("......................")
    attribute_vector = Data.get_attribute_vector(10)
    UtilPlain.print_vector(attribute_vector)