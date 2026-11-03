import math
import random
from typing import List, Dict
from kdpb_class import Record, QueryRecord, InternalNodeRecord

class UtilPlain:
    @staticmethod
    def print_vector(vector: List[int]):
        print(",".join(str(v) for v in vector))
    
    @staticmethod
    def record_to_vector(record: Record) -> List[int]:
        data = record.data
        attribute = record.attribute
        d = len(data)
        l = len(attribute)
        vector = [0] * (2 * l + d + 3)
        
        s = 0
        for i in range(d):
            vector[i] = data[i]
            s += data[i] * data[i]
        vector[d] = s
        vector[d + 1] = 1

        s = 0
        for i in range(l):
            vector[d + 2 + i] = attribute[i]
            vector[d + 2 + l + i] = -2 * attribute[i] * attribute[i]
            s += attribute[i] * attribute[i] * attribute[i]
        
        vector[d + 2 + 2 * l] = s
        return vector
    
    @staticmethod
    def query_to_vector(record: Record, tau: int) -> QueryRecord:
        query_data = record.data
        query_attribute = record.attribute
        d = len(query_data)
        l = len(query_attribute)

        filteration_record = [0] * (l + d + 3)
        filteration_record[:l] = query_attribute
        filteration_record[l] = 1
        filteration_record[l + 1] = 2 * tau
        filteration_record[l + 2] = 1

        for i in range(d):
            filteration_record[l + 3 + i] = 2 * query_data[i]
        
        verification_record = [0] * (2 * l + d + 3)
        s = 0
        for i in range(d):
            verification_record[i] = -2 * query_data[i]
            s += query_data[i] * query_data[i]
        verification_record[d] = 1
        verification_record[d + 1] = s - tau * tau

        delta = tau + 10
        for i in range(l):
            verification_record[d + 2 + i] = delta * delta * query_attribute[i] * query_attribute[i]
            verification_record[l + d + 2 + i] = delta * delta * query_attribute[i]
        verification_record[2 * l + d + 2] = delta * delta

        return QueryRecord(filteration_record, verification_record)
    
    @staticmethod
    def absolute_p_square(point: List[int]) -> int:
        return sum(p * p for p in point)
    
    @staticmethod
    def euclidean_dis(point1: List[int], point2: List[int]) -> float:
        return math.sqrt(sum((p1 - p2) ** 2 for p1, p2 in zip(point1, point2)))

    @staticmethod
    def pivot_to_vector(pivot1: List[int], pivot2: List[int], l: int) -> InternalNodeRecord:
        d = len(pivot1)
        dis1p2 = math.ceil(UtilPlain.euclidean_dis(pivot1, pivot2))

        p1_square = UtilPlain.absolute_p_square(pivot1)
        p2_square = UtilPlain.absolute_p_square(pivot2)

        l_vector = [0] * (l + d + 3)
        r_vector = [0] * (l + d + 3)

        l_vector[l + 1] = -dis1p2
        r_vector[l + 1] = dis1p2
        l_vector[l + 2] = p1_square - p2_square
        r_vector[l + 2] = p1_square - p2_square

        for i in range(d):
            diff = pivot2[i] - pivot1[i]
            l_vector[l + 3 + i] = diff
            r_vector[l + 3 + i] = diff
        
        return InternalNodeRecord(l_vector, r_vector)
    
    @staticmethod
    def cutting_value_to_vector(cd: int, val: int, l: int, d: int) -> InternalNodeRecord:
        cd += 1
        vector = [0] * (l + d + 3)
        vector[cd - 1] = 1
        vector[l] = -val
        return InternalNodeRecord(vector, vector)
    
    @staticmethod
    def dis_between_two_data(v1: List[int], v2: List[int]) -> int:
        return sum((a - b) ** 2 for a, b in zip(v1, v2))

    @staticmethod
    def choose_pivot(data_list: List[Record]) -> List[List[int]]:
        n = len(data_list)
        index = [0, 1]
        max_dis = UtilPlain.dis_between_two_data(data_list[0].data, data_list[1].data)

        for i in range(n):
            for j in range(i + 1, n):
                dis = UtilPlain.dis_between_two_data(data_list[i].data, data_list[j].data)
                if dis > max_dis:
                    max_dis = dis
                    index = [i, j]
        return [data_list[index[0]].data, data_list[index[1]].data]
    
    @staticmethod
    def mean_data_list(data_list: List[Record]) -> List[int]:
        d = len(data_list[0].data)
        mean = [0] * d
        for rec in data_list:
            for i in range(d):
                mean[i] += rec.data[i]
        return [int(x / len(data_list)) for x in mean]

    @staticmethod
    def compute_dis(
        data_list: List[Record], p1: List[int], p2: List[int]
    ) -> Dict[str, List[Record]]:
        left, right = [], []
        for rec in data_list:
            dis1 = UtilPlain.dis_between_two_data(rec.data, p1)
            dis2 = UtilPlain.dis_between_two_data(rec.data, p2)
            (left if dis1 <= dis2 else right).append(rec)
        return {"left": left, "right": right}

    @staticmethod
    def choose_pivot_by_kmeans(data_list: List[Record]) -> List[List[int]]:
        loc1 = random.randint(0, len(data_list) - 1)
        loc2 = random.randint(0, len(data_list) - 1)
        while loc2 == loc1:
            loc2 = random.randint(0, len(data_list) - 1)

        p1, p2 = data_list[loc1].data, data_list[loc2].data
        for _ in range(10):
            data = UtilPlain.compute_dis(data_list, p1, p2)
            p1 = UtilPlain.mean_data_list(data["left"])
            p2 = UtilPlain.mean_data_list(data["right"])
        return [p1, p2]

    @staticmethod
    def choose_cutting_dim_val(data_list: List[Record]) -> List[float]:
        n = len(data_list)
        l = len(data_list[0].attribute)
        num_two = [0] * l
        num_four = [0] * l

        for rec in data_list:
            for j in range(l):
                if rec.attribute[j] == 2:
                    num_two[j] += 1
                elif rec.attribute[j] == 4:
                    num_four[j] += 1

        proportion = [0.0] * l
        max_proportion = 0
        index_prop = -1
        for i in range(l):
            if num_four[i] and num_two[i]:
                proportion[i] = min(num_four[i], num_two[i]) / max(num_four[i], num_two[i])
            if proportion[i] > max_proportion:
                max_proportion = proportion[i]
                index_prop = i

        return [index_prop, max_proportion]

    @staticmethod
    def gene_dummy_value(d: int, l: int) -> List[int]:
        dummy = [0] * (2 * l + d + 3)
        dummy[2 * l + d + 2] = 1
        return dummy

if __name__ == "__main__":
    record = Record([1, 3, 4, 5], [2, 4, 6, 10])

    vector = UtilPlain.record_to_vector(record)
    query_record = UtilPlain.query_to_vector(record, 2)

    print("filtration record:")
    UtilPlain.print_vector(query_record.filteration_record)
    print("verification record:")
    UtilPlain.print_vector(query_record.verification_record)

    pivot1 = [1, 2, 4]
    pivot2 = [4, 6, 9]

    internal_node_record = UtilPlain.pivot_to_vector(pivot1, pivot2, 3)
    print("uL")
    UtilPlain.print_vector(internal_node_record.uL)
    print("uR")
    UtilPlain.print_vector(internal_node_record.uR)

    print("..............................")

    cd = 2
    val = 5
    internal_node_record = UtilPlain.cutting_value_to_vector(cd, val, 3, 4)
    print("uL")
    UtilPlain.print_vector(internal_node_record.uL)
    print("uR")
    UtilPlain.print_vector(internal_node_record.uR)
    print("..................")

    data1 = [1, 2, 3]
    att1 = [2, 2, 4]
    record1 = Record(data1, att1)

    data2 = [2, 4, 6]
    att2 = [2, 4, 4]
    record2 = Record(data2, att2)

    data3 = [0, 0, 0]
    att3 = [2, 2, 4]
    record3 = Record(data3, att3)

    data4 = [3, 6, 9]
    att4 = [2, 4, 2]
    record4 = Record(data4, att4)
    
    data5 = [100, 34, 10]
    att5 = [10, 10, 2]
    record5 = Record(data5, att5)

    record_list = []
    record_list.append(record1)
    record_list.append(record2)
    record_list.append(record3)
    record_list.append(record4)
    record_list.append(record5)

    index =UtilPlain.choose_pivot(record_list)
    print("yesorNo........................")
    UtilPlain.print_vector(index[0])
    UtilPlain.print_vector(index[1])
