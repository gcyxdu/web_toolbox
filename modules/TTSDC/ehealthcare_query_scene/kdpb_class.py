from typing import List
import random
from heu.phe import Ciphertext

class Record:
    def __init__(self, data: List[int], attribute: List[int]):
        self.data = data
        self.attribute = attribute

class InternalNodeRecord:
    def __init__(self, uL: List[int], uR: List[int]):
        self.uL = uL
        self.uR = uR

class QueryRecord:
    def __init__(self, filteration_record: List[int], verification_record: List[int]):
        self.filteration_record = filteration_record
        self.verification_record = verification_record

class Node:
    def __init__(self):
        self.is_leaf = False

class InternalNode(Node):
    def __init__(self, internal_node_record: InternalNodeRecord, left_node: Node, right_node: Node):
        super().__init__()
        self.is_leaf = False
        self.internal_node_record = internal_node_record
        self.left_node = left_node
        self.right_node = right_node

class LeafNode(Node):
    def __init__(self, data_record: List[int]):
        super().__init__()
        self.is_leaf = True
        self.data_record = data_record

class QueryToken:
    def __init__(self, filteration_token: List[int], verification_token: List[int]):
        self.filteration_token = filteration_token
        self.verification_token = verification_token

class EncryptNode(Node):
    def __init__(self):
        super().__init__()

class EncryptInternalNode(EncryptNode):
    def __init__(self, encrypt_uL: List[Ciphertext], encrypt_lL: Ciphertext, encrypt_uR: List[Ciphertext], encrypt_lR: Ciphertext, left_node: EncryptNode, right_node: EncryptNode):
        super().__init__()
        self.encrypt_uL = encrypt_uL
        self.encrypt_lL = encrypt_lL
        self.encrypt_uR = encrypt_uR
        self.encrypt_lR = encrypt_lR
        self.left_node = left_node
        self.right_node = right_node

class EncryptLeafNode(EncryptNode):
    def __init__(self, encrypt_data_record: List[Ciphertext]):
        super().__init__()
        self.is_leaf = True
        self.encrypt_data_record = encrypt_data_record