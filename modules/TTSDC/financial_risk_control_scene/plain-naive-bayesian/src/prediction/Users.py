from .DataProcessor import DataProcessor


class Users:
    def __init__(self, filepath):
        processU = DataProcessor()
        
        self.sypVector = processU.readFile(filepath)
        self.extVector = processU.vectorExtend(self.sypVector)
        self.paddingVector = processU.getUPaddingVector(self.extVector)
        self.sypLabels = processU.getLable(self.sypVector, 9, 9)

