from .DataProcessor import DataProcessor


class MedicalCenters:
    def __init__(self, filepath, collectAttributes):
        process = DataProcessor()
        
        self.originSet = process.readFile(filepath)
        numOfins = len(self.originSet)
        self.extendSet = process.vectorExtend(self.originSet)
        label = process.getLable(self.originSet, 9, 9)
        
        self.e = process.getE(collectAttributes)
        self.NX = process.getNX(self.extendSet)
        self.NY = process.getNY(label)
        self.NZ = process.getNZ(self.extendSet, label)
        self.ND = process.getND(self.NY, self.e)
        self.NL = process.getNL(numOfins, self.e)

