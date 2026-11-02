from .DataProcessor import DataProcessor


class EhealthcareProvider:
    def __init__(self, MCs):
        processEP = DataProcessor()
        
        self.SNX = processEP.getSNX(MCs)
        self.SNY = processEP.getSNY(MCs)
        self.SNZ = processEP.getSNZ(MCs)
        self.SND = processEP.getSND(MCs)
        self.SNL = processEP.getSNL(MCs)
        
        self.X_1_Y_1 = processEP.getX_1_Y_1(self.SNZ, self.SND)
        self.X_1_Y_0 = processEP.getX_1_Y_0(self.SNX, self.SNZ, self.SND, self.SNL)
        self.X_0_Y_1 = processEP.getX_0_Y_1(self.X_1_Y_1)
        self.X_0_Y_0 = processEP.getX_0_Y_0(self.X_1_Y_0)
        self.Y_1 = processEP.getY_1(self.SNY, self.SNL)
        self.Y_0 = processEP.getY_0(self.Y_1)
        
        self.L_X_1_Y_1 = processEP.getLog(self.X_1_Y_1)
        self.L_X_1_Y_0 = processEP.getLog(self.X_1_Y_0)
        self.L_X_0_Y_1 = processEP.getLog(self.X_0_Y_1)
        self.L_X_0_Y_0 = processEP.getLog(self.X_0_Y_0)
        self.L_Y_1 = processEP.getLog(self.Y_1)
        self.L_Y_0 = processEP.getLog(self.Y_0)
        
        self.LI = processEP.getPredictionvectors(self.L_X_1_Y_1, self.L_X_0_Y_1, self.L_Y_1)
        self.LII = processEP.getPredictionvectors(self.L_X_1_Y_0, self.L_X_0_Y_0, self.L_Y_0)
