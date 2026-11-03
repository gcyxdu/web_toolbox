from BuildingBlocks.ase import Shares

class AliasPlain:
    def __init__(self, ele1: int, wgt1: int, ele2: int, wgt2: int):
        self.ele1 = ele1
        self.wgt1 = wgt1
        self.ele2 = ele2
        self.wgt2 = wgt2

class AliasCipher:
    def __init__(self, ele1_shares: Shares, wgt1_shares: Shares, ele2_shares: Shares, wgt2_shares: Shares):
        self.ele1_shares = ele1_shares
        self.wgt1_shares = wgt1_shares
        self.ele2_shares = ele2_shares
        self.wgt2_shares = wgt2_shares