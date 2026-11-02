"""Small-image adaptations of classic CNN architectures; initialized from scratch."""
import torch
from torch import nn
from torch.nn import functional as F


class LeNet5(nn.Module):
    def __init__(self, channels, classes):
        super().__init__()
        self.features = nn.Sequential(nn.Conv2d(channels,6,5), nn.Tanh(), nn.AvgPool2d(2),
                                      nn.Conv2d(6,16,5), nn.Tanh(), nn.AvgPool2d(2))
        self.classifier = nn.Sequential(nn.Flatten(),nn.Linear(400,120),nn.Tanh(),
                                        nn.Linear(120,84),nn.Tanh(),nn.Linear(84,classes))

    def forward(self,x):
        if x.shape[-2:] == (28,28):
            x=F.pad(x,(2,2,2,2))
        elif x.shape[-2:] != (32,32):
            x=F.interpolate(x,size=(32,32),mode='bilinear',align_corners=False)
        return self.classifier(self.features(x))


class OptionA(nn.Module):
    def forward(self,x):
        x=x[:,:,::2,::2]
        padding=x.shape[1]//2
        return F.pad(x,(0,0,0,0,padding,padding))


class BasicBlock(nn.Module):
    expansion=1
    def __init__(self, inputs, channels, stride=1, option_a=False):
        super().__init__()
        self.body=nn.Sequential(nn.Conv2d(inputs,channels,3,stride,1,bias=False),nn.BatchNorm2d(channels),
                                nn.ReLU(inplace=True),nn.Conv2d(channels,channels,3,1,1,bias=False),nn.BatchNorm2d(channels))
        self.shortcut=nn.Identity() if stride==1 and inputs==channels else (
            OptionA() if option_a else nn.Sequential(nn.Conv2d(inputs,channels,1,stride,bias=False),nn.BatchNorm2d(channels)))
    def forward(self,x):
        return F.relu(self.body(x)+self.shortcut(x))


class Bottleneck(nn.Module):
    expansion=4
    def __init__(self,inputs,channels,stride=1,option_a=False):
        super().__init__()
        self.body=nn.Sequential(nn.Conv2d(inputs,channels,1,bias=False),nn.BatchNorm2d(channels),nn.ReLU(inplace=True),
            nn.Conv2d(channels,channels,3,stride,1,bias=False),nn.BatchNorm2d(channels),nn.ReLU(inplace=True),
            nn.Conv2d(channels,channels*4,1,bias=False),nn.BatchNorm2d(channels*4))
        self.shortcut=nn.Identity() if stride==1 and inputs==channels*4 else nn.Sequential(
            nn.Conv2d(inputs,channels*4,1,stride,bias=False),nn.BatchNorm2d(channels*4))
    def forward(self,x):
        return F.relu(self.body(x)+self.shortcut(x))


class ResNet(nn.Module):
    def __init__(self,channels,classes,block,depths,widths,option_a=False):
        super().__init__()
        self.stem=nn.Sequential(nn.Conv2d(channels,widths[0],3,1,1,bias=False),nn.BatchNorm2d(widths[0]),nn.ReLU(inplace=True))
        stages=[]
        inputs=widths[0]
        for stage,(count,width) in enumerate(zip(depths,widths)):
            for index in range(count):
                stride=2 if stage>0 and index==0 else 1
                stages.append(block(inputs,width,stride,option_a))
                inputs=width*block.expansion
        self.stages=nn.Sequential(*stages)
        self.pool=nn.AdaptiveAvgPool2d(1)
        self.classifier=nn.Linear(inputs,classes)
        for layer in self.modules():
            if isinstance(layer,nn.Conv2d):nn.init.kaiming_normal_(layer.weight,mode='fan_out',nonlinearity='relu')
            elif isinstance(layer,nn.BatchNorm2d):
                nn.init.ones_(layer.weight);nn.init.zeros_(layer.bias)
    def forward(self,x):
        if min(x.shape[-2:]) < 16:
            x=F.interpolate(x,size=(32,32),mode="bilinear",align_corners=False)
        return self.classifier(self.pool(self.stages(self.stem(x))).flatten(1))


def classic_model(name,channels,classes):
    if name=='LeNet5':return LeNet5(channels,classes)
    if name=='ResNet20':return ResNet(channels,classes,BasicBlock,[3,3,3],[16,32,64],True)
    if name=='ResNet18':return ResNet(channels,classes,BasicBlock,[2,2,2,2],[64,128,256,512])
    if name=='ResNet50':return ResNet(channels,classes,Bottleneck,[3,4,6,3],[64,128,256,512])
    raise ValueError(f'不支持模型 {name}')
