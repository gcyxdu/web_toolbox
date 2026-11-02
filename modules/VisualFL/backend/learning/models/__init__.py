"""Training model factory: linear legacy records and explicit classic image networks."""
from ..utils import Register
model_registry = Register()
from .regression import lr
from .classic import classic_model


def get_model(args):
    if args.model == 'lr':
        model=lr(input_dim=getattr(args,'input_dim',args.num_dims**2),num_classes=args.num_classes)
    else:
        model=classic_model(args.model,args.num_channels,args.num_classes)
    return model.to(args.device)
