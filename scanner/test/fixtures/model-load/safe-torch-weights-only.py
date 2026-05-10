import torch

def load_checkpoint(path):
    state = torch.load(path, weights_only=True)
    return state
