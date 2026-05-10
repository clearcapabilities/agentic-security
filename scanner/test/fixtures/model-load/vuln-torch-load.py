import torch

def load_checkpoint(path):
    state = torch.load(path)
    return state
