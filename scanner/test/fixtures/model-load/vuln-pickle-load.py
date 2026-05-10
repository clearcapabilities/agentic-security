import pickle

def restore(path):
    with open(path, "rb") as f:
        return pickle.load(f)
