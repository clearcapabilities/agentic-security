import yaml

def parse_config(stream):
    return yaml.safe_load(stream)
