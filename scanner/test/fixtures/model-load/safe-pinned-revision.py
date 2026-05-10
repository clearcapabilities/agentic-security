from transformers import AutoModel, AutoTokenizer

REVISION = "a1b2c3d4e5f6789012345678901234567890abcd"

model = AutoModel.from_pretrained("bert-base-uncased", revision=REVISION)
tokenizer = AutoTokenizer.from_pretrained("bert-base-uncased", revision=REVISION)
