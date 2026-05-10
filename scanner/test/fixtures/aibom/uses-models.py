from transformers import AutoModel, AutoTokenizer

tokenizer = AutoTokenizer.from_pretrained("bert-base-uncased", revision="a1b2c3d4e5f67890")
model = AutoModel.from_pretrained("microsoft/phi-3-mini-4k-instruct")
