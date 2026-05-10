from transformers import AutoModelForCausalLM

model = AutoModelForCausalLM.from_pretrained(
    "some-org/exotic-model",
    trust_remote_code=True,
)
