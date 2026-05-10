def build_messages(user_input):
    return [
        {"role": "system", "content": "You are an assistant."},
        {"role": "user", "content": user_input},
    ]
