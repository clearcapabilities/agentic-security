export function buildPrompt(userInput) {
  return `You are an assistant. Instructions: be concise.

User: ${userInput}
Assistant:`;
}
