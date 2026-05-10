export function buildMessages(userInput) {
  return [
    { role: "system", content: "You are an assistant." },
    { role: "user", content: userInput },
  ];
}
