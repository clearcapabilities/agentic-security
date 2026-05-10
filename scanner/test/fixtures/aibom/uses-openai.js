import OpenAI from 'openai';
const client = new OpenAI();

export async function chat(userMessage) {
  const resp = await client.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: userMessage }],
  });
  return resp.choices[0].message.content;
}
