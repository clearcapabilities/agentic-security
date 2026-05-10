import Anthropic from '@anthropic-ai/sdk';
const anthropic = new Anthropic();

export async function ask(prompt) {
  const msg = await anthropic.messages.create({
    model: "claude-sonnet-4-6",
    max_tokens: 1024,
    messages: [{ role: "user", content: prompt }],
  });
  return msg.content[0].text;
}
