import OpenAI from "openai";
import { ChatCompletionMessageParam } from "openai/resources/chat/completions";
import { toOpenAIFunctions } from "../tools/index.js";

// 硅基流动 API 配置
const client = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY || "sk-xxx", // 你的硅基流动 API Key
  baseURL: process.env.OPENAI_BASE_URL || "https://api.siliconflow.cn/v1" // 硅基流动 API 地址
});

export async function chatWithTools(messages: ChatCompletionMessageParam[]) {
  const resp = await client.chat.completions.create({
    model: process.env.OPENAI_MODEL || "Qwen/Qwen2.5-7B-Instruct", // 硅基流动免费模型
    temperature: 0.6,
    top_p: 0.9,
    messages,
    tools: toOpenAIFunctions(),
    tool_choice: "auto",
    presence_penalty: 0.2,
    frequency_penalty: 0.2
  });

  const choice = resp.choices[0];
  const msg = choice.message;

  if (msg.tool_calls && msg.tool_calls.length > 0) {
    const tc = msg.tool_calls[0];
    return {
      type: "tool_call" as const,
      name: tc.function.name,
      id: tc.id,
      argsJson: tc.function.arguments || "{}",
      assistantMsg: msg
    };
  }
  return { type: "final" as const, content: msg.content ?? "" };
}
