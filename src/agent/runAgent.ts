import { ChatCompletionMessageParam } from "openai/resources/chat/completions";
import { chatWithTools } from "../llm/openaiProvider.js";
import { toolMap } from "../tools/index.js";

export async function runAgent(messages: ChatCompletionMessageParam[], maxSteps = 8) {
  const state: ChatCompletionMessageParam[] = [...messages];

  for (let i = 0; i < maxSteps; i++) {
    const res = await chatWithTools(state);

    if (res.type === "final") {
      return res.content;
    }

    const tool = toolMap.get(res.name);
    if (!tool) {
      state.push({ role: "assistant", content: `工具 ${res.name} 不存在。` } as any);
      continue;
    }

    let args: any = {};
    try { args = JSON.parse(res.argsJson); } catch { args = {}; }

    let result: any;
    try {
      result = await tool.handler(args);
    } catch (e: any) {
      result = { error: String(e?.message ?? e) };
    }

    // 追加工具结果
    state.push(res.assistantMsg as any);
    state.push({
      role: "tool",
      content: JSON.stringify(result).slice(0, 12000),
      tool_call_id: (res as any).id
    } as any);
  }

  return "已达最大推理步数，停止。";
}
