import { Tool } from "./types.js";
import { stringsTool } from "./stringsTool.js";
import { rabin2SymbolsTool } from "./rabin2SymbolsTool.js";
import { elfAnalyzeTool } from "./elfTool.js";

export const tools: Tool[] = [
  stringsTool,
  rabin2SymbolsTool,
  elfAnalyzeTool,
];

export function toolsDescription() {
  return tools.map(t => `- ${t.name}: ${t.description}`).join("\n");
}

export function toOpenAIFunctions() {
  return tools.map(t => ({
    type: "function" as const,
    function: {
      name: t.name,
      description: t.description,
      parameters: t.schema
    }
  }));
}

export const toolMap = new Map(tools.map(t => [t.name, t]));
