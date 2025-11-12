export type Msg = { role: "system"|"user"|"assistant"|"tool"; content: string; name?: string; tool_call_id?: string };

export type PromptParts = {
  coreSystem: string;
  policy?: string;
  pageContext?: string;
  toolsDescription?: string;
  memory?: string;
  userInput: string;
};

export function composeMessages(p: PromptParts): Msg[] {
  const msgs: Msg[] = [{ role: "system", content: p.coreSystem.trim() }];
  if (p.policy) msgs.push({ role: "system", content: p.policy.trim() });
  if (p.pageContext) msgs.push({ role: "system", content: p.pageContext.trim() });
  if (p.toolsDescription) msgs.push({ role: "system", content: p.toolsDescription.trim() });
  if (p.memory) msgs.push({ role: "system", content: `Memory:\n${p.memory.trim()}` });
  msgs.push({ role: "user", content: p.userInput.trim() });
  return msgs;
}
