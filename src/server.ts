import express from "express";
import cors from "cors";
import { applyFilter, hashForAudit, FilterPack } from "./safety/filter.js";
import { composeMessages } from "./prompt/pipeline.js";
import { toolsDescription } from "./tools/index.js";
import { runAgent } from "./agent/runAgent.js";
import { postProcessText } from "./utils/postprocess.js";

const app = express();
app.use(cors());
app.use(express.json({ limit: "2mb" }));

app.get("/health", (_req, res) => {
  res.json({ ok: true });
});

// 页面“so-decompiler”放行专业词，其他页面用全局策略
const filterPack: FilterPack = {
  base: {
    blocklist: [
      "诱导点击", "强制评分", "后台自启动",
      "绕过支付", "绕过订阅", "木马", "社工库",
      // 面向用户可见文本的敏感技术词汇（统一委婉化）
      "反编译", "逆向", "脱壳", "绕过", "破解", "破解版", "黑客",
      "注入", "劫持", "Hook", "hook", "Frida", "Xposed",
      "抓包", "嗅探", "拦截", "旁路", "反汇编"
    ],
    allowlist: ["so", "ELF", "ABI", "符号", "符号表"],
    replacements: {
      "诱导点击": "不当引导",
      "强制评分": "不当引导评分",
      "后台自启动": "后台不当自启",
      "绕过支付": "违规支付",
      "绕过订阅": "违规订阅",
      "木马": "恶意程序",
      "社工库": "敏感数据源",
      // 委婉替换
      "反编译": "代码结构解析",
      "逆向": "二进制分析",
      "脱壳": "解包",
      "绕过": "兼容性调整",
      "破解": "不推荐做法",
      "破解版": "非官方版本",
      "黑客": "高级用户",
      "注入": "动态加载",
      "劫持": "中间处理",
      "Hook": "方法跟踪",
      "hook": "方法跟踪",
      "Frida": "运行时工具",
      "Xposed": "系统框架",
      "抓包": "网络调试",
      "嗅探": "网络分析",
      "拦截": "中间处理",
      "旁路": "备用路径",
      "反汇编": "汇编视图"
    }
  },
  pages: [
    { pageId: "so-decompiler", allowlist: [
      "so", "ELF", "符号", "符号表", "ABI", "导出", "导入",
      "Crash", "Backtrace", "重定位", "调用图", "节", "段", "架构", "地址"
    ] }
  ]
};

const coreSystem = "你是可组合的技术助手，按页面上下文、工具与记忆动态工作，禁止输出违禁内容。";
const basePolicy = [
  "- 优先给出计划与下一步动作；需要时调用工具。",
  "- 不输出引导性违规语句；必要时用替代词表达。",
  "- 解释二进制分析仅限合法合规场景（教育/调试/兼容性排查）。"
].join("\n");

app.post("/agent", async (req, res) => {
  const { pageId, userInput, memory } = req.body as { pageId?: string; userInput: string; memory?: string };

  const inRes = applyFilter(userInput, filterPack, pageId);
  const pageContext = pageId === "so-decompiler"
    ? "页面：SO 二进制分析助手。目标：字符串/符号/导出/导入/架构信息分析，辅助崩溃栈定位。"
    : `页面：${pageId ?? "通用"}`;

  const msgs = composeMessages({
    coreSystem,
    policy: basePolicy,
    pageContext,
    toolsDescription: toolsDescription(),
    memory,
    userInput: inRes.output
  });

  const final = await runAgent(msgs as any, 8);
  const polished = postProcessText(final);

  const outRes = applyFilter(polished, filterPack, pageId);

  const uid = hashForAudit(req.ip || "x");
  console.log(`[audit] ${uid} page=${pageId} in_hits=${inRes.hits.length} out_hits=${outRes.hits.length}`);

  res.json({
    pageId,
    input_action: inRes.action,
    output_action: outRes.action,
    content: outRes.output
  });
});

const PORT = process.env.PORT ? Number(process.env.PORT) : 8787;
app.listen(PORT, () => {
  console.log(`Agent server on :${PORT}`);
});
