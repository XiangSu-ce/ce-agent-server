// Vercel Serverless Function 入口
import express from 'express';
import cors from 'cors';
import { applyFilter, hashForAudit } from '../dist/safety/filter.js';
import { composeMessages } from '../dist/prompt/pipeline.js';
import { toolsDescription } from '../dist/tools/index.js';
import { runAgent } from '../dist/agent/runAgent.js';
import { postProcessText } from '../dist/utils/postprocess.js';

const app = express();
app.use(cors());
app.use(express.json({ limit: '2mb' }));

// 健康检查
app.get('/api/health', (req, res) => {
  res.json({ ok: true });
});

app.get('/health', (req, res) => {
  res.json({ ok: true });
});

// Agent 接口
const filterPack = {
  base: {
    blocklist: [
      "诱导点击", "强制评分", "后台自启动",
      "绕过支付", "绕过订阅", "木马", "社工库",
      "反编译", "逆向", "脱壳", "绕过", "破解", "破解版", "黑客",
      "注入", "劫持", "Hook", "hook", "Frida", "Xposed",
      "抓包", "嗅探", "拦截", "旁路", "反汇编"
    ],
    allowlist: ["so", "ELF", "ABI", "符号", "符号表"],
    replacements: {
      "反编译": "代码结构解析",
      "逆向": "二进制分析",
      "Hook": "方法跟踪",
      "hook": "方法跟踪"
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

app.post('/api/agent', async (req, res) => {
  try {
    const { pageId, userInput, memory } = req.body;

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

    const final = await runAgent(msgs, 8);
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
  } catch (error) {
    console.error('Agent error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/agent', async (req, res) => {
  // 兼容旧路径
  return app.handle(req, res);
});

// 导出为 Vercel Serverless Function
export default app;
