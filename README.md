# Agent Server

Backend for configurable prompt pipeline + tool-enabled AI agent with bidirectional forbidden-words filtering.

Quick start

1) Install deps
- cd agent-server
- npm i

2) Configure env
- copy .env.example to .env and set OPENAI_API_KEY

3) Start (dev)
- npm run dev

4) Health check
- curl http://localhost:8787/health

5) Agent call
- POST http://localhost:8787/agent
  Body:
  {
    "pageId": "so-decompiler",
    "userInput": "对 /data/local/tmp/liba.so 做 ELF 头/Section/Dynamic/导入(按类型与绑定统计)/重定位/哈希摘要分析，并过滤包含 memcpy 的符号",
    "memory": null
  }

- To call elf_analyze directly via agent (example prompt):
  "请对 /data/local/tmp/liba.so 执行 elf_analyze，输出 demangle=true，filters.include=memcpy，topN=50"

Notes
- Tools
  - binary_strings: pure JS extractor for ASCII/UTF-16LE strings.
  - rabin2_symbols: requires radare2 (rabin2) installed; otherwise returns a helpful error.
  - elf_analyze: pure TS ELF parser for header, sections, dynamic (NEEDED/RUNPATH/RPATH/SONAME), imports with bind/type aggregation, relocations (.rel[a].plt/.rel[a].dyn), GNU/SysV hash summary, optional C++ demangling, suspicious-imports categorization, entry-candidate discovery (JNI_OnLoad/init_array/exports), anomaly sniffing (.text/.data/.rodata flags、节尺寸/偏移越界等) and Markdown rendering for UI.
- Filtering
  - Global blocklist with page-level allowlist; "so/ELF/反编译/反汇编/符号/ABI" allowed on pageId=so-decompiler.
- Models
  - OPENAI_MODEL defaults to gpt-4o-mini; override in .env.
