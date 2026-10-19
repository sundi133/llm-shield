"""The AI catalog: what Shield recognizes as AI, and the signals that identify it.

Spec: docs/specs/ai-discovery.md, section 3.1. Collectors match against this
locally and report matches only, so the catalog is also the privacy boundary:
an app, extension, binary or package that is not here is never reported.

Kinds: app (desktop or IDE app), agent (a command-line or coding agent),
ai_service (a hosted model or AI API), model_runtime (a local model server),
framework (an SDK or agent framework found in code), mcp_server (only from
MCP configs; no static entries).

Tenants add their own entries (`discovery_catalog:{tenant}`, up to 500).
`replaces` maps an old entry id to this one when an entry is renamed or merged.
"""

from __future__ import annotations

import re
from typing import Any, Iterable, Optional

VERSION = "2026.10.1"
KINDS = ("app", "agent", "ai_service", "model_runtime", "framework", "mcp_server")
CUSTOM_MAX = 500


def _e(id, name, vendor, kind, *, domains=(), app_ids=(), ide_extensions=(), binaries=(),
       listen_ports=(), packages=(), replaces=()):
    return {"id": id, "name": name, "vendor": vendor, "kind": kind, "domains": list(domains),
            "app_ids": list(app_ids), "ide_extensions": list(ide_extensions),
            "binaries": list(binaries), "listen_ports": list(listen_ports),
            "packages": list(packages), "replaces": list(replaces)}


BUILTIN: list[dict] = [
    # ── assistants and chat apps ─────────────────────────────────────
    _e("chatgpt", "ChatGPT", "OpenAI", "app", domains=["chatgpt.com", "chat.openai.com"],
       app_ids=["com.openai.chat", "ChatGPT.exe"]),
    _e("openai-api", "OpenAI API", "OpenAI", "ai_service", domains=["api.openai.com"],
       packages=["openai", "npm:openai"]),
    _e("claude", "Claude", "Anthropic", "app", domains=["claude.ai"],
       app_ids=["com.anthropic.claudefordesktop", "Claude.exe"]),
    _e("anthropic-api", "Anthropic API", "Anthropic", "ai_service", domains=["api.anthropic.com"],
       packages=["anthropic", "npm:@anthropic-ai/sdk"]),
    _e("gemini", "Gemini", "Google", "app", domains=["gemini.google.com", "bard.google.com"]),
    _e("gemini-api", "Gemini API", "Google", "ai_service",
       domains=["generativelanguage.googleapis.com"],
       packages=["google-generativeai", "google-genai", "npm:@google/generative-ai", "npm:@google/genai"]),
    _e("ai-studio", "Google AI Studio", "Google", "ai_service", domains=["aistudio.google.com"]),
    _e("vertex-ai", "Vertex AI", "Google", "ai_service",
       domains=["aiplatform.googleapis.com", "*-aiplatform.googleapis.com"],
       packages=["google-cloud-aiplatform", "npm:@google-cloud/vertexai"]),
    _e("notebooklm", "NotebookLM", "Google", "app", domains=["notebooklm.google.com"]),
    _e("microsoft-copilot", "Microsoft Copilot", "Microsoft", "app",
       domains=["copilot.microsoft.com", "copilot.cloud.microsoft"]),
    _e("azure-openai", "Azure OpenAI", "Microsoft", "ai_service",
       domains=["*.openai.azure.com", "*.cognitiveservices.azure.com", "*.services.ai.azure.com"]),
    _e("aws-bedrock", "Amazon Bedrock", "Amazon", "ai_service",
       domains=["bedrock-runtime.*.amazonaws.com", "bedrock.*.amazonaws.com",
                "bedrock-agent-runtime.*.amazonaws.com"]),
    _e("aws-q", "Amazon Q", "Amazon", "app", domains=["q.*.amazonaws.com", "codewhisperer.*.amazonaws.com"],
       ide_extensions=["amazonwebservices.amazon-q-vscode"], binaries=["q"]),
    _e("mistral", "Mistral", "Mistral AI", "ai_service",
       domains=["api.mistral.ai", "chat.mistral.ai", "mistral.ai", "codestral.mistral.ai"],
       packages=["mistralai", "npm:@mistralai/mistralai"]),
    _e("cohere", "Cohere", "Cohere", "ai_service",
       domains=["api.cohere.ai", "api.cohere.com", "coral.cohere.com", "dashboard.cohere.com"],
       packages=["cohere", "npm:cohere-ai"]),
    _e("groq", "Groq", "Groq", "ai_service", domains=["api.groq.com", "groq.com", "console.groq.com"],
       packages=["groq", "npm:groq-sdk"]),
    _e("grok", "Grok", "xAI", "app", domains=["grok.com", "api.x.ai", "x.ai"],
       packages=["xai-sdk"]),
    _e("deepseek", "DeepSeek", "DeepSeek", "ai_service",
       domains=["deepseek.com", "chat.deepseek.com", "api.deepseek.com"]),
    _e("perplexity", "Perplexity", "Perplexity", "app",
       domains=["perplexity.ai", "api.perplexity.ai"], app_ids=["ai.perplexity.mac", "Perplexity.exe"]),
    _e("meta-ai", "Meta AI", "Meta", "app", domains=["meta.ai"]),
    _e("poe", "Poe", "Quora", "app", domains=["poe.com"]),
    _e("character-ai", "Character.AI", "Character.AI", "app", domains=["character.ai", "beta.character.ai"]),
    _e("you-com", "You.com", "You.com", "app", domains=["you.com"]),
    _e("phind", "Phind", "Phind", "app", domains=["phind.com"]),
    _e("pi", "Pi", "Inflection AI", "app", domains=["pi.ai"]),
    _e("kimi", "Kimi", "Moonshot AI", "app", domains=["kimi.moonshot.cn", "kimi.com", "api.moonshot.cn",
                                                       "api.moonshot.ai"]),
    _e("qwen", "Qwen", "Alibaba", "ai_service", domains=["chat.qwen.ai", "dashscope.aliyuncs.com",
                                                          "dashscope-intl.aliyuncs.com"],
       packages=["dashscope"]),
    _e("zhipu", "Zhipu GLM", "Zhipu AI", "ai_service", domains=["open.bigmodel.cn", "chatglm.cn",
                                                                 "api.z.ai", "z.ai"],
       packages=["zhipuai"]),
    _e("ernie", "ERNIE", "Baidu", "ai_service", domains=["qianfan.baidubce.com", "yiyan.baidu.com"]),
    _e("doubao", "Doubao", "ByteDance", "app", domains=["doubao.com", "ark.cn-beijing.volces.com"]),
    _e("minimax", "MiniMax", "MiniMax", "ai_service", domains=["api.minimax.chat", "api.minimaxi.com",
                                                                "minimax.io"]),

    # ── model and inference platforms ────────────────────────────────
    _e("openrouter", "OpenRouter", "OpenRouter", "ai_service", domains=["openrouter.ai"]),
    _e("together", "Together AI", "Together AI", "ai_service", domains=["api.together.xyz", "api.together.ai",
                                                                         "together.ai"],
       packages=["together", "npm:together-ai"]),
    _e("fireworks", "Fireworks AI", "Fireworks AI", "ai_service", domains=["api.fireworks.ai", "fireworks.ai"],
       packages=["fireworks-ai"]),
    _e("replicate", "Replicate", "Replicate", "ai_service", domains=["api.replicate.com", "replicate.com"],
       packages=["replicate", "npm:replicate"]),
    _e("huggingface", "Hugging Face", "Hugging Face", "ai_service",
       domains=["huggingface.co", "api-inference.huggingface.co", "router.huggingface.co",
                "*.endpoints.huggingface.cloud"],
       packages=["huggingface-hub", "transformers", "npm:@huggingface/inference"]),
    _e("deepinfra", "DeepInfra", "DeepInfra", "ai_service", domains=["api.deepinfra.com", "deepinfra.com"]),
    _e("cerebras", "Cerebras Inference", "Cerebras", "ai_service", domains=["api.cerebras.ai", "cerebras.ai"],
       packages=["cerebras-cloud-sdk"]),
    _e("sambanova", "SambaNova Cloud", "SambaNova", "ai_service", domains=["api.sambanova.ai"]),
    _e("ai21", "AI21 Labs", "AI21 Labs", "ai_service", domains=["api.ai21.com", "studio.ai21.com"],
       packages=["ai21"]),
    _e("nvidia-nim", "NVIDIA NIM", "NVIDIA", "ai_service", domains=["integrate.api.nvidia.com",
                                                                     "build.nvidia.com"]),
    _e("cloudflare-ai", "Cloudflare Workers AI", "Cloudflare", "ai_service",
       domains=["gateway.ai.cloudflare.com"]),
    _e("ibm-watsonx", "IBM watsonx.ai", "IBM", "ai_service",
       domains=["*.ml.cloud.ibm.com"], packages=["ibm-watsonx-ai"]),
    _e("ollama-cloud", "Ollama (cloud)", "Ollama", "ai_service", domains=["ollama.com"]),
    _e("lepton", "Lepton AI", "Lepton AI", "ai_service", domains=["*.lepton.run"]),
    _e("novita", "Novita AI", "Novita AI", "ai_service", domains=["api.novita.ai"]),
    _e("hyperbolic", "Hyperbolic", "Hyperbolic", "ai_service", domains=["api.hyperbolic.xyz"]),
    _e("nebius", "Nebius AI Studio", "Nebius", "ai_service", domains=["api.studio.nebius.ai",
                                                                       "api.studio.nebius.com"]),

    # ── speech, image, video, embeddings ─────────────────────────────
    _e("elevenlabs", "ElevenLabs", "ElevenLabs", "ai_service", domains=["api.elevenlabs.io", "elevenlabs.io"],
       packages=["elevenlabs"]),
    _e("assemblyai", "AssemblyAI", "AssemblyAI", "ai_service", domains=["api.assemblyai.com"],
       packages=["assemblyai"]),
    _e("deepgram", "Deepgram", "Deepgram", "ai_service", domains=["api.deepgram.com"],
       packages=["deepgram-sdk"]),
    _e("stability", "Stability AI", "Stability AI", "ai_service", domains=["api.stability.ai"]),
    _e("midjourney", "Midjourney", "Midjourney", "app", domains=["midjourney.com"]),
    _e("runway", "Runway", "Runway", "ai_service", domains=["api.runwayml.com", "app.runwayml.com",
                                                             "runwayml.com"]),
    _e("leonardo", "Leonardo.Ai", "Leonardo.Ai", "app", domains=["leonardo.ai", "cloud.leonardo.ai"]),
    _e("ideogram", "Ideogram", "Ideogram", "app", domains=["ideogram.ai"]),
    _e("suno", "Suno", "Suno", "app", domains=["suno.com", "suno.ai"]),
    _e("heygen", "HeyGen", "HeyGen", "app", domains=["heygen.com", "api.heygen.com"]),
    _e("synthesia", "Synthesia", "Synthesia", "app", domains=["synthesia.io"]),
    _e("voyage", "Voyage AI", "Voyage AI", "ai_service", domains=["api.voyageai.com"],
       packages=["voyageai"]),
    _e("jina", "Jina AI", "Jina AI", "ai_service", domains=["api.jina.ai", "r.jina.ai", "s.jina.ai"]),
    _e("otter", "Otter.ai", "Otter.ai", "app", domains=["otter.ai"]),
    _e("fireflies", "Fireflies.ai", "Fireflies.ai", "app", domains=["fireflies.ai", "api.fireflies.ai"]),
    _e("gamma", "Gamma", "Gamma", "app", domains=["gamma.app"]),
    _e("grammarly", "Grammarly", "Grammarly", "app", domains=["grammarly.com", "grammarly.io"],
       app_ids=["com.grammarly.ProjectLlama", "Grammarly.exe"]),
    _e("deepl", "DeepL", "DeepL", "app", domains=["deepl.com", "api.deepl.com", "api-free.deepl.com"],
       app_ids=["com.linguee.DeepLCopyTranslator", "DeepL.exe"]),
    _e("quillbot", "QuillBot", "QuillBot", "app", domains=["quillbot.com"]),
    _e("jasper", "Jasper", "Jasper", "app", domains=["jasper.ai", "app.jasper.ai"]),
    _e("writer", "Writer", "Writer", "ai_service", domains=["writer.com", "api.writer.com"],
       packages=["writer-sdk"]),
    _e("copy-ai", "Copy.ai", "Copy.ai", "app", domains=["copy.ai", "app.copy.ai"]),

    # ── coding assistants, IDEs and app builders ─────────────────────
    _e("github-copilot", "GitHub Copilot", "GitHub", "app",
       domains=["githubcopilot.com", "*.githubcopilot.com", "copilot-proxy.githubusercontent.com"],
       ide_extensions=["github.copilot", "github.copilot-chat"]),
    _e("cursor", "Cursor", "Anysphere", "app", domains=["api2.cursor.sh", "*.cursor.sh", "cursor.com"],
       app_ids=["com.todesktop.230313mzl4w4u92", "Cursor.exe"], binaries=["cursor-agent"]),
    _e("windsurf", "Windsurf", "Windsurf", "app",
       domains=["windsurf.com", "server.codeium.com", "*.codeium.com"],
       app_ids=["com.exafunction.windsurf", "Windsurf.exe"], ide_extensions=["codeium.codeium"]),
    _e("tabnine", "Tabnine", "Tabnine", "app", domains=["tabnine.com", "*.tabnine.com"],
       ide_extensions=["tabnine.tabnine-vscode"]),
    _e("cody", "Sourcegraph Cody", "Sourcegraph", "app", domains=["sourcegraph.com"],
       ide_extensions=["sourcegraph.cody-ai"]),
    _e("continue", "Continue", "Continue", "app", domains=["continue.dev", "api.continue.dev"],
       ide_extensions=["continue.continue"]),
    _e("cline", "Cline", "Cline", "app", ide_extensions=["saoudrizwan.claude-dev"]),
    _e("roo-code", "Roo Code", "Roo Code", "app", ide_extensions=["rooveterinaryinc.roo-cline"]),
    _e("kilo-code", "Kilo Code", "Kilo Code", "app", ide_extensions=["kilocode.kilo-code"]),
    _e("gemini-code-assist", "Gemini Code Assist", "Google", "app",
       domains=["cloudcode-pa.googleapis.com"], ide_extensions=["google.geminicodeassist"]),
    _e("supermaven", "Supermaven", "Supermaven", "app", domains=["supermaven.com", "*.supermaven.com"],
       ide_extensions=["supermaven.supermaven"]),
    _e("blackbox", "Blackbox AI", "Blackbox", "app", domains=["blackbox.ai", "www.blackbox.ai"],
       ide_extensions=["blackboxapp.blackbox"]),
    _e("codegpt", "CodeGPT", "CodeGPT", "app", domains=["codegpt.co"],
       ide_extensions=["danielsanmedium.dscodegpt"]),
    _e("claude-code", "Claude Code", "Anthropic", "agent", ide_extensions=["anthropic.claude-code"],
       binaries=["claude"], packages=["npm:@anthropic-ai/claude-code"]),
    _e("codex", "Codex CLI", "OpenAI", "agent", ide_extensions=["openai.chatgpt"],
       binaries=["codex"], packages=["npm:@openai/codex"]),
    _e("gemini-cli", "Gemini CLI", "Google", "agent", binaries=["gemini"],
       packages=["npm:@google/gemini-cli"]),
    _e("aider", "Aider", "Aider", "agent", binaries=["aider"], packages=["aider-chat"]),
    _e("goose", "Goose", "Block", "agent", binaries=["goose"]),
    _e("opencode", "opencode", "SST", "agent", binaries=["opencode"], packages=["npm:opencode-ai"]),
    _e("amp", "Amp", "Sourcegraph", "agent", domains=["ampcode.com"], binaries=["amp"],
       packages=["npm:@sourcegraph/amp"]),
    _e("crush", "Crush", "Charm", "agent", binaries=["crush"]),
    _e("qwen-code", "Qwen Code", "Alibaba", "agent", binaries=["qwen"], packages=["npm:@qwen-code/qwen-code"]),
    _e("devin", "Devin", "Cognition", "agent", domains=["devin.ai", "app.devin.ai", "api.devin.ai"]),
    _e("replit", "Replit Agent", "Replit", "app", domains=["replit.com"]),
    _e("v0", "v0", "Vercel", "app", domains=["v0.dev", "v0.app"]),
    _e("bolt", "Bolt", "StackBlitz", "app", domains=["bolt.new"]),
    _e("lovable", "Lovable", "Lovable", "app", domains=["lovable.dev"]),
    _e("jetbrains-ai", "JetBrains AI Assistant", "JetBrains", "app",
       domains=["api.jetbrains.ai", "grazie.ai"]),
    _e("zed-ai", "Zed AI", "Zed Industries", "app", domains=["llm.zed.dev"]),
    _e("warp", "Warp AI", "Warp", "app", domains=["app.warp.dev"], app_ids=["dev.warp.Warp-Stable"]),

    # ── local model runtimes ─────────────────────────────────────────
    _e("ollama", "Ollama", "Ollama", "model_runtime", app_ids=["com.electron.ollama", "ollama app.exe"],
       binaries=["ollama"], listen_ports=[11434], packages=["ollama", "npm:ollama"]),
    _e("lm-studio", "LM Studio", "Element Labs", "model_runtime",
       app_ids=["ai.elementlabs.lmstudio", "LM Studio.exe"], binaries=["lms"], listen_ports=[1234]),
    _e("gpt4all", "GPT4All", "Nomic AI", "model_runtime", app_ids=["io.gpt4all.gpt4all", "chat.exe"],
       listen_ports=[4891], packages=["gpt4all"]),
    _e("jan", "Jan", "Menlo Research", "model_runtime", app_ids=["jan.ai.app", "Jan.exe"],
       listen_ports=[1337]),
    _e("llamafile", "llamafile", "Mozilla", "model_runtime", binaries=["llamafile"]),
    _e("llama-cpp", "llama.cpp server", "ggml", "model_runtime", binaries=["llama-server", "llama-cli"],
       packages=["llama-cpp-python"]),
    _e("vllm", "vLLM", "vLLM", "model_runtime", binaries=["vllm"], packages=["vllm"]),
    _e("localai", "LocalAI", "LocalAI", "model_runtime", binaries=["local-ai"]),
    _e("msty", "Msty", "Msty", "model_runtime", app_ids=["app.msty.app", "Msty.exe"]),
    _e("anythingllm", "AnythingLLM", "Mintplex Labs", "model_runtime",
       app_ids=["com.anythingllm", "AnythingLLM.exe"]),

    # ── frameworks and SDKs (found in code) ──────────────────────────
    _e("langchain", "LangChain", "LangChain", "framework",
       domains=["api.smith.langchain.com"],
       packages=["langchain", "langchain-core", "langchain-openai", "langchain-anthropic",
                 "langchain-community", "npm:langchain", "npm:@langchain/core",
                 "npm:@langchain/openai", "npm:@langchain/anthropic"]),
    _e("langgraph", "LangGraph", "LangChain", "framework",
       packages=["langgraph", "npm:@langchain/langgraph"]),
    _e("llamaindex", "LlamaIndex", "LlamaIndex", "framework", domains=["api.cloud.llamaindex.ai"],
       packages=["llama-index", "llama-index-core", "npm:llamaindex"]),
    _e("crewai", "CrewAI", "CrewAI", "framework", packages=["crewai", "crewai-tools"]),
    _e("autogen", "AutoGen", "Microsoft", "framework",
       packages=["autogen-agentchat", "autogen-core", "pyautogen", "ag2"]),
    _e("semantic-kernel", "Semantic Kernel", "Microsoft", "framework",
       packages=["semantic-kernel", "npm:@microsoft/semantic-kernel"]),
    _e("haystack", "Haystack", "deepset", "framework", packages=["haystack-ai", "farm-haystack"]),
    _e("dspy", "DSPy", "Stanford NLP", "framework", packages=["dspy", "dspy-ai"]),
    _e("litellm", "LiteLLM", "BerriAI", "framework", packages=["litellm"]),
    _e("openai-agents", "OpenAI Agents SDK", "OpenAI", "framework",
       packages=["openai-agents", "npm:@openai/agents"]),
    _e("claude-agent-sdk", "Claude Agent SDK", "Anthropic", "framework",
       packages=["claude-agent-sdk", "claude-code-sdk", "npm:@anthropic-ai/claude-agent-sdk"]),
    _e("google-adk", "Agent Development Kit", "Google", "framework", packages=["google-adk"]),
    _e("smolagents", "smolagents", "Hugging Face", "framework", packages=["smolagents"]),
    _e("pydantic-ai", "Pydantic AI", "Pydantic", "framework", packages=["pydantic-ai", "pydantic-ai-slim"]),
    _e("instructor", "Instructor", "Instructor", "framework", packages=["instructor"]),
    _e("vercel-ai-sdk", "Vercel AI SDK", "Vercel", "framework",
       packages=["npm:ai", "npm:@ai-sdk/openai", "npm:@ai-sdk/anthropic", "npm:@ai-sdk/google"]),
    _e("mastra", "Mastra", "Mastra", "framework", packages=["npm:@mastra/core"]),
    _e("strands", "Strands Agents", "AWS", "framework", packages=["strands-agents"]),
    _e("agno", "Agno", "Agno", "framework", packages=["agno"]),
    _e("mcp-sdk", "MCP SDK", "Anthropic", "framework",
       packages=["mcp", "fastmcp", "npm:@modelcontextprotocol/sdk"]),
    _e("guidance", "Guidance", "Microsoft", "framework", packages=["guidance"]),
    _e("outlines", "Outlines", ".txt", "framework", packages=["outlines"]),

    # ── observability and vector stores used by AI apps ──────────────
    _e("langsmith", "LangSmith", "LangChain", "ai_service", domains=["smith.langchain.com"],
       packages=["langsmith"]),
    _e("langfuse", "Langfuse", "Langfuse", "ai_service", domains=["cloud.langfuse.com", "us.cloud.langfuse.com"],
       packages=["langfuse"]),
    _e("helicone", "Helicone", "Helicone", "ai_service", domains=["oai.helicone.ai", "api.helicone.ai"]),
    _e("weights-biases", "Weights & Biases Weave", "Weights & Biases", "ai_service",
       domains=["trace.wandb.ai"], packages=["weave"]),
    _e("pinecone", "Pinecone", "Pinecone", "ai_service", domains=["*.pinecone.io"],
       packages=["pinecone", "pinecone-client", "npm:@pinecone-database/pinecone"]),
    _e("weaviate", "Weaviate Cloud", "Weaviate", "ai_service", domains=["*.weaviate.cloud", "*.weaviate.network"],
       packages=["weaviate-client"]),
    _e("qdrant", "Qdrant Cloud", "Qdrant", "ai_service", domains=["*.cloud.qdrant.io"],
       packages=["qdrant-client"]),
    _e("chroma", "Chroma", "Chroma", "ai_service", domains=["api.trychroma.com"], packages=["chromadb"]),

    # ── workplace assistants ─────────────────────────────────────────
    _e("glean", "Glean", "Glean", "app", domains=["*.glean.com"]),
    _e("zoom-ai", "Zoom AI Companion", "Zoom", "app", domains=["ai.zoom.us"]),
    _e("chatgpt-enterprise-connectors", "ChatGPT connectors", "OpenAI", "app",
       domains=["connectors.openai.com"]),
    _e("manus", "Manus", "Manus", "agent", domains=["manus.im"]),
    _e("genspark", "Genspark", "Genspark", "agent", domains=["genspark.ai"]),
    _e("comet", "Comet browser", "Perplexity", "app", app_ids=["ai.perplexity.comet", "Comet.exe"]),
    _e("chatgpt-atlas", "ChatGPT Atlas", "OpenAI", "app", app_ids=["com.openai.atlas"]),
    _e("dia", "Dia browser", "The Browser Company", "app", app_ids=["company.thebrowser.dia"]),
    _e("raycast-ai", "Raycast AI", "Raycast", "app", domains=["backend.raycast.com"]),
    _e("superhuman-ai", "Superhuman AI", "Superhuman", "app", domains=["superhuman.com"]),
]

#: Where MCP clients keep their server lists, per OS. `~` and %APPDATA% /
#: %USERPROFILE% are expanded on the device. key: the JSON or TOML table that
#: holds servers.
MCP_CONFIG_PATHS: list[dict] = [
    {"client": "claude-desktop", "os": "macos", "path": "~/Library/Application Support/Claude/claude_desktop_config.json", "key": "mcpServers"},
    {"client": "claude-desktop", "os": "windows", "path": "%APPDATA%/Claude/claude_desktop_config.json", "key": "mcpServers"},
    {"client": "claude-code", "os": "any", "path": "~/.claude.json", "key": "mcpServers"},
    {"client": "cursor", "os": "any", "path": "~/.cursor/mcp.json", "key": "mcpServers"},
    {"client": "windsurf", "os": "any", "path": "~/.codeium/windsurf/mcp_config.json", "key": "mcpServers"},
    {"client": "vscode", "os": "macos", "path": "~/Library/Application Support/Code/User/mcp.json", "key": "servers"},
    {"client": "vscode", "os": "windows", "path": "%APPDATA%/Code/User/mcp.json", "key": "servers"},
    {"client": "gemini-cli", "os": "any", "path": "~/.gemini/settings.json", "key": "mcpServers"},
    {"client": "codex", "os": "any", "path": "~/.codex/config.toml", "key": "mcp_servers"},
    {"client": "cline", "os": "macos", "path": "~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json", "key": "mcpServers"},
    {"client": "cline", "os": "windows", "path": "%APPDATA%/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json", "key": "mcpServers"},
]

#: Shield's own domains are never inventory entries.
SHIELD_DOMAINS = ("votal.ai",)

_HOST = re.compile(r"^(?=.{1,253}$)(\*\.|[a-z0-9*](?:[a-z0-9*-]{0,61}[a-z0-9])?\.)*[a-z0-9-]{2,63}(/[\w./-]*)?$")


def _custom(tenant_id: str) -> list[dict]:
    if not tenant_id:
        return []
    try:
        from storage.tenant_store import kv_get
        v = kv_get(f"discovery_catalog:{tenant_id}")
        return v if isinstance(v, list) else []
    except Exception:
        return []


def entries(tenant_id: str = "") -> list[dict]:
    """The built-in catalog plus the tenant's entries (a tenant entry with the
    same id replaces the built-in one)."""
    out = {e["id"]: e for e in BUILTIN}
    for e in _custom(tenant_id):
        out[e["id"]] = {**_e(e["id"], e["name"], e.get("vendor", ""), e["kind"]), **e, "custom": True}
    return list(out.values())


def by_id(tenant_id: str = "") -> dict:
    out = {e["id"]: e for e in entries(tenant_id)}
    for e in list(out.values()):
        for old in e.get("replaces") or []:
            out.setdefault(old, e)
    return out


def normalize_host(host: str) -> str:
    h = (host or "").strip().lower()
    h = re.sub(r"^[a-z][a-z0-9+.-]*://", "", h)
    h = h.split("/")[0].split("@")[-1]
    h = re.sub(r":\d+$", "", h)
    return h.rstrip(".")


def _domain_matches(pattern: str, host: str) -> bool:
    p = pattern.lower().split("/")[0]
    if p.startswith("*."):
        return host.endswith(p[1:]) and host != p[2:]
    if "*" in p:
        rx = "^" + re.escape(p).replace(r"\*", "[a-z0-9-]+") + "$"
        return re.match(rx, host) is not None
    return host == p or host.endswith("." + p)


def is_shield_host(host: str) -> bool:
    host = normalize_host(host)
    return any(host == d or host.endswith("." + d) for d in SHIELD_DOMAINS)


def match_domain(host: str, catalog: Optional[list] = None) -> Optional[dict]:
    """The catalog entry for a hostname, most specific pattern first."""
    host = normalize_host(host)
    if not host or is_shield_host(host):
        return None
    best, best_len = None, -1
    for e in catalog if catalog is not None else BUILTIN:
        for d in e.get("domains") or []:
            if _domain_matches(d, host):
                score = len(d.replace("*", ""))
                if score > best_len:
                    best, best_len = e, score
    return best


def match_field(field: str, value: str, catalog: Optional[list] = None) -> Optional[dict]:
    """By app_ids, ide_extensions, binaries, packages (case-insensitive) or
    listen_ports (int)."""
    for e in catalog if catalog is not None else BUILTIN:
        vals = e.get(field) or []
        if field == "listen_ports":
            if value in vals:
                return e
        elif str(value).lower() in {str(v).lower() for v in vals}:
            return e
    return None


def registrable_domain(host: str) -> str:
    """A rough eTLD+1: the last two labels, or three for common two-part TLDs."""
    parts = normalize_host(host).split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "com", "ac", "gov", "org", "net") and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def validate_custom(raw: Any) -> list[dict]:
    """A tenant's own entries. Raises ValueError with every problem."""
    if not isinstance(raw, list) or len(raw) > CUSTOM_MAX:
        raise ValueError(f"entries: a list of at most {CUSTOM_MAX}")
    errors, out, seen = [], [], set()
    for i, e in enumerate(raw):
        where = f"entries[{i}]"
        if not isinstance(e, dict):
            errors.append(f"{where}: an object")
            continue
        eid = str(e.get("id") or "").strip()
        if not re.match(r"^[a-z0-9][a-z0-9._-]{0,63}$", eid) or eid in seen:
            errors.append(f"{where}.id: unique, lowercase letters, digits, . _ -")
        seen.add(eid)
        kind = e.get("kind")
        if kind not in KINDS or kind == "mcp_server":
            errors.append(f"{where}.kind: one of {', '.join(k for k in KINDS if k != 'mcp_server')}")
        name = str(e.get("name") or "").strip()[:100]
        if not name:
            errors.append(f"{where}.name: required")
        domains = [normalize_host(d) if "/" not in d else d.lower() for d in (e.get("domains") or [])][:50]
        for d in domains:
            if not _HOST.match(d):
                errors.append(f"{where}.domains: '{d}' is not a hostname pattern")
        out.append(_e(eid, name, str(e.get("vendor") or "")[:100], kind, domains=domains,
                      app_ids=[str(x)[:200] for x in (e.get("app_ids") or [])][:20],
                      ide_extensions=[str(x).lower()[:200] for x in (e.get("ide_extensions") or [])][:20],
                      binaries=[str(x)[:64] for x in (e.get("binaries") or [])][:20],
                      listen_ports=[int(p) for p in (e.get("listen_ports") or [])
                                    if isinstance(p, int) and 0 < p < 65536][:10],
                      packages=[str(x).lower()[:200] for x in (e.get("packages") or [])][:50]))
    if errors:
        raise ValueError("; ".join(errors))
    return out


def device_bundle(tenant_id: str = "") -> dict:
    """What the device agent needs to match locally: signals only, no domains
    it cannot see. Shipped in the signed device bundle when discovery is on."""
    cat = entries(tenant_id)
    return {"version": VERSION,
            "apps": [{"id": e["id"], "app_ids": e["app_ids"]} for e in cat if e["app_ids"]],
            "extensions": [{"id": e["id"], "ids": e["ide_extensions"]} for e in cat if e["ide_extensions"]],
            "binaries": [{"id": e["id"], "names": e["binaries"]} for e in cat if e["binaries"]],
            "ports": [{"id": e["id"], "ports": e["listen_ports"]} for e in cat if e["listen_ports"]],
            "mcp_config_paths": MCP_CONFIG_PATHS}


def domains(tenant_id: str = "") -> list[str]:
    """Every catalog domain pattern (for the proxy shipper and log import)."""
    out = set()
    for e in entries(tenant_id):
        out.update(d.split("/")[0] for d in e.get("domains") or [])
    return sorted(out)


def iter_signals(catalog: Iterable[dict], field: str):
    for e in catalog:
        for v in e.get(field) or []:
            yield v, e
