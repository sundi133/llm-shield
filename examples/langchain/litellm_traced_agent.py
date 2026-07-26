#!/usr/bin/env python3
"""LangChain agent whose calls carry Shield identity + run-tracing headers.

Two sides of the same three headers:

  • LangChain (this file) SETS them via ChatOpenAI(default_headers=...):
        x-agent-key    which agent is calling
        x-user-role    the caller's role (RBAC)
        x-shield-run-id ties every guard record of this run together

  • LiteLLM FORWARDS them to Shield via its proxy config:
        model_list:
          - model_name: gpt-4o
            litellm_params: { model: openai/gpt-4o, api_key: os.environ/OPENAI_API_KEY }
        litellm_settings:
          callbacks: ["otel"]          # emit LLM spans + propagate traceparent
        mcp_servers:
          files:
            url: https://<shield>/gateway/files/mcp
            extra_headers: ["x-agent-key", "x-user-role", "x-shield-run-id"]

Point ChatOpenAI at LiteLLM (or at Shield's /v1 directly). One run_id is used for
the whole agent run so all of Shield's records — and, with tracing on, all spans —
correlate into one run.

    pip install langchain-openai
    export LLM_BASE_URL=http://localhost:4000/v1   # LiteLLM proxy
    export LLM_API_KEY=sk-...                       # LiteLLM key
    python examples/langchain/litellm_traced_agent.py
"""
import os
import uuid

from langchain_openai import ChatOpenAI


def build_llm(run_id: str) -> ChatOpenAI:
    """A chat model that stamps Shield identity + run headers on every request."""
    return ChatOpenAI(
        base_url=os.environ.get("LLM_BASE_URL", "http://localhost:4000/v1"),
        api_key=os.environ.get("LLM_API_KEY", "sk-noauth"),
        model=os.environ.get("LLM_MODEL", "gpt-4o"),
        temperature=0,
        # These reach Shield: LiteLLM forwards them via `extra_headers`.
        default_headers={
            "x-agent-key": "support-bot",
            "x-user-role": "support_agent",
            "x-shield-run-id": run_id,      # stable for the whole run
        },
    )


def main():
    # One run id per agent run. Generate here (or accept from your caller) and reuse
    # it for every turn — that is what correlates the run across LiteLLM + Shield.
    run_id = os.environ.get("RUN_ID", f"run-{uuid.uuid4().hex[:12]}")
    print(f"Agent run: {run_id}\n")

    llm = build_llm(run_id)          # reuse the same instance -> same headers every turn

    # A short multi-turn conversation. Every .invoke() sends the three headers,
    # so Shield sees one run across all turns.
    history = [("system", "You are a concise support agent.")]
    for user_msg in ["Is order 8821 eligible for a refund?", "Great, please proceed."]:
        history.append(("human", user_msg))
        reply = llm.invoke(history)
        history.append(("ai", reply.content))
        print(f"user: {user_msg}\nbot:  {reply.content}\n")

    print(f"All turns shared x-shield-run-id={run_id}.")
    print("Filter metadata.run_id in Shield's audit log, or run.id in your trace backend.")


if __name__ == "__main__":
    main()
