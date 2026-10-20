# Install the Votal Guardrails kit from GitHub

This directory contains the complete customer kit. The repository is public; no tenant keys or customer configuration are included. Each customer provides its own Votal tenant credential.

## Download

Clone the repository with a sparse checkout so only this integration is downloaded into the working tree:

    git clone --filter=blob:none --sparse https://github.com/sundi133/llm-shield.git
    cd llm-shield
    git sparse-checkout set integrations/codex/votal-guardrails
    cd integrations/codex/votal-guardrails

These commands use the default branch after the hosting pull request is merged. To evaluate the hosting PR before merge, add --branch codex/votal-guardrails-customer-kit to the git clone command. Enterprise administrators should select and review an immutable commit before rollout.

## Install and configure

From this directory:

    codex plugin marketplace add .
    codex plugin add votal-ai-guardrails@votal-guardrails-customer
    python3 plugins/votal-ai-guardrails/scripts/start_guarded.py --cli

The launcher asks for the customer's key with hidden input and passes it to the Codex child process in memory. It does not save a key to disk. Do not include a key in the clone URL, command arguments, Git files, or support messages.

Then review and trust the UserPromptSubmit hook through /hooks in Codex CLI. Follow the [full installation and acceptance-test guide](plugins/votal-ai-guardrails/README.md) for desktop launching, endpoint selection, policy configuration, and tests. The key used for the automatic prompt hook is separate from any saved MCP connection credential.

## Enterprise rollout

Start with a small customer pilot and verify allowed and confidential-pricing test requests against that customer's tenant. For mandatory enforcement, the customer's IT team must deploy reviewed scripts and credentials through its approved device/secrets management and use managed hook policy. This kit does not install managed policy, prevent users disabling local hooks, or protect browser-only chats.

## Updates

Have IT review the new version and commit. Update the checkout, reinstall the plugin using the commands above, reload Codex, review any changed hook definitions, and rerun acceptance tests. Keep a record of the approved commit and package checksum. Do not automatically deploy an unreviewed branch head.

## Verify the source

From this directory:

    python3 -m unittest discover -s tests -v

These tests use mocked decisions and synthetic credentials. Live customer policy enforcement and installed hook activation require the acceptance tests in the guide.
