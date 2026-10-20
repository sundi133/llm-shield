# Votal Guardrails customer kit - 0.2.0

Read [the installation guide](plugins/votal-ai-guardrails/README.md) before enabling the hook. This bundle is for private installation in supported local Codex sessions.

Extract the entire kit to a stable directory. Open a terminal in this extracted directory, then register and install:

    codex plugin marketplace add .
    codex plugin add votal-ai-guardrails@votal-guardrails-customer

Start Codex CLI through the included launcher:

    python3 plugins/votal-ai-guardrails/scripts/start_guarded.py --cli

The launcher asks for the customer's tenant key with hidden input. It does not save the key to disk. Each customer supplies its own key. Then use /hooks to review and trust the installed UserPromptSubmit hook, and run the acceptance tests in the guide.

For macOS desktop, quit existing Codex instances fully, then use the actual installed app location:

    python3 plugins/votal-ai-guardrails/scripts/start_guarded.py --app "/Applications/Codex.app"

The app location above is an example; replace it if the app is elsewhere. Start with the launcher again after each full application restart.

Run the included offline tests from this directory:

    python3 -m unittest discover -s tests -v

No customer credentials are included. This is a private deployment kit, not a public directory submission or a browser extension. Actual customer policy enforcement must pass the acceptance tests before production use.

For repository download, enterprise rollout, and reviewed updates, see [GitHub installation instructions](GITHUB-INSTALL.md).
