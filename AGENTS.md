# Installing or using this plugin

If the user gave you this repository to install or use Gemini Subagent, follow
[INSTALL.md](INSTALL.md). It is the agent-facing entrypoint. Installation does
not require changing this repository or running development tests.

# Development

- The plugin lives in `plugins/gemini-subagent`; read its `AGENTS.md` before
  changing the runtime or skills.
- Keep this repository suitable for public distribution. Runtime state,
  account identities, provider credentials, prompts, job results, and private
  behavioral reports must stay outside it.
- Run the mock-provider suite with
  `python3 -W error::ResourceWarning -m unittest discover -s plugins/gemini-subagent/tests -v`.
  These tests must not require a Google login or paid provider calls.
- Keep the plugin version, runtime version, installation examples, and release
  notes consistent. Provider compatibility claims require separate live evidence.
