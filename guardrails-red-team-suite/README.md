# Red Team Prompt Suite

Automated red-team test suites for evaluating AI chatbot guardrails across **13 industries**. Each suite contains **1,850 adversarial attack prompts** and **250 safe prompts** as executable Bash scripts that hit a guardrails API endpoint and produce a pass/fail report.

## Industries Covered

| # | File | Industry |
|---|------|----------|
| 01 | `01_healthcare.sh` | Healthcare |
| 02 | `02_banking_finance.sh` | Banking & Finance |
| 03 | `03_legal.sh` | Legal |
| 04 | `04_ecommerce_retail.sh` | E-Commerce & Retail |
| 05 | `05_hr_recruitment.sh` | HR & Recruitment |
| 06 | `06_government.sh` | Government & Public Services |
| 07 | `07_real_estate.sh` | Real Estate |
| 08 | `08_education.sh` | Education |
| 09 | `09_telecom.sh` | Telecom & Customer Support |
| 10 | `10_travel_hospitality.sh` | Travel & Hospitality |
| 11 | `11_it_software_saas.sh` | IT, Software & SaaS |
| 12 | `12_insurance.sh` | Insurance |
| 13 | `13_logistics_supply_chain.sh` | Logistics & Supply Chain |

## Attack Taxonomy

Each test file exercises **185 named attack techniques** across 8 categories, with **10 prompt variants per technique**:

| Category | Description |
|----------|-------------|
| Part 1 | Injection methods and delivery vectors |
| Category A | Overt instruction attacks |
| Category B | Cognitive control bypass |
| Category C | Reformulation and evasion |
| Category D | Prompt boundary manipulation |
| Category E | Integrative instruction |
| Category F | Multimodal (textual stand-ins) |
| Category G | Additional evasion |

Prompt variants include direct attacks, base64 obfuscation, few-shot poisoning, persona hijacking, fictional framing, social engineering wrappers, and more.

## Quick Start

### 1. Configure endpoint

Open any `.sh` file and set the two variables at the top:

```bash
BASE_URL="https://your-endpoint/classify"
TOKEN="your-api-token"
```

### 2. Run a test suite

```bash
chmod +x 01_healthcare.sh
./01_healthcare.sh
```

The script will:
- Send each prompt to your API via `curl`
- Compare the response (`action` / `safe` fields) against the expected outcome (`block` or `safe`)
- Print color-coded pass/fail results in the terminal
- Generate an HTML report at the end (e.g. `guardrails_report_healthcare_*.html`)

### 3. Review results

Open the generated HTML report in a browser for a full breakdown including failed tests, payload details, and summary statistics.

## Regenerating Test Files

The test suites are generated from Python source files:

```bash
python generate_red_team_prompts.py
```

### Source Files

| File | Purpose |
|------|---------|
| `generate_red_team_prompts.py` | Main generator — defines the 185-entry attack taxonomy, 13 industry configs (topics, blocklists, roles, secrets, PII, attack scenarios), 250 safe prompt templates, and writes the `.sh` files |
| `industry_pools.py` | Auxiliary data pools (sensitive targets, decoy tasks, scenario hooks) used by the generator for prompt variation |
| `_bash_runner_template.sh` | Bash boilerplate embedded into each generated file — handles API calls, result tracking, color output, and HTML report generation |
| `validate_outputs.py` | Quick validation that generated files have parseable `run_test` lines with valid JSON |

## Guardrail Configuration

Each prompt payload includes a guardrail configuration block specifying:

- **Topic restrictions** — allowed conversation topics for the industry
- **Adversarial prompt detection** — enabled/disabled flag
- **Keyword blocklist** — industry-specific blocked terms
- **Language detection** — expected language constraint

## Requirements

- **Bash** (4.0+)
- **curl**
- **Python 3** (used by the runner for JSON parsing and report generation)

## Repository Structure

```
.
├── 01_healthcare.sh              # Generated test suite
├── 02_banking_finance.sh
├── ...
├── 13_logistics_supply_chain.sh
├── _bash_runner_template.sh      # Bash runner template
├── generate_red_team_prompts.py  # Main generator
├── industry_pools.py             # Industry data pools
├── validate_outputs.py           # Output validator
└── README.md
```
