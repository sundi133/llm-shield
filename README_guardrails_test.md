# Dynamic Guardrails Policy Testing

## Overview
The `guardrails_policy_test.py` script automatically detects your active guardrail policies and generates targeted test cases. It only requires **RUNPOD_TOKEN** and **TENANT_ID** - no API key needed for basic testing.

## Quick Start

### Minimal Setup (Recommended)
```bash
# Set required environment variables
export RUNPOD_TOKEN="your_runpod_token"
export TENANT_ID="your_tenant_id"

# Run all tests
python3 guardrails_policy_test.py
```

### Advanced Setup (Optional)
```bash
# Add API key for detailed tenant configuration
export API_KEY="your_api_key"

# Custom endpoint
export BASE_URL="https://your-endpoint.com"

# Run specific test types
python3 guardrails_policy_test.py --test-type single
python3 guardrails_policy_test.py --test-type multi-turn
python3 guardrails_policy_test.py --test-type all
```

## Features

### ✅ **Dynamic Test Generation**
- Automatically detects active guardrails
- Generates test cases only for enabled policies
- No hardcoded assumptions about your configuration

### ✅ **Smart Requirements**
- **Required**: `RUNPOD_TOKEN`, `TENANT_ID`
- **Optional**: `API_KEY` (only for detailed tenant config)

### ✅ **Comprehensive Testing**
- **Single Turn**: Tests individual prompts against each guardrail
- **Multi-Turn**: Tests conversation scenarios for context drift
- **Dynamic Coverage**: Only tests what's actually enabled

### ✅ **Intelligent Analysis**
- Success rate by guardrail type
- Failed test identification
- Performance recommendations

## Detected Guardrails

The script automatically tests these guardrails if detected:

| Guardrail | Test Coverage |
|-----------|--------------|
| `pii_detection` | SSN, phone, email, credit card, account numbers |
| `topic_restriction` | Off-topic vs allowed topics |
| `safety_check` | Harmful, violent, illegal content |
| `adversarial_detection` | Prompt injection, system probing, jailbreaks |
| `system_prompt_leak` | System prompt extraction attempts |
| `keyword_blocklist` | Blocked keyword detection |
| `length_limit` | Content length validation |

## Sample Output

```
🔍 Discovering active guardrails...
✅ Detected 9 active guardrails:
   - keyword_blocklist
   - length_limit  
   - pii_detection
   - safety_check
   - topic_restriction
   - adversarial_detection
   - system_prompt_leak

🛡️ Testing pii_detection (6 test cases)
🚫 ✅ Social Security Number: My SSN is 123-45-6789...
🚫 ✅ Phone number: Call me at (555) 123-4567...

📊 RESULTS SUMMARY:
Total Tests: 28
✅ Successful Tests: 25  
❌ Failed Tests: 3
📈 Success Rate: 89.3%
```

## Command Line Options

```bash
python3 guardrails_policy_test.py [OPTIONS]

Options:
  --base-url URL        API endpoint (default: from BASE_URL env var)
  --auth-token TOKEN    Auth token (default: from RUNPOD_TOKEN env var)  
  --tenant-id ID        Tenant ID (default: from TENANT_ID env var)
  --api-key KEY         API key (optional, from API_KEY env var)
  --test-type TYPE      single|multi-turn|all (default: all)
  --output-json FILE    Save results to JSON file
  --quiet, -q           Suppress verbose output
```

## Integration Examples

### CI/CD Pipeline
```bash
#!/bin/bash
# Guardrail validation in CI

export RUNPOD_TOKEN="${RUNPOD_TOKEN}"
export TENANT_ID="${TENANT_ID}"

python3 guardrails_policy_test.py --quiet --output-json test_results.json

# Check exit code
if [ $? -eq 0 ]; then
    echo "✅ Guardrail tests passed"
else
    echo "❌ Guardrail tests failed"
    exit 1
fi
```

### Development Validation
```bash
# Quick check during development
python3 guardrails_policy_test.py --test-type single --quiet
```

### Comprehensive Audit
```bash
# Full analysis with detailed reporting
python3 guardrails_policy_test.py --test-type all --output-json audit_$(date +%Y%m%d).json
```

## Benefits

### 🎯 **Zero Configuration**
- No hardcoded test cases
- Works with any guardrail configuration
- Automatic policy discovery

### ⚡ **Fast & Focused**  
- Only tests enabled guardrails
- Skips irrelevant test categories
- Optimized for your specific setup

### 🔒 **Secure**
- Minimal credential requirements
- Environment variable based config
- No sensitive data in code

### 📊 **Actionable Insights**
- Clear pass/fail metrics
- Performance recommendations  
- Detailed failure analysis

Start testing your guardrails in seconds, not hours!