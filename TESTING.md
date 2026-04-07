# LLM Shield Testing Guide

Comprehensive testing suite for both basic and agentic guardrail functionality.

## Quick Start

### Prerequisites
```bash
export RUNPOD_TOKEN="your-runpod-token"
export SHIELD_ADMIN_KEY="your-admin-key"
export RUNPOD_HOST="https://your-endpoint.api.runpod.ai"  # optional
```

### Run All Tests
```bash
./run_all_tests.sh
```

### Run Individual Test Suites
```bash
# Basic input/output guardrails only
./test_basic_guardrails.sh

# Agentic tool authorization only  
./test_agentic_guardrails.sh
```

## Test Suites Overview

### 1. Basic Guardrails (`test_basic_guardrails.sh`)

Tests core guardrail functionality without agentic features:

**Input Guardrails:**
- ✅ **Keyword Blocklist** - Block harmful/restricted keywords
- ✅ **Topic Restriction** - Whitelist/blacklist topic enforcement  
- ✅ **Language Detection** - Block non-allowed languages
- ✅ **PII Detection** - Detect SSN, email, phone numbers
- ✅ **Sentiment Analysis** - Flag negative/inappropriate sentiment
- ✅ **Safety Checks** - Block violence, self-harm, illegal content
- ✅ **Adversarial Detection** - Detect prompt injection attempts

**Output Guardrails:**
- ✅ **PII Leakage** - Prevent sensitive data in responses
- ✅ **Tone Enforcement** - Maintain brand voice consistency
- ✅ **Bias Detection** - Flag discriminatory content  
- ✅ **Hallucinated Links** - Detect fake/suspicious URLs
- ✅ **Competitor Mention** - Control competitor references

**Test Coverage:**
- Safe/legitimate content (should pass)
- Malicious/harmful content (should block)
- Edge cases and error handling
- Performance validation
- Multi-guardrail configurations

### 2. Agentic Guardrails (`test_agentic_guardrails.sh`)

Tests advanced agent and tool management features:

**Agent Management:**
- ✅ **Agent Registration** - Register agents with tool access
- ✅ **Role-Based Permissions** - Control tool access by user role
- ✅ **Tool Policy Configuration** - Per-tool validation rules

**Authorization & Validation:**
- ✅ **Pre-Authorization Checks** - Validate tool access before execution
- ✅ **LLM Validation** - AI-powered tool call appropriateness
- ✅ **Data Sanitization** - Role-based output redaction
- ✅ **Policy Enforcement** - Multi-layered access control

**Integration Testing:**
- ✅ **End-to-End Flow** - Complete agent → tool → validation pipeline
- ✅ **Role Scenarios** - Doctor, nurse, patient, admin access patterns
- ✅ **Policy Violations** - Unauthorized access blocking
- ✅ **Data Protection** - HIPAA-style data redaction

## Test Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `RUNPOD_TOKEN` | ✅ | - | Your RunPod API authentication token |
| `SHIELD_ADMIN_KEY` | ✅ | - | LLM Shield admin key for tenant management |
| `RUNPOD_HOST` | ❌ | `https://kk5losqxwr2ui7.api.runpod.ai` | RunPod endpoint URL |
| `TENANT_ID` | ❌ | `basic-test-co` / `agentic-test-co` | Test tenant identifier |
| `TENANT_API_KEY` | ❌ | Auto-generated | Tenant API key for guardrail requests |

### Advanced Usage

**Run specific test types:**
```bash
# Basic tests only
./run_all_tests.sh --basic-only

# Agentic tests only  
./run_all_tests.sh --agentic-only

# Stop on first failure
./run_all_tests.sh --stop-on-failure
```

**Custom tenant configuration:**
```bash
export TENANT_ID="my-custom-tenant"
export TENANT_API_KEY="my-tenant-key"
./test_basic_guardrails.sh
```

## Expected Results

### Successful Test Run

```
╔══════════════════════════════════════════════════╗
║                    FINAL TEST SUMMARY             ║
╚══════════════════════════════════════════════════╝
  Test Suites Run: 2
  Test Suites Passed: 2  
  Test Suites Failed: 0

🎉 ALL TEST SUITES PASSED!

Your LLM Shield deployment is working correctly:
  ✅ Input guardrails (safety, PII, topic, language)
  ✅ Output guardrails (bias, tone, PII leakage, links)  
  ✅ Agent registration and tool policies
  ✅ Role-based authorization and LLM validation
  ✅ Data sanitization and policy enforcement
```

### Test Breakdown

Each test suite reports individual test results:

```
✓ I1  Greeting message → Safe (Expected)
✓ I4  Blocked keyword - bomb → Blocked (Expected)  
✓ O2  PII leak - SSN → Warning (Expected)
✗ I8  Off-topic cooking → Expected block, got Safe=True
```

## Troubleshooting

### Common Issues

**Authentication Errors:**
```bash
# Verify tokens are set correctly
echo $RUNPOD_TOKEN
echo $SHIELD_ADMIN_KEY

# Test basic connectivity
curl -H "Authorization: Bearer $RUNPOD_TOKEN" "$RUNPOD_HOST/health"
```

**Guardrail Configuration Issues:**
- Check if guardrails are enabled in tenant config
- Verify guardrail settings match expected behavior
- Review server logs for configuration errors

**Endpoint Availability:**
```bash
# Test input endpoint
curl -X POST "$RUNPOD_HOST/guardrails/input" \
  -H "Authorization: Bearer $RUNPOD_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"message": "test"}'

# Test output endpoint  
curl -X POST "$RUNPOD_HOST/guardrails/output" \
  -H "Authorization: Bearer $RUNPOD_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"output": "test"}'
```

**Performance Issues:**
- Tests expect responses under 5 seconds
- Check server resources and model loading
- Consider running fewer guardrails simultaneously

### Debug Mode

Add debug output to test scripts:
```bash
# Enable curl verbose output
export CURL_VERBOSE="-v"

# Show full responses
export DEBUG_RESPONSES="true"
```

## Integration Examples

### CI/CD Pipeline

```yaml
# .github/workflows/guardrails-test.yml
name: Guardrails Test
on: [push, pull_request]

jobs:
  test-guardrails:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Test Basic Guardrails
        env:
          RUNPOD_TOKEN: ${{ secrets.RUNPOD_TOKEN }}
          SHIELD_ADMIN_KEY: ${{ secrets.SHIELD_ADMIN_KEY }}
        run: ./test_basic_guardrails.sh
        
      - name: Test Agentic Guardrails  
        env:
          RUNPOD_TOKEN: ${{ secrets.RUNPOD_TOKEN }}
          SHIELD_ADMIN_KEY: ${{ secrets.SHIELD_ADMIN_KEY }}
        run: ./test_agentic_guardrails.sh
```

### Custom Test Scenarios

Create your own test scenarios by modifying the test scripts:

```bash
# Add custom test cases
test_input_guardrail "C1" "Custom scenario" "block" "Your custom test message"

# Test with custom configurations
CUSTOM_CONFIG='{"your-guardrail": {"enabled": true, "threshold": 0.5}}'
test_input_guardrail "C2" "Custom config test" "safe" "Test message" "$CUSTOM_CONFIG"
```

## Performance Benchmarks

### Expected Response Times

| Test Type | Expected Time | Acceptable Threshold |
|-----------|---------------|---------------------|
| Basic Input | < 500ms | < 2s |
| Basic Output | < 800ms | < 3s |
| Agentic Auth | < 200ms | < 1s |
| LLM Validation | < 2s | < 5s |

### Throughput Testing

```bash
# Run concurrent requests (requires GNU parallel)
seq 1 10 | parallel -j 5 'curl -s "$RUNPOD_HOST/guardrails/input" \
  -H "Authorization: Bearer $RUNPOD_TOKEN" \
  -H "X-API-Key: $TENANT_API_KEY" \
  -d "{\"message\": \"test {}\"}"'
```

## Security Validation

The test suites validate critical security controls:

**Data Protection:**
- PII detection and redaction
- Role-based data access
- Unauthorized information blocking

**Access Control:**
- User role validation
- Tool permission enforcement  
- Agent authorization checks

**Content Safety:**
- Harmful content blocking
- Bias and toxicity detection
- Adversarial prompt protection

**Compliance:**
- Audit trail generation
- Policy violation tracking
- Data handling compliance

## Support

- **Documentation**: Check `/docs` endpoint on your deployment
- **API Reference**: Visit `$RUNPOD_HOST/docs` for interactive API docs
- **Test Issues**: Review test output and server logs
- **Custom Scenarios**: Modify test scripts for your specific use cases

Run tests regularly to ensure your guardrails deployment remains secure and functional! 🛡️