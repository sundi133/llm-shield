#!/bin/bash

# LLM Shield Admin Portal - Docker Build & Test Script
set -e

echo "🏗️  Building LLM Shield Admin Portal Docker Image"
echo "================================================="

# Check if Redis is running locally
echo "🔍 Checking local Redis..."
if ! redis-cli ping > /dev/null 2>&1; then
    echo "❌ Redis not running locally. Starting Redis with Docker..."
    docker run -d --name redis-admin-test -p 6379:6379 redis:7-alpine redis-server --appendonly yes
    echo "✅ Redis started on port 6379"
    sleep 3
else
    echo "✅ Redis is already running"
fi

# Build the admin portal image
echo ""
echo "🏗️  Building admin portal Docker image..."
docker build -f Dockerfile.admin -t llm-shield-admin .

echo ""
echo "🌱 Seeding test data in Redis..."
# Seed test data directly into Redis
redis-cli << 'EOF'
SET "tenant:test-tenant-001:agents" '{"healthcare-doctor":{"agent_id":"healthcare-doctor","name":"Healthcare Doctor Assistant","description":"AI assistant for doctors with full medical access","tools":["patient_lookup","diagnosis_update","prescribe_medication","view_records"],"role_permissions":{"doctor":["patient_lookup","diagnosis_update","prescribe_medication","view_records"],"nurse":["patient_lookup"],"admin":["patient_lookup"],"patient":[]},"created_at":1775632429,"updated_at":1775632429},"healthcare-nurse":{"agent_id":"healthcare-nurse","name":"Healthcare Nurse Assistant","description":"AI assistant for nurses with limited medical access","tools":["patient_lookup","schedule_appointment","update_vitals","view_basic_records"],"role_permissions":{"nurse":["patient_lookup","schedule_appointment","update_vitals","view_basic_records"],"doctor":["patient_lookup","schedule_appointment"],"admin":["patient_lookup"],"patient":[]},"created_at":1775632479,"updated_at":1775632479}}'

SET "tenant:test-tenant-001:policies" '[{"tool_name":"patient_lookup","data_sanitization":{"redact_ssn":true,"redact_phone":true,"redact_email":false,"redact_medical_ids":true},"role_restrictions":{"doctor":"allow","nurse":"redact","patient":"block"},"compliance_framework":"hipaa"},{"tool_name":"prescribe_medication","data_sanitization":{"redact_dosage_sensitive":true,"redact_patient_notes":true},"role_restrictions":{"doctor":"allow","nurse":"block","patient":"block"},"compliance_framework":"hipaa"}]'

SET "apikey:$(echo -n 'sk-test-healthcare' | sha256sum | cut -d' ' -f1)" "test-tenant-001"

SET "tenant:test-tenant-001" '{"name":"Test Healthcare Organization","plan":"enterprise","description":"Test tenant for healthcare AI agents","industry":"healthcare","compliance_frameworks":["hipaa"],"created_at":"2026-04-08T00:00:00Z"}'

BGSAVE
EOF

echo "✅ Test data seeded"

# Stop any existing admin container
echo ""
echo "🧹 Cleaning up existing containers..."
docker stop llm-shield-admin-test 2>/dev/null || true
docker rm llm-shield-admin-test 2>/dev/null || true

# Run the admin portal
echo ""
echo "🚀 Starting Admin Portal container..."
docker run -d \
  --name llm-shield-admin-test \
  -p 8080:8080 \
  -e REDIS_URL=redis://host.docker.internal:6379 \
  -e SHIELD_ADMIN_KEY=admin123 \
  -e SHIELD_AUTH_ENABLED=true \
  -e ENVIRONMENT=admin_testing \
  llm-shield-admin

# Wait for container to be ready
echo "⏳ Waiting for admin portal to be ready..."
sleep 5

# Health check
while ! curl -f http://localhost:8080/health > /dev/null 2>&1; do
    echo "   Waiting for admin portal..."
    sleep 2
done

echo ""
echo "✅ Admin Portal is ready!"
echo "========================"
echo ""
echo "🌐 Admin Portal URLs:"
echo "   Tenant Portal:  http://localhost:8080/tenant"
echo "   Admin Portal:   http://localhost:8080/admin"
echo "   Health Check:   http://localhost:8080/health"
echo ""
echo "🔑 Test Credentials:"
echo "   API Key: sk-test-healthcare"
echo "   Admin Key: admin123"
echo ""
echo "🧪 Test Commands:"
echo "   # Test agents endpoint"
echo "   curl -H 'X-API-Key: sk-test-healthcare' http://localhost:8080/v1/agents/registry"
echo ""
echo "   # Test policies endpoint"
echo "   curl -H 'X-API-Key: sk-test-healthcare' http://localhost:8080/v1/agents/tools/policies"
echo ""
echo "   # Test tenant info"
echo "   curl -H 'X-API-Key: sk-test-healthcare' http://localhost:8080/v1/tenant/me"
echo ""
echo "📊 Expected Results:"
echo "   - Healthcare agents with proper tools and roles"
echo "   - HIPAA policies with SSN redaction rules"
echo "   - Real tenant data from Redis (not mock)"
echo ""
echo "🛑 To stop:"
echo "   docker stop llm-shield-admin-test"
echo "   docker stop redis-admin-test  # if you started Redis"
echo ""
echo "📋 Container logs:"
echo "   docker logs -f llm-shield-admin-test"
echo ""

# Open browser
if command -v open >/dev/null 2>&1; then
    echo "🖥️  Opening admin portal in browser..."
    sleep 2
    open "http://localhost:8080/tenant"
fi

echo "🎯 Admin Portal Docker testing ready!"