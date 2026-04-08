#!/bin/bash

# LLM Shield - Admin Portal Local Testing Script
set -e

echo "🚀 Starting LLM Shield Admin Portal for Local Testing"
echo "=================================================="

# Start services
echo "📦 Starting Redis and LLM Shield services..."
docker-compose -f docker-compose.dev.yml up -d

# Wait for services to be ready
echo "⏳ Waiting for services to be ready..."
sleep 10

# Health check
echo "🔍 Checking service health..."
while ! curl -f http://localhost:8000/health > /dev/null 2>&1; do
    echo "   Waiting for LLM Shield to be ready..."
    sleep 2
done

echo "✅ Services are ready!"

# Seed test data
echo "🌱 Seeding test data..."
curl -X POST "http://localhost:8000/v1/agents/seed-test-data" \
  -H "Content-Type: application/json" \
  --silent --show-error || echo "❌ Failed to seed data (this might be normal on first run)"

echo ""
echo "🎯 Admin Portal Testing Ready!"
echo "================================"
echo ""
echo "🌐 Frontend URLs:"
echo "   Tenant Portal:  http://localhost:8000/tenant"
echo "   Admin Portal:   http://localhost:8000/static/enhanced-admin-portal.html"
echo ""
echo "🔑 Test API Key: sk-test-healthcare"
echo ""
echo "🧪 Test Commands:"
echo "   # Test agents endpoint"
echo "   curl -H 'X-API-Key: sk-test-healthcare' http://localhost:8000/v1/agents/registry"
echo ""
echo "   # Test policies endpoint"
echo "   curl -H 'X-API-Key: sk-test-healthcare' http://localhost:8000/v1/agents/tools/policies"
echo ""
echo "📊 What you should see:"
echo "   - Healthcare agents: doctor, nurse with proper tools"
echo "   - HIPAA policies: SSN redaction, role restrictions"
echo "   - Real Redis data (not mock)"
echo ""
echo "🛑 To stop: docker-compose -f docker-compose.dev.yml down"
echo ""

# Open browser
if command -v open >/dev/null 2>&1; then
    echo "🖥️  Opening admin portal in browser..."
    sleep 2
    open "http://localhost:8000/tenant"
fi