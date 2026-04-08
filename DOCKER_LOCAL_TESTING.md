# 🐳 Docker Local Testing Guide

Test the LLM Shield Admin Portal locally with Docker - no complex setup required!

## 🚀 Quick Start

### **Option 1: One-Click Script**
```bash
# Start everything and open admin portal
./test-admin-portal.sh
```

### **Option 2: Manual Steps**
```bash
# 1. Start services
docker-compose -f docker-compose.dev.yml up -d

# 2. Seed test data
curl -X POST "http://localhost:8000/v1/agents/seed-test-data"

# 3. Open admin portal
open http://localhost:8000/tenant
```

## 🎯 What You'll Test

### **Frontend Portals:**
- **Tenant Portal**: `http://localhost:8000/tenant`
- **Enhanced Admin**: `http://localhost:8000/static/enhanced-admin-portal.html`

### **Test Credentials:**
- **API Key**: `sk-test-healthcare`
- **Admin Key**: `admin123` (for admin portal)

### **Real Data Examples:**
- **Healthcare Agents**: Doctor, Nurse with proper tools
- **HIPAA Policies**: SSN redaction, role restrictions  
- **Redis Storage**: Real tenant-specific data

## 🧪 API Testing

### **Test Agents:**
```bash
curl -H "X-API-Key: sk-test-healthcare" \
  http://localhost:8000/v1/agents/registry
```

### **Test Policies:**
```bash
curl -H "X-API-Key: sk-test-healthcare" \
  http://localhost:8000/v1/agents/tools/policies
```

### **Test Data Validation:**
```bash
curl -X POST "http://localhost:8000/v1/data-policies/validate" \
  -H "X-API-Key: sk-test-healthcare" \
  -H "Content-Type: application/json" \
  -d '{
    "data": "Patient: John Doe, SSN: 123-45-6789",
    "tool_name": "patient_lookup",
    "user_role": "nurse"
  }'
```

## 🔧 Services Included

### **Redis Container:**
- **Port**: `6379`
- **Data**: Persistent volume `redis_dev_data`
- **Purpose**: Store tenant agents, policies, API keys

### **LLM Shield Container:**
- **Port**: `8000` 
- **Environment**: Development mode
- **Features**: Direct Redis access, no GPU/models needed

## 📊 Expected Results

### **Agents Registry Response:**
```json
{
  "success": true,
  "agents": {
    "healthcare-doctor": {
      "name": "Healthcare Doctor Assistant",
      "tools": ["patient_lookup", "prescribe_medication", "view_records"],
      "role_permissions": {
        "doctor": ["patient_lookup", "prescribe_medication", "view_records"],
        "nurse": ["patient_lookup"]
      }
    }
  },
  "source": "redis_direct"
}
```

### **Tool Policies Response:**
```json
{
  "success": true,
  "tool_policies": [
    {
      "tool_name": "patient_lookup",
      "role_restrictions": {
        "doctor": "allow",
        "nurse": "redact", 
        "patient": "block"
      },
      "compliance_framework": "hipaa"
    }
  ]
}
```

## 🛑 Stop Services

```bash
# Stop and remove containers
docker-compose -f docker-compose.dev.yml down

# Clean up volumes (optional)
docker-compose -f docker-compose.dev.yml down -v
```

## 🐛 Troubleshooting

### **Port 8000 in use:**
```bash
# Find and kill process using port 8000
lsof -ti:8000 | xargs kill -9

# Or change port in docker-compose.dev.yml
ports:
  - "8001:8000"  # Use port 8001 instead
```

### **Redis connection issues:**
```bash
# Check Redis container
docker logs llm-shield-redis-dev

# Test Redis connection
docker exec llm-shield-redis-dev redis-cli ping
```

### **Missing test data:**
```bash
# Re-seed test data
curl -X POST "http://localhost:8000/v1/agents/seed-test-data"

# Check Redis contents
docker exec llm-shield-redis-dev redis-cli keys "*"
```

## 💡 Development Tips

### **Live Code Changes:**
- Source code is mounted as volume
- Restart container to see changes: `docker-compose -f docker-compose.dev.yml restart llm-shield-dev`

### **View Logs:**
```bash
# All services
docker-compose -f docker-compose.dev.yml logs -f

# Just the app
docker-compose -f docker-compose.dev.yml logs -f llm-shield-dev
```

### **Access Redis CLI:**
```bash
docker exec -it llm-shield-redis-dev redis-cli
```

**Perfect for testing admin portal features before deploying!** 🎯