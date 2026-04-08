# 🐳 Admin Portal Docker Testing Guide

Build and test the LLM Shield Admin Portal using the dedicated `Dockerfile.admin` - lightweight, no GPU required!

## 🚀 Quick Start

### **Option 1: One-Click Script**
```bash
# Build image, start Redis, seed data, and launch admin portal
./test-admin-docker.sh
```

### **Option 2: Manual Steps**
```bash
# 1. Start Redis (if not running)
docker run -d --name redis-admin -p 6379:6379 redis:7-alpine

# 2. Build admin portal image
docker build -f Dockerfile.admin -t llm-shield-admin .

# 3. Run admin portal
docker run -d \
  --name llm-shield-admin-test \
  -p 8080:8080 \
  -e REDIS_URL=redis://host.docker.internal:6379 \
  -e SHIELD_ADMIN_KEY=admin123 \
  llm-shield-admin

# 4. Seed test data
curl -X POST "http://localhost:8080/v1/agents/seed-test-data"

# 5. Open admin portal
open http://localhost:8080/tenant
```

## 🎯 What's Included

### **Dockerfile.admin Features:**
- ✅ **Lightweight**: No GPU, models, or llama.cpp
- ✅ **Admin Focus**: Only admin/tenant portal functionality  
- ✅ **Redis Direct**: Connects to same Redis as production
- ✅ **Port 8080**: Dedicated admin portal port
- ✅ **Minimal Dependencies**: Only essential packages

### **admin_app.py Features:**
- ✅ **Tenant Portal**: `/tenant` - Full tenant management UI
- ✅ **Admin Portal**: `/admin` - Administrative interface
- ✅ **Agent APIs**: `/v1/agents/*` - Direct Redis agent access
- ✅ **Tenant APIs**: `/v1/tenant/*` - Tenant self-service
- ✅ **Health Check**: `/health` - Container health monitoring

## 🌐 Access Points

### **Frontend Portals:**
- **Tenant Portal**: `http://localhost:8080/tenant`
- **Admin Portal**: `http://localhost:8080/admin`
- **API Docs**: `http://localhost:8080/docs`

### **Test Credentials:**
- **Tenant API Key**: `sk-test-healthcare`  
- **Admin Key**: `admin123`
- **Tenant ID**: `test-tenant-001`

## 🧪 API Testing

### **Test Agent Registry:**
```bash
curl -H "X-API-Key: sk-test-healthcare" \
  http://localhost:8080/v1/agents/registry
```

**Expected Response:**
```json
{
  "success": true,
  "agents": {
    "healthcare-doctor": {
      "name": "Healthcare Doctor Assistant",
      "tools": ["patient_lookup", "diagnosis_update", "prescribe_medication"],
      "role_permissions": {
        "doctor": ["patient_lookup", "diagnosis_update", "prescribe_medication"],
        "nurse": ["patient_lookup"]
      }
    }
  },
  "source": "redis_direct"
}
```

### **Test Tool Policies:**
```bash
curl -H "X-API-Key: sk-test-healthcare" \
  http://localhost:8080/v1/agents/tools/policies
```

**Expected Response:**
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
  ],
  "source": "redis_direct"
}
```

### **Test Tenant Info:**
```bash
curl -H "X-API-Key: sk-test-healthcare" \
  http://localhost:8080/v1/tenant/me
```

## 🔧 Advanced Configuration

### **Environment Variables:**
```bash
# Redis Configuration
REDIS_URL=redis://host.docker.internal:6379

# Admin Authentication  
SHIELD_ADMIN_KEY=admin123
SHIELD_AUTH_ENABLED=true

# Application Settings
PORT=8080
ENVIRONMENT=admin_testing
PYTHONPATH=/app
```

### **Custom Redis Connection:**
```bash
# For external Redis (Upstash, etc.)
docker run -d \
  --name llm-shield-admin-test \
  -p 8080:8080 \
  -e UPSTASH_REDIS_REST_URL=https://your-redis.upstash.io \
  -e UPSTASH_REDIS_REST_TOKEN=your-token \
  -e SHIELD_ADMIN_KEY=admin123 \
  llm-shield-admin
```

### **Production-Like Testing:**
```bash
# Connect to same Redis as production
docker run -d \
  --name llm-shield-admin-prod-test \
  -p 8080:8080 \
  -e REDIS_URL=redis://your-production-redis:6379 \
  -e SHIELD_ADMIN_KEY=your-production-admin-key \
  llm-shield-admin
```

## 📊 Monitoring & Debugging

### **View Container Logs:**
```bash
# Live logs
docker logs -f llm-shield-admin-test

# Recent logs
docker logs --tail 50 llm-shield-admin-test
```

### **Container Health:**
```bash
# Check health endpoint
curl http://localhost:8080/health

# Container inspect
docker inspect llm-shield-admin-test
```

### **Redis Data Verification:**
```bash
# Connect to Redis CLI
redis-cli

# Check tenant data
redis-cli GET "tenant:test-tenant-001:agents"
redis-cli GET "tenant:test-tenant-001:policies"
```

## 🛑 Cleanup

### **Stop Services:**
```bash
# Stop admin portal
docker stop llm-shield-admin-test
docker rm llm-shield-admin-test

# Stop Redis (if started by script)
docker stop redis-admin-test
docker rm redis-admin-test
```

### **Remove Images:**
```bash
# Remove admin image
docker rmi llm-shield-admin

# Remove Redis image
docker rmi redis:7-alpine
```

## 🐛 Troubleshooting

### **Port 8080 in use:**
```bash
# Find process using port 8080
lsof -ti:8080 | xargs kill -9

# Or use different port
docker run -p 8081:8080 ... llm-shield-admin
```

### **Redis connection issues:**
```bash
# Test Redis connectivity
redis-cli ping

# Check Docker network
docker network inspect bridge

# Use localhost instead of host.docker.internal (Linux)
-e REDIS_URL=redis://localhost:6379
```

### **Container won't start:**
```bash
# Check logs
docker logs llm-shield-admin-test

# Run interactively for debugging
docker run -it --rm llm-shield-admin bash
```

## 💡 Key Differences from Full Docker

| Feature | Full Docker | Admin Docker |
|---------|-------------|--------------|
| **GPU Support** | ✅ CUDA | ❌ CPU only |
| **Models** | ✅ Qwen3.5 | ❌ None |
| **Port** | 80/8000 | 8080 |
| **Size** | ~8GB | ~200MB |
| **Boot Time** | 2-3 mins | 10 secs |
| **Memory** | 4GB+ | 512MB |
| **Purpose** | Production | Admin UI |

## 🎯 Perfect For:

- ✅ **Admin Portal Testing** - Full UI functionality
- ✅ **Tenant Management** - Create, edit, delete tenants  
- ✅ **Agent Configuration** - Test agent/policy setup
- ✅ **API Development** - Test admin endpoints
- ✅ **Quick Demos** - Show admin features to stakeholders
- ✅ **CI/CD Testing** - Automated admin portal tests

**Lightweight admin portal ready for testing!** 🚀✨