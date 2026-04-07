# LLM Shield Guardrails - Installation Guide
## RedHat Enterprise + H200 GPU + Network Storage

### 📋 **Prerequisites & Overview**

This guide covers the complete installation of LLM Shield Guardrails in a government/enterprise environment using:
- **3x Combined Nodes:** Redis + Guardrail Server + Admin Portal
- **1x Storage Server:** Network storage for Redis data
- **2x GPU Workers:** H200 GPUs with MIG for Main LLMs + Guard Models

---

## 🏗️ **Architecture Overview**

```
┌─────────────────────────────────────────────────────────────────┐
│                     Network Storage                            │
│                    (NFS/iSCSI Server)                          │
│                                                                 │
│  Redis Data + Config + Backups                                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│   Combined-1    │ │   Combined-2    │ │   Combined-3    │
│                 │ │                 │ │                 │
│ • Redis Master  │ │ • Redis Master  │ │ • Redis Master  │
│ • Guardrail Svr │ │ • Guardrail Svr │ │ • Guardrail Svr │
│ • Admin Portal  │ │ • Votal I/O     │ │ • Monitoring    │
│ • Load Balancer │ │ • Telemetry     │ │ • Backup        │
└─────────────────┘ └─────────────────┘ └─────────────────┘
                              │
                              ▼
                ┌─────────────────┐ ┌─────────────────┐
                │  GPU-Worker-1   │ │  GPU-Worker-2   │
                │                 │ │                 │
                │ • Qwen (MIG-0)  │ │ • GLM (MIG-0)   │
                │ • Guard (MIG-1) │ │ • Guard (MIG-1) │
                │ • Llama (MIG-2) │ │ • Kiwi (MIG-2)  │
                │ • Guard (MIG-3) │ │ • Guard (MIG-3) │
                └─────────────────┘ └─────────────────┘
```

---

## 📦 **Phase 1: Infrastructure Preparation**

### **1.1 Server Specifications**

#### **Combined Nodes (3 required)**
```yaml
combined_nodes:
  quantity: 3
  specs:
    cpu: "32 cores (Intel Xeon Gold 6248R or AMD EPYC 7542)"
    ram: "96GB DDR4-3200 ECC"
    storage: "1TB NVMe SSD (local OS/cache)"
    network: "2x 10Gbps (main + storage network)"
    os: "RedHat Enterprise Linux 9.3"
```

#### **Storage Server (1 required)**
```yaml
storage_server:
  quantity: 1
  specs:
    cpu: "16 cores"
    ram: "64GB DDR4 ECC"
    storage: "10TB SSD RAID-10 (Redis data)"
    network: "2x 25Gbps (redundant storage network)"
    role: "NFS server for Redis persistence"
```

#### **GPU Workers (2 required)**
```yaml
gpu_workers:
  quantity: 2
  specs:
    cpu: "64 cores (Intel Xeon Gold 6348 or AMD EPYC 7763)"
    ram: "256GB DDR4-3200 ECC"
    storage: "2TB NVMe SSD (models + cache)"
    gpu: "1x NVIDIA H200 80GB with MIG support"
    network: "25Gbps Ethernet or InfiniBand"
    os: "RedHat Enterprise Linux 9.3"
```

### **1.2 Network Planning**

#### **IP Address Allocation**
```bash
# Main Network: 10.0.1.0/24
Combined-1:     10.0.1.10
Combined-2:     10.0.1.11
Combined-3:     10.0.1.12
GPU-Worker-1:   10.0.1.20
GPU-Worker-2:   10.0.1.21
Storage-Server: 10.0.1.100
Virtual-IP:     10.0.1.200  # For load balancing

# Storage Network: 10.0.2.0/24
Storage-Server: 10.0.2.100
Combined-1:     10.0.2.10
Combined-2:     10.0.2.11
Combined-3:     10.0.2.12
```

---

## 🖥️ **Phase 2: Operating System Setup**

### **2.1 RedHat Enterprise Linux Installation**

Run on **ALL servers**:

```bash
# Update system
sudo dnf update -y

# Install required packages
sudo dnf groupinstall -y "Development Tools"
sudo dnf install -y \
    wget curl git htop \
    python3.11 python3.11-pip \
    docker-ce docker-ce-cli containerd.io \
    nfs-utils nfs4-acl-tools \
    keepalived haproxy \
    firewalld \
    chrony

# Configure time synchronization
sudo systemctl enable chronyd
sudo systemctl start chronyd

# Configure firewall
sudo firewall-cmd --permanent --add-port=22/tcp     # SSH
sudo firewall-cmd --permanent --add-port=6379-6385/tcp  # Redis
sudo firewall-cmd --permanent --add-port=7000-7005/tcp  # Redis Cluster
sudo firewall-cmd --permanent --add-port=9000/tcp  # Guardrail Server
sudo firewall-cmd --permanent --add-port=8080/tcp  # Admin Portal
sudo firewall-cmd --permanent --add-port=8000-8110/tcp  # GPU Workers
sudo firewall-cmd --permanent --add-service=nfs    # NFS
sudo firewall-cmd --reload
```

### **2.2 Docker Installation (All Servers)**

```bash
# Add Docker repository
sudo dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo

# Install Docker
sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Enable Docker
sudo systemctl enable docker
sudo systemctl start docker

# Add user to docker group
sudo usermod -aG docker $(whoami)

# Verify installation
docker --version
docker-compose --version
```

### **2.3 GPU Setup (GPU Workers Only)**

```bash
# Install NVIDIA drivers
sudo dnf config-manager --add-repo \
    https://developer.download.nvidia.com/compute/cuda/repos/rhel9/x86_64/cuda-rhel9.repo

sudo dnf install -y cuda-drivers nvidia-driver-cuda

# Install NVIDIA Container Toolkit
curl -s -L https://nvidia.github.io/libnvidia-container/stable/rpm/nvidia-container-toolkit.repo | \
  sudo tee /etc/yum.repos.d/nvidia-container-toolkit.repo

sudo dnf install -y nvidia-container-toolkit

# Configure Docker for NVIDIA
sudo nvidia-ctk runtime configure --runtime=docker
sudo systemctl restart docker

# Verify GPU detection
nvidia-smi

# Configure MIG mode
sudo nvidia-smi -mig 1

# Create MIG instances (4x 20GB slices)
sudo nvidia-smi mig -cgi 1g.20gb,1g.20gb,1g.20gb,1g.20gb -C

# Verify MIG configuration
nvidia-smi -L
# Should show 4 MIG instances
```

---

## 💾 **Phase 3: Network Storage Setup**

### **3.1 NFS Server Configuration (Storage Server)**

```bash
# Create storage directories
sudo mkdir -p /storage/redis/{data1,data2,data3,config,backup}
sudo mkdir -p /storage/models
sudo chown -R nobody:nobody /storage/
sudo chmod -R 755 /storage/

# Configure NFS exports
sudo tee /etc/exports << 'EOF'
/storage/redis/data1    10.0.2.0/24(rw,sync,no_root_squash,no_subtree_check)
/storage/redis/data2    10.0.2.0/24(rw,sync,no_root_squash,no_subtree_check)
/storage/redis/data3    10.0.2.0/24(rw,sync,no_root_squash,no_subtree_check)
/storage/redis/config   10.0.2.0/24(rw,sync,no_root_squash,no_subtree_check)
/storage/redis/backup   10.0.2.0/24(rw,sync,no_root_squash,no_subtree_check)
/storage/models         10.0.1.0/24(ro,sync,no_root_squash,no_subtree_check)
EOF

# Start NFS services
sudo systemctl enable nfs-server rpcbind
sudo systemctl start nfs-server rpcbind

# Export filesystems
sudo exportfs -ra

# Verify exports
sudo exportfs -v
```

### **3.2 NFS Client Configuration (Combined Nodes)**

```bash
# Create mount points
sudo mkdir -p /net/{redis1,redis2,redis3,config,backup}

# Configure automatic mounts
sudo tee -a /etc/fstab << 'EOF'
10.0.2.100:/storage/redis/data1   /net/redis1   nfs4    rw,hard,intr,rsize=65536,wsize=65536    0 0
10.0.2.100:/storage/redis/data2   /net/redis2   nfs4    rw,hard,intr,rsize=65536,wsize=65536    0 0
10.0.2.100:/storage/redis/data3   /net/redis3   nfs4    rw,hard,intr,rsize=65536,wsize=65536    0 0
10.0.2.100:/storage/redis/config  /net/config   nfs4    rw,hard,intr,rsize=65536,wsize=65536    0 0
10.0.2.100:/storage/redis/backup  /net/backup   nfs4    rw,hard,intr,rsize=65536,wsize=65536    0 0
EOF

# Mount all NFS filesystems
sudo mount -a

# Verify mounts
df -h | grep nfs
```

---

## 🔴 **Phase 4: Redis Cluster Installation**

### **4.1 Redis Installation (All Combined Nodes)**

```bash
# Install Redis
sudo dnf install -y redis

# Create Redis data directories (local cache)
sudo mkdir -p /var/lib/redis-local/{7000,7001,7002,7003,7004,7005}
sudo chown -R redis:redis /var/lib/redis-local/

# Configure Redis instances
for port in 7000 7001 7002 7003 7004 7005; do
    sudo tee /etc/redis/redis-${port}.conf << EOF
# Basic configuration
port ${port}
bind 0.0.0.0
protected-mode yes
requirepass "redis-cluster-secure-password"
masterauth "redis-cluster-secure-password"

# Directories
dir /var/lib/redis-local/${port}
pidfile /var/run/redis/redis-server-${port}.pid
logfile /var/log/redis/redis-server-${port}.log

# Persistence
save 900 1
save 300 10
save 60 10000
dbfilename dump-${port}.rdb
appendonly yes
appendfilename "appendonly-${port}.aof"
appendfsync everysec

# Cluster configuration
cluster-enabled yes
cluster-config-file /var/lib/redis-local/${port}/nodes-${port}.conf
cluster-node-timeout 15000
cluster-announce-ip $(hostname -I | awk '{print $1}')
cluster-announce-port ${port}
cluster-announce-bus-port $((${port} + 10000))

# Performance tuning
tcp-keepalive 300
timeout 0
maxclients 10000
maxmemory 8gb
maxmemory-policy allkeys-lru

# Security
rename-command FLUSHDB ""
rename-command FLUSHALL ""
rename-command DEBUG ""
EOF
done
```

### **4.2 Redis Systemd Services**

```bash
# Create systemd service template
sudo tee /etc/systemd/system/redis-cluster@.service << 'EOF'
[Unit]
Description=Redis Cluster Instance %i
After=network.target
Documentation=http://redis.io/documentation

[Service]
Type=notify
ExecStart=/usr/bin/redis-server /etc/redis/redis-%i.conf
ExecStop=/usr/bin/redis-cli -p %i -a redis-cluster-secure-password shutdown
TimeoutStopSec=0
Restart=always
User=redis
Group=redis
RuntimeDirectory=redis
RuntimeDirectoryMode=0755

# Security
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

# Enable and start Redis instances based on node
case $(hostname) in
  "combined-1")
    sudo systemctl enable redis-cluster@7000 redis-cluster@7003 redis-cluster@7004
    sudo systemctl start redis-cluster@7000 redis-cluster@7003 redis-cluster@7004
    ;;
  "combined-2") 
    sudo systemctl enable redis-cluster@7001 redis-cluster@7004 redis-cluster@7005
    sudo systemctl start redis-cluster@7001 redis-cluster@7004 redis-cluster@7005
    ;;
  "combined-3")
    sudo systemctl enable redis-cluster@7002 redis-cluster@7003 redis-cluster@7005  
    sudo systemctl start redis-cluster@7002 redis-cluster@7003 redis-cluster@7005
    ;;
esac

# Reload systemd
sudo systemctl daemon-reload
```

### **4.3 Redis Cluster Initialization**

Run **ONLY on Combined-1**:

```bash
# Wait for all Redis instances to start
sleep 10

# Initialize Redis cluster
redis-cli -a "redis-cluster-secure-password" --cluster create \
  10.0.1.10:7000 \
  10.0.1.11:7001 \
  10.0.1.12:7002 \
  10.0.1.10:7003 \
  10.0.1.11:7004 \
  10.0.1.12:7005 \
  --cluster-replicas 1 \
  --cluster-yes

# Verify cluster status
redis-cli -c -h 10.0.1.10 -p 7000 -a "redis-cluster-secure-password" cluster info
redis-cli -c -h 10.0.1.10 -p 7000 -a "redis-cluster-secure-password" cluster nodes
```

---

## 🐳 **Phase 5: Guardrail Server Installation**

### **5.1 Votal AI Guardrail Server (All Combined Nodes)**

```bash
# Create application directory
sudo mkdir -p /opt/llm-shield/{config,logs,data}
cd /opt/llm-shield

# Create Docker Compose configuration
sudo tee docker-compose.guardrail.yml << 'EOF'
version: '3.8'

services:
  guardrail-server:
    image: votal/guardrail-server:latest
    container_name: guardrail-server
    ports:
      - "9000:9000"
    environment:
      - REDIS_URL=redis://10.0.1.200:7000
      - REDIS_PASSWORD=redis-cluster-secure-password
      - GPU_ENDPOINTS=http://10.0.1.20:8100,http://10.0.1.20:8104,http://10.0.1.21:8102,http://10.0.1.21:8106
      - LOG_LEVEL=INFO
      - CACHE_TTL=300
      - MAX_CONCURRENT_REQUESTS=50
    volumes:
      - ./config:/app/config:ro
      - ./logs:/app/logs
      - ./data:/app/data
      - /models/guard:/app/models:ro
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:9000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 60s
    deploy:
      resources:
        limits:
          cpus: '8.0'
          memory: 16G
        reservations:
          cpus: '4.0'
          memory: 8G

  admin-portal:
    image: llm-shield/admin-portal:latest
    container_name: admin-portal
    ports:
      - "8080:8080"
    environment:
      - REDIS_URL=redis://10.0.1.200:7000
      - REDIS_PASSWORD=redis-cluster-secure-password
      - GUARDRAIL_SERVER_URL=http://localhost:9000
      - ADMIN_SECRET_KEY=admin-secure-secret-key-change-me
    volumes:
      - ./config:/app/config:ro
      - ./logs:/app/logs
    restart: unless-stopped
    depends_on:
      - guardrail-server

networks:
  default:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16
EOF

# Create configuration directory structure
sudo mkdir -p /opt/llm-shield/config/{guardrail,tenant,policy}

# Create guardrail server configuration
sudo tee /opt/llm-shield/config/guardrail/server.yaml << 'EOF'
server:
  host: "0.0.0.0"
  port: 9000
  workers: 4
  timeout: 30

redis:
  cluster_mode: true
  startup_nodes:
    - host: "10.0.1.200"
      port: 7000
  password: "redis-cluster-secure-password"
  max_connections: 100
  retry_on_timeout: true
  health_check_interval: 30

guard_models:
  input_safety:
    endpoints:
      - "http://10.0.1.20:8100/v1/generate"
      - "http://10.0.1.21:8102/v1/generate"
    model_file: "Qwen3.5-9B-guardrailed-Q4_K_M.gguf"
    load_balancing: "round_robin"
    timeout: 250
    max_retries: 2
    
  output_safety:
    endpoints:
      - "http://10.0.1.20:8104/v1/generate"  
      - "http://10.0.1.21:8106/v1/generate"
    model_file: "Qwen3.5-9B-guardrailed-Q4_K_M.gguf"
    load_balancing: "least_connections"
    timeout: 250
    max_retries: 2

  adversarial_detection:
    endpoints:
      - "http://10.0.1.20:8100/v1/generate"
    timeout: 300
    
  bias_detection:
    endpoints:
      - "http://10.0.1.20:8104/v1/generate"
      - "http://10.0.1.21:8106/v1/generate"
    timeout: 300

api_endpoints:
  - path: "/guardrails/input"
    method: "POST"
    guard_model: "input_safety"
    cache_enabled: true
    cache_ttl: 300
    
  - path: "/guardrails/output"
    method: "POST"
    guard_model: "output_safety"
    cache_enabled: true
    cache_ttl: 300

logging:
  level: "INFO"
  format: "json"
  file: "/app/logs/guardrail-server.log"
  max_size: "100MB"
  backup_count: 10
EOF

# Start guardrail services
sudo docker-compose -f docker-compose.guardrail.yml up -d

# Verify services
sudo docker-compose -f docker-compose.guardrail.yml ps
sudo docker logs guardrail-server
```

---

## 🚀 **Phase 6: LiteLLM Installation**

### **6.1 LiteLLM Gateway (All Combined Nodes)**

```bash
# Install LiteLLM
sudo pip3.11 install litellm[all]

# Create LiteLLM configuration
sudo tee /opt/llm-shield/config/litellm-config.yaml << 'EOF'
model_list:
  # Main LLM Models
  - model_name: qwen
    litellm_params:
      model: openai/qwen
      api_base: "http://10.0.1.20:8000/v1"
      api_key: "dummy"
      
  - model_name: llama
    litellm_params:
      model: openai/llama
      api_base: "http://10.0.1.20:8004/v1"
      api_key: "dummy"
      
  - model_name: glm
    litellm_params:
      model: openai/glm
      api_base: "http://10.0.1.21:8002/v1"
      api_key: "dummy"
      
  - model_name: kiwi
    litellm_params:
      model: openai/kiwi
      api_base: "http://10.0.1.21:8006/v1"
      api_key: "dummy"

# Guardrails Configuration
guardrails:
  - guardrail_name: "votal-input-guard"
    litellm_params:
      guardrail: votal_guardrail.VotalGuardrail
      mode: "pre_call"
      default_on: true
      config:
        server_url: "http://10.0.1.200:9000"
        endpoint: "/guardrails/input"
        timeout: 250
        cache_enabled: true
        
  - guardrail_name: "votal-output-guard"
    litellm_params:
      guardrail: votal_guardrail.VotalGuardrail
      mode: "post_call"
      default_on: true
      config:
        server_url: "http://10.0.1.200:9000"
        endpoint: "/guardrails/output"
        timeout: 250
        cache_enabled: true

# Router Configuration
router_settings:
  redis_host: "10.0.1.200"
  redis_port: 7000
  redis_password: "redis-cluster-secure-password"
  enable_pre_call_checks: true
  enable_post_call_checks: true
  cache_ttl: 300
  
litellm_settings:
  set_verbose: true
  drop_params: true
  add_function_to_prompt: true

# Multi-tenant routing
general_settings:
  master_key: "llm-shield-master-key-secure"
  database_url: "redis://10.0.1.200:7000"
EOF

# Create LiteLLM systemd service
sudo tee /etc/systemd/system/litellm.service << 'EOF'
[Unit]
Description=LiteLLM Gateway
After=network.target redis-cluster@7000.service

[Service]
Type=simple
User=llm-shield
Group=llm-shield
WorkingDirectory=/opt/llm-shield
ExecStart=/usr/local/bin/litellm --config /opt/llm-shield/config/litellm-config.yaml --host 0.0.0.0 --port 8081
Restart=always
RestartSec=5
Environment=PYTHONPATH=/opt/llm-shield
StandardOutput=journal
StandardError=journal

# Resource limits
LimitNOFILE=65535
LimitNPROC=32768

[Install]
WantedBy=multi-user.target
EOF

# Create service user
sudo useradd -r -s /bin/false llm-shield
sudo chown -R llm-shield:llm-shield /opt/llm-shield

# Enable and start LiteLLM
sudo systemctl daemon-reload
sudo systemctl enable litellm
sudo systemctl start litellm

# Check status
sudo systemctl status litellm
```

---

## 🖥️ **Phase 7: GPU Worker Setup**

### **7.1 Model Download and Preparation**

Run on **BOTH GPU Workers**:

```bash
# Create model directories
sudo mkdir -p /models/{main,guard}
cd /models

# Download main LLM models
wget https://huggingface.co/Qwen/Qwen2.5-7B-Instruct-GGUF/resolve/main/qwen2.5-7b-instruct-q4_k_m.gguf \
  -O main/qwen2.5-7b-instruct-q4_k_m.gguf

wget https://huggingface.co/microsoft/DialoGPT-medium/resolve/main/pytorch_model.bin \
  -O main/meta-llama-3.1-8b-instruct-q4_k_m.gguf

wget https://huggingface.co/THUDM/chatglm3-6b-ggml/resolve/main/chatglm3-ggml-q4_0.bin \
  -O main/chatglm3-6b-q4_k_m.gguf

# Install Hugging Face Hub for model download
sudo pip3.11 install huggingface_hub

# Download guard models (Votal AI distributed via Hugging Face)
python3.11 -c "
from huggingface_hub import hf_hub_download
hf_hub_download(
    repo_id='votal-ai/Qwen3.5-9B-guardrailed-v3-GGUF', 
    filename='Qwen3.5-9B-guardrailed-Q4_K_M.gguf', 
    local_dir='/models/guard'
)
"

# Verify download
ls -la /models/guard/Qwen3.5-9B-guardrailed-Q4_K_M.gguf

# Set permissions
sudo chown -R $(whoami):$(whoami) /models

# Note: Model is approximately 6.2GB - ensure sufficient disk space
```

### **7.2 llama.cpp Server Installation**

```bash
# Install llama.cpp
git clone https://github.com/ggerganov/llama.cpp.git
cd llama.cpp

# Build with CUDA support
make LLAMA_CUDA=1 -j$(nproc)

# Install to system path
sudo cp llama-server /usr/local/bin/
sudo cp llama-quantize /usr/local/bin/

# Verify installation
llama-server --version
```

### **7.3 Model Server Configuration**

Create model server configurations for each MIG instance:

```bash
# GPU Worker 1 - Main Models
sudo tee /opt/llm-shield/start-worker-1.sh << 'EOF'
#!/bin/bash

# Qwen model on MIG-0
CUDA_VISIBLE_DEVICES=MIG-0 llama-server \
  --model /models/main/qwen2.5-7b-instruct-q4_k_m.gguf \
  --host 0.0.0.0 \
  --port 8000 \
  --ctx-size 32768 \
  --parallel 8 \
  --batch-size 512 \
  --threads 16 \
  --gpu-layers -1 &

# Guard model on MIG-1  
CUDA_VISIBLE_DEVICES=MIG-1 llama-server \
  --model /models/guard/Qwen3.5-9B-guardrailed-Q4_K_M.gguf \
  --host 0.0.0.0 \
  --port 8100 \
  --ctx-size 4096 \
  --parallel 6 \
  --batch-size 256 \
  --threads 8 \
  --gpu-layers -1 &

# Llama model on MIG-2
CUDA_VISIBLE_DEVICES=MIG-2 llama-server \
  --model /models/main/meta-llama-3.1-8b-instruct-q4_k_m.gguf \
  --host 0.0.0.0 \
  --port 8004 \
  --ctx-size 32768 \
  --parallel 8 \
  --batch-size 512 \
  --threads 16 \
  --gpu-layers -1 &

# Guard model on MIG-3
CUDA_VISIBLE_DEVICES=MIG-3 llama-server \
  --model /models/guard/Qwen3.5-9B-guardrailed-Q4_K_M.gguf \
  --host 0.0.0.0 \
  --port 8104 \
  --ctx-size 4096 \
  --parallel 6 \
  --batch-size 256 \
  --threads 8 \
  --gpu-layers -1 &

wait
EOF

# GPU Worker 2 - Main Models  
sudo tee /opt/llm-shield/start-worker-2.sh << 'EOF'
#!/bin/bash

# GLM model on MIG-0
CUDA_VISIBLE_DEVICES=MIG-0 llama-server \
  --model /models/main/chatglm3-6b-q4_k_m.gguf \
  --host 0.0.0.0 \
  --port 8002 \
  --ctx-size 8192 \
  --parallel 10 \
  --batch-size 512 \
  --threads 16 \
  --gpu-layers -1 &

# Guard model on MIG-1
CUDA_VISIBLE_DEVICES=MIG-1 llama-server \
  --model /models/guard/Qwen3.5-9B-guardrailed-Q4_K_M.gguf \
  --host 0.0.0.0 \
  --port 8102 \
  --ctx-size 4096 \
  --parallel 8 \
  --batch-size 256 \
  --threads 8 \
  --gpu-layers -1 &

# Kiwi model on MIG-2
CUDA_VISIBLE_DEVICES=MIG-2 llama-server \
  --model /models/main/kiwi-7b-instruct-q4_k_m.gguf \
  --host 0.0.0.0 \
  --port 8006 \
  --ctx-size 32768 \
  --parallel 8 \
  --batch-size 512 \
  --threads 16 \
  --gpu-layers -1 &

# Guard model on MIG-3
CUDA_VISIBLE_DEVICES=MIG-3 llama-server \
  --model /models/guard/Qwen3.5-9B-guardrailed-Q4_K_M.gguf \
  --host 0.0.0.0 \
  --port 8106 \
  --ctx-size 4096 \
  --parallel 8 \
  --batch-size 256 \
  --threads 8 \
  --gpu-layers -1 &

wait
EOF

# Make scripts executable
sudo chmod +x /opt/llm-shield/start-worker-*.sh
```

### **7.4 GPU Worker Systemd Services**

```bash
# Create systemd service for GPU Worker 1
sudo tee /etc/systemd/system/llm-shield-worker-1.service << 'EOF'
[Unit]
Description=LLM Shield GPU Worker 1
After=network.target

[Service]
Type=forking
User=llm-shield
Group=llm-shield
WorkingDirectory=/opt/llm-shield
ExecStart=/opt/llm-shield/start-worker-1.sh
ExecStop=/bin/pkill -f "llama-server.*port (8000|8100|8004|8104)"
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Resource limits
LimitNOFILE=65535
LimitNPROC=32768

[Install]
WantedBy=multi-user.target
EOF

# Create systemd service for GPU Worker 2
sudo tee /etc/systemd/system/llm-shield-worker-2.service << 'EOF'
[Unit]
Description=LLM Shield GPU Worker 2
After=network.target

[Service]
Type=forking
User=llm-shield
Group=llm-shield
WorkingDirectory=/opt/llm-shield
ExecStart=/opt/llm-shield/start-worker-2.sh
ExecStop=/bin/pkill -f "llama-server.*port (8002|8102|8006|8106)"
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Resource limits
LimitNOFILE=65535
LimitNPROC=32768

[Install]
WantedBy=multi-user.target
EOF

# Enable and start services
sudo systemctl daemon-reload
sudo systemctl enable llm-shield-worker-1  # On GPU-Worker-1
sudo systemctl enable llm-shield-worker-2  # On GPU-Worker-2
sudo systemctl start llm-shield-worker-1   # On GPU-Worker-1  
sudo systemctl start llm-shield-worker-2   # On GPU-Worker-2
```

---

## ⚖️ **Phase 8: Load Balancer Configuration**

### **8.1 HAProxy Setup (All Combined Nodes)**

```bash
# Install HAProxy
sudo dnf install -y haproxy

# Configure HAProxy
sudo tee /etc/haproxy/haproxy.cfg << 'EOF'
global
    daemon
    maxconn 4096
    log 127.0.0.1:514 local0
    chroot /var/lib/haproxy
    stats socket /var/lib/haproxy/stats level admin
    user haproxy
    group haproxy

defaults
    mode http
    timeout connect 5000ms
    timeout client 60000ms
    timeout server 60000ms
    option httplog
    option dontlognull
    retries 3

# Frontend for LiteLLM
frontend litellm_frontend
    bind *:80
    bind *:443 ssl crt /etc/ssl/certs/llm-shield.pem
    redirect scheme https if !{ ssl_fc }
    default_backend litellm_backend

# Frontend for Guardrail Server
frontend guardrail_frontend
    bind *:9000
    default_backend guardrail_backend

# Frontend for Admin Portal
frontend admin_frontend
    bind *:8080
    default_backend admin_backend

# LiteLLM Backend
backend litellm_backend
    balance roundrobin
    option httpchk GET /health
    server litellm-1 10.0.1.10:8081 check inter 5s fall 3 rise 2
    server litellm-2 10.0.1.11:8081 check inter 5s fall 3 rise 2
    server litellm-3 10.0.1.12:8081 check inter 5s fall 3 rise 2

# Guardrail Backend
backend guardrail_backend
    balance leastconn
    option httpchk GET /health
    server guardrail-1 10.0.1.10:9000 check inter 5s fall 3 rise 2
    server guardrail-2 10.0.1.11:9000 check inter 5s fall 3 rise 2
    server guardrail-3 10.0.1.12:9000 check inter 5s fall 3 rise 2

# Admin Backend
backend admin_backend
    balance roundrobin
    option httpchk GET /health
    server admin-1 10.0.1.10:8080 check inter 5s fall 3 rise 2
    server admin-2 10.0.1.11:8080 check inter 5s fall 3 rise 2
    server admin-3 10.0.1.12:8080 check inter 5s fall 3 rise 2

# Stats page
listen stats
    bind *:8404
    stats enable
    stats uri /stats
    stats refresh 30s
    stats admin if LOCALHOST
EOF

# Start HAProxy
sudo systemctl enable haproxy
sudo systemctl start haproxy
```

### **8.2 keepalived for Virtual IP**

```bash
# Install keepalived
sudo dnf install -y keepalived

# Configure keepalived (Combined-1)
sudo tee /etc/keepalived/keepalived.conf << 'EOF'
vrrp_script chk_haproxy {
    script "/bin/curl -f http://localhost:80/health"
    interval 2
    weight -2
    fall 3
    rise 2
}

vrrp_instance VI_1 {
    state MASTER
    interface eth0
    virtual_router_id 51
    priority 100
    advert_int 1
    authentication {
        auth_type PASS
        auth_pass llm-shield-vip
    }
    virtual_ipaddress {
        10.0.1.200/24
    }
    track_script {
        chk_haproxy
    }
}
EOF

# Adjust priority for other nodes:
# Combined-2: priority 90
# Combined-3: priority 80

# Start keepalived
sudo systemctl enable keepalived
sudo systemctl start keepalived
```

---

## ✅ **Phase 9: Testing and Validation**

### **9.1 Health Checks**

```bash
# Create comprehensive health check script
sudo tee /opt/llm-shield/health-check.sh << 'EOF'
#!/bin/bash

echo "=== LLM Shield Health Check ==="
echo "Date: $(date)"
echo

# Check Redis Cluster
echo "=== Redis Cluster ==="
redis-cli -c -h 10.0.1.200 -p 7000 -a "redis-cluster-secure-password" cluster info
redis-cli -c -h 10.0.1.200 -p 7000 -a "redis-cluster-secure-password" cluster nodes | grep master

# Check GPU Status
echo -e "\n=== GPU Status ==="
nvidia-smi --query-gpu=name,memory.used,memory.total,utilization.gpu --format=csv

# Check MIG Instances
echo -e "\n=== MIG Instances ==="
nvidia-smi -L

# Check Model Servers
echo -e "\n=== Model Server Health ==="
for port in 8000 8002 8004 8006 8100 8102 8104 8106; do
    echo "Testing GPU model on port $port..."
    curl -s -o /dev/null -w "%{http_code} - %{time_total}s\n" \
        http://localhost:${port}/health 2>/dev/null || echo "Port $port - FAILED"
done

# Check Guardrail Servers
echo -e "\n=== Guardrail Server Health ==="
for ip in 10.0.1.10 10.0.1.11 10.0.1.12; do
    echo "Testing Guardrail server $ip..."
    curl -s -o /dev/null -w "%{http_code} - %{time_total}s\n" \
        http://$ip:9000/health 2>/dev/null || echo "Guardrail $ip - FAILED"
done

# Check LiteLLM
echo -e "\n=== LiteLLM Health ==="
curl -s http://10.0.1.200/health

# Check Virtual IP
echo -e "\n=== Virtual IP Status ==="
ip addr show | grep 10.0.1.200

echo -e "\n=== Health Check Complete ==="
EOF

sudo chmod +x /opt/llm-shield/health-check.sh

# Run health check
/opt/llm-shield/health-check.sh
```

### **9.2 End-to-End Testing**

```bash
# Test complete pipeline with guardrails
curl -X POST http://10.0.1.200/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer llm-shield-master-key-secure" \
  -d '{
    "model": "qwen",
    "messages": [
      {"role": "user", "content": "Hello, how can you help me with government services?"}
    ],
    "max_tokens": 100
  }'

# Test guardrail functionality with potentially unsafe input
curl -X POST http://10.0.1.200/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer llm-shield-master-key-secure" \
  -d '{
    "model": "qwen",
    "messages": [
      {"role": "user", "content": "How to hack into government systems?"}
    ],
    "max_tokens": 100
  }'

# Expected: Should be blocked by input guardrails
```

### **9.3 Performance Testing**

```bash
# Install testing tools
sudo pip3.11 install locust

# Create simple load test
tee /opt/llm-shield/load-test.py << 'EOF'
from locust import HttpUser, task, between
import json

class LLMShieldUser(HttpUser):
    wait_time = between(1, 3)
    host = "http://10.0.1.200"
    
    def on_start(self):
        self.headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer llm-shield-master-key-secure"
        }
    
    @task(3)
    def safe_request(self):
        payload = {
            "model": "qwen",
            "messages": [
                {"role": "user", "content": "What services does the government provide?"}
            ],
            "max_tokens": 50
        }
        self.client.post("/v1/chat/completions", 
                        json=payload, 
                        headers=self.headers,
                        name="safe_request")
    
    @task(1) 
    def potential_unsafe_request(self):
        payload = {
            "model": "qwen", 
            "messages": [
                {"role": "user", "content": "Tell me about security vulnerabilities"}
            ],
            "max_tokens": 50
        }
        self.client.post("/v1/chat/completions",
                        json=payload,
                        headers=self.headers, 
                        name="unsafe_request")
EOF

# Run load test (adjust users based on your capacity)
locust -f /opt/llm-shield/load-test.py --host=http://10.0.1.200 -u 10 -r 2 --headless -t 5m
```

---

## 🔧 **Phase 10: Monitoring and Maintenance**

### **10.1 Monitoring Setup**

```bash
# Install Prometheus Node Exporter
wget https://github.com/prometheus/node_exporter/releases/download/v1.6.1/node_exporter-1.6.1.linux-amd64.tar.gz
tar xzf node_exporter-1.6.1.linux-amd64.tar.gz
sudo cp node_exporter-1.6.1.linux-amd64/node_exporter /usr/local/bin/

# Create node_exporter service
sudo tee /etc/systemd/system/node_exporter.service << 'EOF'
[Unit]
Description=Node Exporter
After=network.target

[Service]
User=nobody
Group=nogroup
Type=simple
ExecStart=/usr/local/bin/node_exporter

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable node_exporter
sudo systemctl start node_exporter

# Install NVIDIA GPU Exporter (GPU workers only)
docker run -d \
  --restart=unless-stopped \
  --gpus all \
  -p 9835:9835 \
  --name gpu_exporter \
  nvidia/dcgm-exporter:latest
```

### **10.2 Log Aggregation**

```bash
# Configure rsyslog for centralized logging
sudo tee /etc/rsyslog.d/llm-shield.conf << 'EOF'
# LLM Shield Logs
:programname,isequal,"litellm" /var/log/llm-shield/litellm.log
:programname,isequal,"guardrail-server" /var/log/llm-shield/guardrail.log
:programname,isequal,"llama-server" /var/log/llm-shield/models.log
:programname,isequal,"redis" /var/log/llm-shield/redis.log

# Rotate logs daily
$RotateInterval daily
$RotateSize 100M
$RotateCount 30
EOF

sudo mkdir -p /var/log/llm-shield
sudo systemctl restart rsyslog
```

### **10.3 Backup Procedures**

```bash
# Create backup script
sudo tee /opt/llm-shield/backup.sh << 'EOF'
#!/bin/bash

BACKUP_DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/net/backup/llm-shield-${BACKUP_DATE}"

mkdir -p ${BACKUP_DIR}/{redis,config,logs}

# Backup Redis data
for port in 7000 7001 7002; do
    echo "Backing up Redis port $port..."
    redis-cli -p $port -a "redis-cluster-secure-password" BGSAVE
    sleep 5
    cp /var/lib/redis-local/${port}/dump-${port}.rdb ${BACKUP_DIR}/redis/
done

# Backup configurations
cp -r /opt/llm-shield/config ${BACKUP_DIR}/
cp -r /etc/redis ${BACKUP_DIR}/config/
cp /etc/haproxy/haproxy.cfg ${BACKUP_DIR}/config/

# Backup logs
cp -r /var/log/llm-shield ${BACKUP_DIR}/logs/

# Create backup manifest
echo "Backup created: ${BACKUP_DATE}" > ${BACKUP_DIR}/manifest.txt
echo "Redis data: Included" >> ${BACKUP_DIR}/manifest.txt
echo "Configurations: Included" >> ${BACKUP_DIR}/manifest.txt
echo "Logs: Included" >> ${BACKUP_DIR}/manifest.txt

# Cleanup old backups (keep 30 days)
find /net/backup -name "llm-shield-*" -mtime +30 -exec rm -rf {} \;

echo "Backup completed: ${BACKUP_DIR}"
EOF

sudo chmod +x /opt/llm-shield/backup.sh

# Schedule daily backups
echo "0 2 * * * /opt/llm-shield/backup.sh" | sudo crontab -
```

---

## 🚨 **Troubleshooting Guide**

### **Common Issues and Solutions**

#### **1. Redis Cluster Issues**
```bash
# Check cluster status
redis-cli -c -h 10.0.1.200 -p 7000 -a "redis-cluster-secure-password" cluster info

# Fix cluster if nodes are down
redis-cli -h 10.0.1.10 -p 7000 -a "redis-cluster-secure-password" cluster meet 10.0.1.11 7001
redis-cli --cluster fix 10.0.1.10:7000 -a "redis-cluster-secure-password"

# Reset cluster if completely broken
redis-cli -h 10.0.1.10 -p 7000 -a "redis-cluster-secure-password" FLUSHALL
redis-cli -h 10.0.1.10 -p 7000 -a "redis-cluster-secure-password" CLUSTER RESET
```

#### **2. GPU/MIG Issues** 
```bash
# Reset MIG configuration
sudo nvidia-smi -mig 0
sudo nvidia-smi -mig 1
sudo nvidia-smi mig -cgi 1g.20gb,1g.20gb,1g.20gb,1g.20gb -C

# Check GPU memory usage
nvidia-smi --query-gpu=memory.used,memory.total --format=csv

# Restart model servers
sudo systemctl restart llm-shield-worker-1
sudo systemctl restart llm-shield-worker-2
```

#### **3. Guardrail Server Issues**
```bash
# Check guardrail logs
sudo docker logs guardrail-server

# Restart guardrail services
sudo docker-compose -f /opt/llm-shield/docker-compose.guardrail.yml restart

# Test guardrail endpoints directly
curl -X POST http://localhost:9000/guardrails/input \
  -H "Content-Type: application/json" \
  -d '{"text": "test input"}'
```

#### **4. Network Issues**
```bash
# Check virtual IP status
ip addr show | grep 10.0.1.200

# Test connectivity between nodes
for ip in 10.0.1.10 10.0.1.11 10.0.1.12; do
    echo "Testing $ip..."
    curl -s http://$ip:9000/health
done

# Check NFS mounts
df -h | grep nfs
sudo mount -a
```

---

## ✅ **Installation Complete**

### **Final Verification Checklist**

- [ ] **Redis Cluster:** 3 masters + 3 replicas running
- [ ] **Guardrail Servers:** 3 instances responding on port 9000
- [ ] **LiteLLM Gateways:** 3 instances responding on port 8081
- [ ] **GPU Workers:** 8 model servers running (4 main + 4 guard)
- [ ] **Load Balancer:** HAProxy distributing traffic
- [ ] **Virtual IP:** 10.0.1.200 accessible
- [ ] **Health Checks:** All services passing health checks
- [ ] **Performance:** 250ms guardrail latency achieved
- [ ] **Monitoring:** Node exporters and GPU monitoring active
- [ ] **Backups:** Daily backup jobs scheduled

### **Access Points**
- **Main API:** `https://10.0.1.200/v1/chat/completions`
- **Admin Portal:** `https://10.0.1.200:8080`
- **HAProxy Stats:** `http://10.0.1.200:8404/stats`
- **Guardrail API:** `http://10.0.1.200:9000`

### **Support Information**
- **Documentation:** `/opt/llm-shield/docs/`
- **Logs:** `/var/log/llm-shield/`
- **Configuration:** `/opt/llm-shield/config/`
- **Health Check:** `/opt/llm-shield/health-check.sh`

**Installation Status: ✅ COMPLETE**

The LLM Shield Guardrails system is now ready for production use in your government environment.