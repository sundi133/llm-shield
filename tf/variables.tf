# =============================================================================
# Rafay / Cluster
# =============================================================================

variable "rafay_api_key" {
  description = "Rafay API key"
  type        = string
  sensitive   = true
}

variable "rafay_api_secret" {
  description = "Rafay API secret"
  type        = string
  sensitive   = true
}

variable "rafay_project_name" {
  description = "Rafay project name"
  type        = string
  default     = "llm-shield"
}

variable "cluster_name" {
  description = "Name of the Rafay-managed Kubernetes cluster"
  type        = string
}

variable "kubeconfig_path" {
  description = "Path to kubeconfig file for the Rafay cluster"
  type        = string
  default     = "~/.kube/config"
}

variable "kubeconfig_context" {
  description = "Kubeconfig context to use (leave empty for current-context)"
  type        = string
  default     = ""
}

variable "namespace" {
  description = "Kubernetes namespace for all LLM Shield resources"
  type        = string
  default     = "llm-shield"
}

# =============================================================================
# Container images
# =============================================================================

variable "shield_image" {
  description = "Shield app Docker image"
  type        = string
  default     = "docker.io/sundi133/llm-shield:latest"
}

variable "admin_image" {
  description = "Admin portal Docker image"
  type        = string
  default     = "docker.io/sundi133/llm-shield-admin:latest"
}

variable "vllm_image" {
  description = "vLLM server Docker image"
  type        = string
  default     = "vllm/vllm-openai:latest"
}

variable "redis_image" {
  description = "Redis Docker image"
  type        = string
  default     = "redis:7-alpine"
}

# =============================================================================
# Shield App
# =============================================================================

variable "shield_replicas" {
  description = "Initial replica count for Shield app"
  type        = number
  default     = 2
}

variable "shield_min_replicas" {
  description = "HPA minimum replicas for Shield app"
  type        = number
  default     = 2
}

variable "shield_max_replicas" {
  description = "HPA maximum replicas for Shield app"
  type        = number
  default     = 10
}

variable "shield_workers" {
  description = "Number of uvicorn workers per Shield pod"
  type        = number
  default     = 32
}

variable "shield_cpu_request" {
  description = "CPU request for Shield app"
  type        = string
  default     = "1"
}

variable "shield_cpu_limit" {
  description = "CPU limit for Shield app"
  type        = string
  default     = "4"
}

variable "shield_memory_request" {
  description = "Memory request for Shield app"
  type        = string
  default     = "2Gi"
}

variable "shield_memory_limit" {
  description = "Memory limit for Shield app"
  type        = string
  default     = "8Gi"
}

variable "shield_host" {
  description = "Ingress hostname for Shield app (e.g. shield.example.com)"
  type        = string
  default     = ""
}

# =============================================================================
# vLLM
# =============================================================================

variable "vllm_model_name" {
  description = "HuggingFace model to serve with vLLM"
  type        = string
  default     = "votal-ai/vai35-4B-v2"
}

variable "vllm_gpu_count" {
  description = "Number of GPUs for vLLM"
  type        = number
  default     = 1
}

variable "gpu_memory_utilization" {
  description = "vLLM GPU memory utilization (0.0-1.0)"
  type        = string
  default     = "0.85"
}

variable "vllm_max_model_len" {
  description = "Maximum model sequence length"
  type        = string
  default     = "8196"
}

variable "vllm_max_num_seqs" {
  description = "Maximum number of concurrent sequences"
  type        = string
  default     = "48"
}

variable "vllm_cpu_request" {
  description = "CPU request for vLLM"
  type        = string
  default     = "4"
}

variable "vllm_cpu_limit" {
  description = "CPU limit for vLLM"
  type        = string
  default     = "8"
}

variable "vllm_memory_request" {
  description = "Memory request for vLLM"
  type        = string
  default     = "16Gi"
}

variable "vllm_memory_limit" {
  description = "Memory limit for vLLM"
  type        = string
  default     = "32Gi"
}

variable "gpu_node_pool_label" {
  description = "Node label key for GPU node pool (for nodeSelector)"
  type        = string
  default     = "nvidia.com/gpu.present"
}

# =============================================================================
# Admin Portal
# =============================================================================

variable "admin_replicas" {
  description = "Initial replica count for Admin portal"
  type        = number
  default     = 1
}

variable "admin_min_replicas" {
  description = "HPA minimum replicas for Admin portal"
  type        = number
  default     = 1
}

variable "admin_max_replicas" {
  description = "HPA maximum replicas for Admin portal"
  type        = number
  default     = 6
}

variable "admin_host" {
  description = "Ingress hostname for Admin portal (e.g. admin.example.com)"
  type        = string
  default     = ""
}

# =============================================================================
# Redis
# =============================================================================

variable "redis_storage_size" {
  description = "PVC storage size for Redis"
  type        = string
  default     = "10Gi"
}

variable "redis_max_memory" {
  description = "Redis maxmemory setting"
  type        = string
  default     = "8gb"
}

variable "redis_cpu_request" {
  description = "CPU request for Redis"
  type        = string
  default     = "500m"
}

variable "redis_cpu_limit" {
  description = "CPU limit for Redis"
  type        = string
  default     = "2"
}

variable "redis_memory_request" {
  description = "Memory request for Redis"
  type        = string
  default     = "4Gi"
}

variable "redis_memory_limit" {
  description = "Memory limit for Redis"
  type        = string
  default     = "9Gi"
}

# =============================================================================
# Secrets
# =============================================================================

variable "shield_admin_key" {
  description = "API key for admin portal access"
  type        = string
  sensitive   = true
}

variable "upstash_redis_rest_url" {
  description = "Upstash Redis REST URL (leave empty to use in-cluster Redis)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "upstash_redis_rest_token" {
  description = "Upstash Redis REST token"
  type        = string
  default     = ""
  sensitive   = true
}

variable "playground_llm_base_url" {
  description = "LLM endpoint for admin playground"
  type        = string
  default     = ""
}

variable "playground_llm_master_key" {
  description = "LLM auth key for admin playground"
  type        = string
  default     = ""
  sensitive   = true
}

variable "playground_llm_model" {
  description = "Default model for admin playground"
  type        = string
  default     = ""
}

variable "playground_shield_endpoint" {
  description = "Remote Shield URL for playground validation"
  type        = string
  default     = ""
}

variable "playground_shield_token" {
  description = "Auth token for remote Shield in playground"
  type        = string
  default     = ""
  sensitive   = true
}

# =============================================================================
# HTTP Proxy (on-prem)
# =============================================================================

variable "http_proxy" {
  description = "HTTP proxy URL for outbound traffic (e.g. http://proxy.corp:8080)"
  type        = string
  default     = ""
}

variable "https_proxy" {
  description = "HTTPS proxy URL for outbound traffic (e.g. http://proxy.corp:8080)"
  type        = string
  default     = ""
}

variable "no_proxy" {
  description = "Comma-separated list of hosts/CIDRs to bypass the proxy"
  type        = string
  default     = "localhost,127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,.svc,.cluster.local,redis,vllm"
}

# =============================================================================
# Ingress
# =============================================================================

variable "ingress_class_name" {
  description = "Kubernetes ingress class (e.g. nginx, traefik)"
  type        = string
  default     = "nginx"
}

variable "tls_secret_name" {
  description = "K8s TLS secret name for ingress (leave empty to disable TLS)"
  type        = string
  default     = ""
}
