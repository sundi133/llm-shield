output "namespace" {
  description = "Kubernetes namespace for LLM Shield"
  value       = kubernetes_namespace_v1.llm_shield.metadata[0].name
}

output "redis_service" {
  description = "Redis internal service endpoint (password in shield-secrets)"
  value       = "redis://redis.${kubernetes_namespace_v1.llm_shield.metadata[0].name}.svc.cluster.local:6379"
}

output "vllm_service" {
  description = "vLLM internal service endpoint"
  value       = "http://vllm.${kubernetes_namespace_v1.llm_shield.metadata[0].name}.svc.cluster.local:8000"
}

output "shield_service" {
  description = "Shield app internal service endpoint"
  value       = "http://shield.${kubernetes_namespace_v1.llm_shield.metadata[0].name}.svc.cluster.local:80"
}

output "admin_service" {
  description = "Admin portal internal service endpoint"
  value       = "http://shield-admin.${kubernetes_namespace_v1.llm_shield.metadata[0].name}.svc.cluster.local:8080"
}

output "shield_ingress_host" {
  description = "Shield app external hostname (if ingress enabled)"
  value       = var.shield_host != "" ? var.shield_host : "(ingress not configured — set shield_host)"
}

output "admin_ingress_host" {
  description = "Admin portal external hostname (if ingress enabled)"
  value       = var.admin_host != "" ? var.admin_host : "(ingress not configured — set admin_host)"
}
