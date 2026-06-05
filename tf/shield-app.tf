# =============================================================================
# Shield App — core guardrail inference API
# =============================================================================

locals {
  shield_labels = {
    "app"                        = "shield"
    "app.kubernetes.io/part-of"  = "llm-shield"
    "app.kubernetes.io/managed-by" = "terraform"
  }
}

resource "kubernetes_deployment_v1" "shield" {
  metadata {
    name      = "shield"
    namespace = kubernetes_namespace_v1.llm_shield.metadata[0].name
    labels    = local.shield_labels
  }

  spec {
    replicas = var.shield_replicas

    selector {
      match_labels = {
        app = "shield"
      }
    }

    strategy {
      type = "RollingUpdate"

      rolling_update {
        max_unavailable = "0"
        max_surge       = "1"
      }
    }

    template {
      metadata {
        labels = local.shield_labels
      }

      spec {
        container {
          name  = "shield"
          image = var.shield_image
          image_pull_policy = "Always"

          # Override entrypoint to skip local vLLM — use the decoupled vLLM service
          command = ["python3", "handler.py"]

          port {
            container_port = 80
            protocol       = "TCP"
            name           = "http"
          }

          # Core config
          env {
            name  = "PORT"
            value = "80"
          }

          env {
            name  = "WORKERS"
            value = tostring(var.shield_workers)
          }

          env {
            name  = "SKIP_VLLM"
            value = "true"
          }

          # Point to the decoupled vLLM service
          env {
            name  = "LLM_BACKEND_URL"
            value = "http://vllm:8000/v1"
          }

          env {
            name  = "LLM_BACKEND_TYPE"
            value = "vllm"
          }

          # Redis — authenticated in-cluster service
          env {
            name = "REDIS_URL"
            value_from {
              secret_key_ref {
                name = kubernetes_secret_v1.shield_secrets.metadata[0].name
                key  = "REDIS_URL"
              }
            }
          }

          env {
            name  = "AUDIT_DB_PATH"
            value = "/app/data/audit.db"
          }

          env {
            name  = "CONFIG_PATH"
            value = "/app/data/config.yaml"
          }

          # HTTP proxy for on-prem environments
          dynamic "env" {
            for_each = local.proxy_env
            content {
              name  = env.value.name
              value = env.value.value
            }
          }

          env_from {
            secret_ref {
              name = kubernetes_secret_v1.shield_secrets.metadata[0].name
            }
          }

          resources {
            requests = {
              cpu    = var.shield_cpu_request
              memory = var.shield_memory_request
            }
            limits = {
              cpu    = var.shield_cpu_limit
              memory = var.shield_memory_limit
            }
          }

          liveness_probe {
            http_get {
              path = "/health"
              port = 80
            }
            initial_delay_seconds = 15
            period_seconds        = 15
            timeout_seconds       = 5
            failure_threshold     = 3
          }

          readiness_probe {
            http_get {
              path = "/health"
              port = 80
            }
            initial_delay_seconds = 5
            period_seconds        = 10
            timeout_seconds       = 3
            failure_threshold     = 2
          }

          security_context {
            allow_privilege_escalation = false

            capabilities {
              drop = ["ALL"]
            }
          }

          volume_mount {
            name       = "data"
            mount_path = "/app/data"
          }
        }

        volume {
          name = "data"
          empty_dir {
            size_limit = "1Gi"
          }
        }
      }
    }
  }

  depends_on = [
    kubernetes_deployment_v1.redis,
  ]
}

# --- Service -----------------------------------------------------------
resource "kubernetes_service_v1" "shield" {
  metadata {
    name      = "shield"
    namespace = kubernetes_namespace_v1.llm_shield.metadata[0].name
    labels    = local.shield_labels
  }

  spec {
    selector = {
      app = "shield"
    }

    port {
      port        = 80
      target_port = 80
      protocol    = "TCP"
      name        = "http"
    }

    type = "ClusterIP"
  }
}

# --- Ingress -----------------------------------------------------------
resource "kubernetes_ingress_v1" "shield" {
  count = var.shield_host != "" ? 1 : 0

  metadata {
    name      = "shield"
    namespace = kubernetes_namespace_v1.llm_shield.metadata[0].name
    labels    = local.shield_labels

    annotations = {
      "nginx.ingress.kubernetes.io/proxy-body-size"    = "10m"
      "nginx.ingress.kubernetes.io/proxy-read-timeout" = "60"
    }
  }

  spec {
    ingress_class_name = var.ingress_class_name

    dynamic "tls" {
      for_each = var.tls_secret_name != "" ? [1] : []
      content {
        hosts       = [var.shield_host]
        secret_name = var.tls_secret_name
      }
    }

    rule {
      host = var.shield_host

      http {
        path {
          path      = "/"
          path_type = "Prefix"

          backend {
            service {
              name = kubernetes_service_v1.shield.metadata[0].name
              port {
                number = 80
              }
            }
          }
        }
      }
    }
  }
}

# --- HorizontalPodAutoscaler ------------------------------------------
resource "kubernetes_horizontal_pod_autoscaler_v2" "shield" {
  metadata {
    name      = "shield"
    namespace = kubernetes_namespace_v1.llm_shield.metadata[0].name
    labels    = local.shield_labels
  }

  spec {
    scale_target_ref {
      api_version = "apps/v1"
      kind        = "Deployment"
      name        = kubernetes_deployment_v1.shield.metadata[0].name
    }

    min_replicas = var.shield_min_replicas
    max_replicas = var.shield_max_replicas

    metric {
      type = "Resource"
      resource {
        name = "cpu"
        target {
          type                = "Utilization"
          average_utilization = 70
        }
      }
    }

    metric {
      type = "Resource"
      resource {
        name = "memory"
        target {
          type                = "Utilization"
          average_utilization = 80
        }
      }
    }
  }
}
