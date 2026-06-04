# =============================================================================
# Admin Portal — tenant management UI, RBAC config, playground
# =============================================================================

locals {
  admin_labels = {
    "app"                        = "shield-admin"
    "app.kubernetes.io/part-of"  = "llm-shield"
    "app.kubernetes.io/managed-by" = "terraform"
  }
}

resource "kubernetes_deployment" "admin" {
  metadata {
    name      = "shield-admin"
    namespace = kubernetes_namespace.llm_shield.metadata[0].name
    labels    = local.admin_labels
  }

  spec {
    replicas = var.admin_replicas

    selector {
      match_labels = {
        app = "shield-admin"
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
        labels = local.admin_labels
      }

      spec {
        init_container {
          name  = "init-permissions"
          image = "busybox:latest"
          command = ["sh", "-c", "mkdir -p /app/data /app/log"]

          resources {
            requests = {
              cpu    = "50m"
              memory = "32Mi"
            }
            limits = {
              cpu    = "100m"
              memory = "64Mi"
            }
          }

          volume_mount {
            name       = "storage-data"
            mount_path = "/app/data"
          }

          volume_mount {
            name       = "logs"
            mount_path = "/app/log"
          }
        }

        container {
          name              = "shield-admin"
          image             = var.admin_image
          image_pull_policy = "Always"

          port {
            container_port = 8080
            protocol       = "TCP"
            name           = "http"
          }

          env {
            name  = "AUDIT_LOGGING_ENABLED"
            value = "true"
          }

          env {
            name  = "AUDIT_DB_PATH"
            value = "/app/data/audit.db"
          }

          env {
            name  = "SHIELD_MAX_MODEL_LEN"
            value = "16384"
          }

          # Redis — use in-cluster service
          env {
            name  = "REDIS_URL"
            value = "redis://redis:6379"
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
              name = kubernetes_secret.admin_secrets.metadata[0].name
            }
          }

          resources {
            requests = {
              cpu    = "250m"
              memory = "256Mi"
            }
            limits = {
              cpu    = "1"
              memory = "512Mi"
            }
          }

          liveness_probe {
            http_get {
              path = "/health"
              port = 8080
            }
            initial_delay_seconds = 10
            period_seconds        = 15
            timeout_seconds       = 5
            failure_threshold     = 3
          }

          readiness_probe {
            http_get {
              path = "/health"
              port = 8080
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
            name       = "tmp"
            mount_path = "/tmp"
          }

          volume_mount {
            name       = "storage-data"
            mount_path = "/app/data"
          }

          volume_mount {
            name       = "logs"
            mount_path = "/app/log"
          }

          volume_mount {
            name       = "reports"
            mount_path = "/app/report"
          }

          volume_mount {
            name       = "guardrail-reports"
            mount_path = "/app/reports"
          }
        }

        volume {
          name = "tmp"
          empty_dir {}
        }

        volume {
          name = "storage-data"
          empty_dir {
            size_limit = "500Mi"
          }
        }

        volume {
          name = "logs"
          empty_dir {
            size_limit = "500Mi"
          }
        }

        volume {
          name = "reports"
          empty_dir {
            size_limit = "1Gi"
          }
        }

        volume {
          name = "guardrail-reports"
          empty_dir {
            size_limit = "1Gi"
          }
        }
      }
    }
  }

  depends_on = [
    kubernetes_deployment.redis,
  ]
}

# --- Service -----------------------------------------------------------
resource "kubernetes_service" "admin" {
  metadata {
    name      = "shield-admin"
    namespace = kubernetes_namespace.llm_shield.metadata[0].name
    labels    = local.admin_labels
  }

  spec {
    selector = {
      app = "shield-admin"
    }

    port {
      port        = 8080
      target_port = 8080
      protocol    = "TCP"
      name        = "http"
    }

    type = "ClusterIP"
  }
}

# --- Ingress -----------------------------------------------------------
resource "kubernetes_ingress_v1" "admin" {
  count = var.admin_host != "" ? 1 : 0

  metadata {
    name      = "shield-admin"
    namespace = kubernetes_namespace.llm_shield.metadata[0].name
    labels    = local.admin_labels
  }

  spec {
    ingress_class_name = var.ingress_class_name

    dynamic "tls" {
      for_each = var.tls_secret_name != "" ? [1] : []
      content {
        hosts       = [var.admin_host]
        secret_name = var.tls_secret_name
      }
    }

    rule {
      host = var.admin_host

      http {
        path {
          path      = "/"
          path_type = "Prefix"

          backend {
            service {
              name = kubernetes_service.admin.metadata[0].name
              port {
                number = 8080
              }
            }
          }
        }
      }
    }
  }
}

# --- HorizontalPodAutoscaler ------------------------------------------
resource "kubernetes_horizontal_pod_autoscaler_v2" "admin" {
  metadata {
    name      = "shield-admin"
    namespace = kubernetes_namespace.llm_shield.metadata[0].name
    labels    = local.admin_labels
  }

  spec {
    scale_target_ref {
      api_version = "apps/v1"
      kind        = "Deployment"
      name        = kubernetes_deployment.admin.metadata[0].name
    }

    min_replicas = var.admin_min_replicas
    max_replicas = var.admin_max_replicas

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
