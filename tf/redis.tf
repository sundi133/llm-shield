# =============================================================================
# Redis — shared state store for tenants, policies, RBAC
# =============================================================================

locals {
  redis_labels = {
    "app"                        = "redis"
    "app.kubernetes.io/part-of"  = "llm-shield"
    "app.kubernetes.io/managed-by" = "terraform"
  }
}

# --- PersistentVolumeClaim ---------------------------------------------
resource "kubernetes_persistent_volume_claim" "redis_data" {
  metadata {
    name      = "redis-data"
    namespace = kubernetes_namespace.llm_shield.metadata[0].name
    labels    = local.redis_labels
  }

  spec {
    access_modes = ["ReadWriteOnce"]

    resources {
      requests = {
        storage = var.redis_storage_size
      }
    }
  }
}

# --- Deployment --------------------------------------------------------
resource "kubernetes_deployment" "redis" {
  metadata {
    name      = "redis"
    namespace = kubernetes_namespace.llm_shield.metadata[0].name
    labels    = local.redis_labels
  }

  spec {
    replicas = 1

    selector {
      match_labels = {
        app = "redis"
      }
    }

    strategy {
      type = "Recreate"
    }

    template {
      metadata {
        labels = local.redis_labels
      }

      spec {
        container {
          name  = "redis"
          image = var.redis_image

          command = [
            "redis-server",
            "--appendonly", "yes",
            "--dir", "/data",
            "--maxmemory", var.redis_max_memory,
            "--maxmemory-policy", "allkeys-lru",
            "--save", "900 1",
            "--save", "300 100",
            "--tcp-keepalive", "60",
            "--timeout", "0",
          ]

          port {
            container_port = 6379
            protocol       = "TCP"
          }

          resources {
            requests = {
              cpu    = var.redis_cpu_request
              memory = var.redis_memory_request
            }
            limits = {
              cpu    = var.redis_cpu_limit
              memory = var.redis_memory_limit
            }
          }

          liveness_probe {
            exec {
              command = ["redis-cli", "ping"]
            }
            initial_delay_seconds = 10
            period_seconds        = 15
            timeout_seconds       = 3
            failure_threshold     = 3
          }

          readiness_probe {
            exec {
              command = ["redis-cli", "ping"]
            }
            initial_delay_seconds = 5
            period_seconds        = 5
            timeout_seconds       = 3
            failure_threshold     = 2
          }

          volume_mount {
            name       = "redis-data"
            mount_path = "/data"
          }
        }

        volume {
          name = "redis-data"

          persistent_volume_claim {
            claim_name = kubernetes_persistent_volume_claim.redis_data.metadata[0].name
          }
        }
      }
    }
  }
}

# --- Service -----------------------------------------------------------
resource "kubernetes_service" "redis" {
  metadata {
    name      = "redis"
    namespace = kubernetes_namespace.llm_shield.metadata[0].name
    labels    = local.redis_labels
  }

  spec {
    selector = {
      app = "redis"
    }

    port {
      port        = 6379
      target_port = 6379
      protocol    = "TCP"
      name        = "redis"
    }

    type = "ClusterIP"
  }
}
