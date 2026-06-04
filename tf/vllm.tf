# =============================================================================
# vLLM — GPU-accelerated LLM inference server
# =============================================================================

locals {
  vllm_labels = {
    "app"                        = "vllm"
    "app.kubernetes.io/part-of"  = "llm-shield"
    "app.kubernetes.io/managed-by" = "terraform"
  }
}

resource "kubernetes_deployment" "vllm" {
  metadata {
    name      = "vllm"
    namespace = kubernetes_namespace.llm_shield.metadata[0].name
    labels    = local.vllm_labels
  }

  spec {
    replicas = 1

    selector {
      match_labels = {
        app = "vllm"
      }
    }

    strategy {
      type = "Recreate"
    }

    template {
      metadata {
        labels = local.vllm_labels
      }

      spec {
        # Schedule on GPU nodes
        node_selector = {
          (var.gpu_node_pool_label) = "true"
        }

        toleration {
          key      = "nvidia.com/gpu"
          operator = "Exists"
          effect   = "NoSchedule"
        }

        container {
          name  = "vllm"
          image = var.vllm_image

          args = [
            "--model", var.vllm_model_name,
            "--host", "0.0.0.0",
            "--port", "8000",
            "--dtype", "bfloat16",
            "--quantization", "fp8",
            "--kv-cache-dtype", "fp8",
            "--max-model-len", var.vllm_max_model_len,
            "--max-num-batched-tokens", var.vllm_max_model_len,
            "--max-num-seqs", var.vllm_max_num_seqs,
            "--gpu-memory-utilization", var.gpu_memory_utilization,
            "--enable-prefix-caching",
          ]

          port {
            container_port = 8000
            protocol       = "TCP"
            name           = "http"
          }

          env {
            name  = "VLLM_ATTENTION_BACKEND"
            value = "FLASHINFER"
          }

          # HTTP proxy for on-prem (needed for HuggingFace model downloads)
          dynamic "env" {
            for_each = local.proxy_env
            content {
              name  = env.value.name
              value = env.value.value
            }
          }

          # Cache directories for model artifacts
          env {
            name  = "HF_HOME"
            value = "/tmp/cache/huggingface"
          }

          env {
            name  = "VLLM_CACHE_ROOT"
            value = "/tmp/cache/vllm"
          }

          resources {
            requests = {
              cpu               = var.vllm_cpu_request
              memory            = var.vllm_memory_request
              "nvidia.com/gpu"  = var.vllm_gpu_count
            }
            limits = {
              cpu               = var.vllm_cpu_limit
              memory            = var.vllm_memory_limit
              "nvidia.com/gpu"  = var.vllm_gpu_count
            }
          }

          # vLLM takes time to download + load models on first start
          startup_probe {
            http_get {
              path = "/v1/models"
              port = 8000
            }
            initial_delay_seconds = 30
            period_seconds        = 10
            timeout_seconds       = 5
            failure_threshold     = 30 # up to 5 minutes for model download
          }

          liveness_probe {
            http_get {
              path = "/v1/models"
              port = 8000
            }
            initial_delay_seconds = 120
            period_seconds        = 30
            timeout_seconds       = 5
            failure_threshold     = 3
          }

          readiness_probe {
            http_get {
              path = "/v1/models"
              port = 8000
            }
            initial_delay_seconds = 10
            period_seconds        = 10
            timeout_seconds       = 5
            failure_threshold     = 3
          }

          volume_mount {
            name       = "cache"
            mount_path = "/tmp/cache"
          }

          volume_mount {
            name       = "shm"
            mount_path = "/dev/shm"
          }
        }

        volume {
          name = "cache"
          empty_dir {
            size_limit = "50Gi"
          }
        }

        # vLLM uses shared memory for tensor parallelism
        volume {
          name = "shm"
          empty_dir {
            medium     = "Memory"
            size_limit = "8Gi"
          }
        }
      }
    }
  }
}

# --- Service (internal only) ------------------------------------------
resource "kubernetes_service" "vllm" {
  metadata {
    name      = "vllm"
    namespace = kubernetes_namespace.llm_shield.metadata[0].name
    labels    = local.vllm_labels
  }

  spec {
    selector = {
      app = "vllm"
    }

    port {
      port        = 8000
      target_port = 8000
      protocol    = "TCP"
      name        = "http"
    }

    type = "ClusterIP"
  }
}
