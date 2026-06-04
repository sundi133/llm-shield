# =============================================================================
# Network Policies — restrict inter-service traffic
# =============================================================================

# --- Redis: only accept from pods in the same namespace ----------------
resource "kubernetes_network_policy" "redis_ingress" {
  metadata {
    name      = "redis-ingress"
    namespace = kubernetes_namespace.llm_shield.metadata[0].name

    labels = {
      app = "redis"
    }
  }

  spec {
    pod_selector {
      match_labels = {
        app = "redis"
      }
    }

    policy_types = ["Ingress"]

    ingress {
      from {
        pod_selector {}
      }

      ports {
        port     = "6379"
        protocol = "TCP"
      }
    }
  }
}

# --- vLLM: only accept from Shield app pods ----------------------------
resource "kubernetes_network_policy" "vllm_ingress" {
  metadata {
    name      = "vllm-ingress"
    namespace = kubernetes_namespace.llm_shield.metadata[0].name

    labels = {
      app = "vllm"
    }
  }

  spec {
    pod_selector {
      match_labels = {
        app = "vllm"
      }
    }

    policy_types = ["Ingress"]

    ingress {
      from {
        pod_selector {
          match_labels = {
            app = "shield"
          }
        }
      }

      ports {
        port     = "8000"
        protocol = "TCP"
      }
    }
  }
}

# --- Shield: accept from ingress controller + namespace pods -----------
resource "kubernetes_network_policy" "shield_ingress" {
  metadata {
    name      = "shield-ingress"
    namespace = kubernetes_namespace.llm_shield.metadata[0].name

    labels = {
      app = "shield"
    }
  }

  spec {
    pod_selector {
      match_labels = {
        app = "shield"
      }
    }

    policy_types = ["Ingress"]

    ingress {
      # From ingress controller namespace
      from {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = "ingress-nginx"
          }
        }
      }

      # From pods in same namespace
      from {
        pod_selector {}
      }

      ports {
        port     = "80"
        protocol = "TCP"
      }
    }
  }
}

# --- Admin: accept from ingress controller + namespace pods ------------
resource "kubernetes_network_policy" "admin_ingress" {
  metadata {
    name      = "admin-ingress"
    namespace = kubernetes_namespace.llm_shield.metadata[0].name

    labels = {
      app = "shield-admin"
    }
  }

  spec {
    pod_selector {
      match_labels = {
        app = "shield-admin"
      }
    }

    policy_types = ["Ingress"]

    ingress {
      from {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = "ingress-nginx"
          }
        }
      }

      from {
        pod_selector {}
      }

      ports {
        port     = "8080"
        protocol = "TCP"
      }
    }
  }
}
