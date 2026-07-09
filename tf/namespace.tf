# --- Rafay project -----------------------------------------------------
resource "rafay_project" "llm_shield" {
  metadata {
    name = var.rafay_project_name
  }

  spec {
    default = false
  }
}

# --- Kubernetes namespace ----------------------------------------------
resource "kubernetes_namespace_v1" "llm_shield" {
  metadata {
    name = var.namespace

    labels = {
      "app.kubernetes.io/part-of"  = "llm-shield"
      "app.kubernetes.io/managed-by" = "terraform"
    }
  }
}
