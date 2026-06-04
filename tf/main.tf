terraform {
  required_version = ">= 1.5"

  required_providers {
    rafay = {
      source  = "RafaySystems/rafay"
      version = ">= 1.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.25"
    }
  }
}

# --- Rafay provider ---------------------------------------------------
provider "rafay" {
  api_key      = var.rafay_api_key
  project      = var.rafay_project_name
  rest_endpoint = var.rafay_rest_endpoint
}

# --- Kubernetes provider (uses Rafay-managed cluster) ------------------
# Configure with your cluster's kubeconfig after Rafay provisions it.
provider "kubernetes" {
  config_path    = var.kubeconfig_path
  config_context = var.kubeconfig_context
}
