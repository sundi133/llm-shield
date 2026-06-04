# --- Shield app secrets -------------------------------------------------
resource "kubernetes_secret_v1" "shield_secrets" {
  metadata {
    name      = "shield-secrets"
    namespace = kubernetes_namespace_v1.llm_shield.metadata[0].name

    labels = {
      "app.kubernetes.io/part-of" = "llm-shield"
    }
  }

  data = {
    REDIS_URL = "redis://redis:6379"
  }
}

# --- Admin portal secrets ----------------------------------------------
resource "kubernetes_secret_v1" "admin_secrets" {
  metadata {
    name      = "admin-secrets"
    namespace = kubernetes_namespace_v1.llm_shield.metadata[0].name

    labels = {
      "app.kubernetes.io/part-of" = "llm-shield"
    }
  }

  data = merge(
    {
      SHIELD_ADMIN_KEY = var.shield_admin_key
    },
    # Use in-cluster Redis by default; Upstash overrides if provided
    var.upstash_redis_rest_url != "" ? {
      UPSTASH_REDIS_REST_URL   = var.upstash_redis_rest_url
      UPSTASH_REDIS_REST_TOKEN = var.upstash_redis_rest_token
    } : {},
    var.playground_llm_base_url != "" ? {
      PLAYGROUND_LLM_BASE_URL   = var.playground_llm_base_url
      PLAYGROUND_LLM_MASTER_KEY = var.playground_llm_master_key
      PLAYGROUND_LLM_MODEL      = var.playground_llm_model
    } : {},
    var.playground_shield_endpoint != "" ? {
      PLAYGROUND_SHIELD_ENDPOINT = var.playground_shield_endpoint
      PLAYGROUND_SHIELD_TOKEN    = var.playground_shield_token
    } : {},
  )
}
