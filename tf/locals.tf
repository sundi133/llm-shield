# Shared proxy environment variables for on-prem deployments.
# Injected into all service containers when http_proxy is set.

locals {
  proxy_enabled = var.http_proxy != ""

  proxy_env = local.proxy_enabled ? [
    { name = "HTTP_PROXY",  value = var.http_proxy },
    { name = "HTTPS_PROXY", value = var.https_proxy != "" ? var.https_proxy : var.http_proxy },
    { name = "http_proxy",  value = var.http_proxy },
    { name = "https_proxy", value = var.https_proxy != "" ? var.https_proxy : var.http_proxy },
    { name = "NO_PROXY",    value = var.no_proxy },
    { name = "no_proxy",    value = var.no_proxy },
  ] : []
}
