{{- define "shield-identity.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "shield-identity.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "shield-identity.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "shield-identity.labels" -}}
app.kubernetes.io/name: {{ include "shield-identity.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}

{{- define "shield-identity.selectorLabels" -}}
app.kubernetes.io/name: {{ include "shield-identity.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* Name of the Secret holding the proxy token. */}}
{{- define "shield-identity.proxySecretName" -}}
{{- if .Values.proxySecret.existingSecret -}}
{{ .Values.proxySecret.existingSecret }}
{{- else -}}
{{ include "shield-identity.fullname" . }}-proxy-token
{{- end -}}
{{- end -}}
