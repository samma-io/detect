{{/*
Common labels applied to all resources.
*/}}
{{- define "detect.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: detect
{{- end }}

{{/*
Produce a safe k8s resource name for a scanner.
Usage: {{ include "detect.scannerName" $name }}
*/}}
{{- define "detect.scannerName" -}}
{{- printf "detect-%s" . | trunc 63 | trimSuffix "-" }}
{{- end }}
