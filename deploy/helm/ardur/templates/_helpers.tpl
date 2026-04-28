{{/*
Ardur chart template helpers.
*/}}

{{/*
Canonical name — truncated to fit k8s label length limits.
*/}}
{{- define "ardur.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Fully qualified app name.
*/}}
{{- define "ardur.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Standard labels applied to every resource.
*/}}
{{- define "ardur.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "ardur.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: ardur
{{- end -}}

{{- define "ardur.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ardur.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Image reference helper — combines global.registry + component.image.repository + tag.
*/}}
{{- define "ardur.image" -}}
{{- $registry := .Values.global.registry -}}
{{- $component := .component -}}
{{- printf "%s/%s:%s" $registry $component.image.repository $component.image.tag -}}
{{- end -}}
