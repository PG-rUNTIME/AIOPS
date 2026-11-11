{{- define "svc.name" -}}{{ .Values.service | required "service is required" }}{{- end -}}
{{- define "svc.labels" -}}
app.kubernetes.io/name: {{ include "svc.name" . }}
app.kubernetes.io/part-of: aiops-platform
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end -}}
{{- define "svc.selector" -}}
app.kubernetes.io/name: {{ include "svc.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{- define "svc.image" -}}
{{- $repo := printf "%s/%s" .Values.image.repository (include "svc.name" .) -}}
{{- if .Values.image.digest -}}{{ $repo }}@{{ .Values.image.digest }}{{- else -}}{{ $repo }}:{{ .Values.image.tag | default .Chart.AppVersion }}{{- end -}}
{{- end -}}
