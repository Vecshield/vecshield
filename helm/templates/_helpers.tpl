{{/*
Name of the Secret holding CUSTOMER_API_TOKEN (and optionally VECSHIELD_ADMIN_TOKEN).
*/}}
{{- define "vecshield.authSecret" -}}
{{- .Values.auth.existingSecret | default (printf "%s-auth" .Release.Name) -}}
{{- end -}}

{{/*
Environment shared by the server and the scheduled-audit CronJob: store secret
policy (ADR 0003), NLP mode, writable cache locations for a read-only root
filesystem, and any extra variables.
*/}}
{{- define "vecshield.commonEnv" -}}
- name: HOME
  value: /tmp
- name: XDG_CACHE_HOME
  value: /tmp/.cache
{{- with .Values.nlp.mode }}
- name: VECSHIELD_NLP_MODE
  value: {{ . | quote }}
{{- end }}
{{- with .Values.nlp.model }}
- name: VECSHIELD_NLP_MODEL
  value: {{ . | quote }}
{{- end }}
{{- if .Values.storeSecrets.rejectPlaintext }}
- name: VECSHIELD_REJECT_PLAINTEXT_SECRETS
  value: "1"
{{- end }}
{{- with .Values.storeSecrets.envPrefixes }}
- name: VECSHIELD_SECRET_ENV_PREFIXES
  value: {{ printf "VECSHIELD_STORE_,%s" . | quote }}
{{- end }}
{{- with .Values.storeSecrets.envAllow }}
- name: VECSHIELD_SECRET_ENV_ALLOW
  value: {{ . | quote }}
{{- end }}
{{- with .Values.alerting.webhookHostAllow }}
- name: VECSHIELD_WEBHOOK_HOST_ALLOW
  value: {{ . | quote }}
{{- end }}
{{- with .Values.storeSecrets.env }}
{{ toYaml . }}
{{- end }}
{{- with .Values.extraEnv }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{/*
Volumes shared by the server and the CronJob.
*/}}
{{- define "vecshield.volumes" -}}
- name: data
{{- if .Values.persistence.enabled }}
  persistentVolumeClaim:
    claimName: {{ .Release.Name }}-data
{{- else }}
  emptyDir: {}
{{- end }}
- name: tmp
  emptyDir:
    sizeLimit: {{ .Values.tmpSizeLimit }}
{{- with .Values.storeSecrets.secretName }}
- name: store-secrets
  secret:
    secretName: {{ . }}
    # Group-readable: with fsGroup the files belong to the pod's group.
    defaultMode: 0440
{{- end }}
{{- end -}}

{{- define "vecshield.volumeMounts" -}}
- name: data
  mountPath: /data
- name: tmp
  mountPath: /tmp
{{- if .Values.storeSecrets.secretName }}
- name: store-secrets
  mountPath: /run/secrets/vecshield
  readOnly: true
{{- end }}
{{- end -}}
