# VecShield Enterprise — customer-hosted API/dashboard image.
#
# Two targets, both with NLP detection on and required (a model that fails to
# load stops the start instead of degrading silently):
#
#   docker build -t vecshield-platform:0.0.1 .                      # full (default)
#   docker build --target slim -t vecshield-platform:0.0.1-slim .   # slim
#
#   full  en_core_web_trf 3.8.0 (RoBERTa, curated-transformers, CPU PyTorch).
#         Best measured precision; plan for 2.2-3.2 GB of memory per pod.
#   slim  en_core_web_lg 3.8.0 (CNN + vectors), no PyTorch; about 1-1.3 GB.
#
# Run:    docker run -p 8088:8088 \
#           -e VECSHIELD_INITIAL_ADMIN_PASSWORD="$(openssl rand -base64 18)" \
#           -v $PWD/data:/data vecshield-platform:0.0.1
#         The default command binds 0.0.0.0, so serve refuses to start without
#         that variable (or with a weak one) rather than create admin / admin.
#
# NLP build arguments (see docs/nlp_models.md). Models are installed from
# hash-pinned wheels at build time, verified by loading them in an offline
# interpreter, and never downloaded at scan time:
#   --build-arg VECSHIELD_NLP_MODEL=<catalog name>     override the target's model
#   --build-arg VECSHIELD_NLP_LANGUAGE_MODELS=--extras also bake the configured
#               non-English models (VECSHIELD_NER_MODELS); or list catalog names,
#               e.g. "de_core_news_sm fr_core_news_sm". Not included by default.
#   --build-arg VECSHIELD_NLP_MODEL=none --build-arg VECSHIELD_NLP_MODE=disabled
#               regex-only image (names, places and organisations are then
#               reported as not examined, never as clean).
# Air-gapped builds: put the model wheels in ./wheelhouse inside the build
# context and pass --build-arg VECSHIELD_NLP_WHEELHOUSE=/app/wheelhouse.
#
# NOTE: the detection core `vecshield` ships in-tree; any private deps must be
# resolvable from your configured private mirror at build time.

FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Configure your private index here (build arg), e.g.:
#   --build-arg PIP_INDEX_URL=https://user:token@pypi.internal/simple
# It is a build ARG only (visible to RUN steps), not an image ENV, so index
# credentials are not persisted into the runtime image configuration. Prefer
# BuildKit secrets for credentials: build args remain visible in build history.
ARG PIP_INDEX_URL=""

WORKDIR /app
RUN pip install --upgrade pip && \
    useradd --create-home --uid 10001 vecshield

# The model is baked in below; the running service never fetches weights or
# tokenizers from the Hugging Face Hub (the code enforces this too).
ENV HF_HUB_OFFLINE=1 \
    TRANSFORMERS_OFFLINE=1

EXPOSE 8088
ENTRYPOINT ["vecshield-platform"]
CMD ["serve", "--config", "/data/vecshield.json", "--state-dir", "/data/state", "--host", "0.0.0.0", "--port", "8088"]


# ---------------------------------------------------------------------------
# slim: en_core_web_lg, no PyTorch.
# ---------------------------------------------------------------------------
FROM base AS slim

COPY . /app
# Install with the connector extras you deploy (edit as needed).
RUN pip install ".[chroma,pgvector,nlp-lg]"

ARG VECSHIELD_NLP_MODEL=en_core_web_lg
ARG VECSHIELD_NLP_MODE=required
ARG VECSHIELD_NLP_LANGUAGE_MODELS=""
ARG VECSHIELD_NLP_WHEELHOUSE=""
ARG VECSHIELD_NLP_MODELS=""
RUN set -e; \
    if [ -n "$VECSHIELD_NLP_MODELS" ]; then \
        echo "VECSHIELD_NLP_MODELS was replaced by VECSHIELD_NLP_MODEL and VECSHIELD_NLP_LANGUAGE_MODELS; see docs/nlp_models.md" >&2; exit 1; \
    fi; \
    if [ "$VECSHIELD_NLP_MODEL" = "none" ]; then \
        if [ "$VECSHIELD_NLP_MODE" != "disabled" ]; then \
            echo "VECSHIELD_NLP_MODEL=none needs --build-arg VECSHIELD_NLP_MODE=disabled" >&2; exit 1; \
        fi; \
        echo "no NLP model installed (regex-only detection)"; \
    else \
        vecshield-platform nlp install "$VECSHIELD_NLP_MODEL" $VECSHIELD_NLP_LANGUAGE_MODELS; \
    fi
ENV VECSHIELD_NLP_MODE=${VECSHIELD_NLP_MODE} \
    VECSHIELD_NLP_MODEL=${VECSHIELD_NLP_MODEL}

USER vecshield


# ---------------------------------------------------------------------------
# full (default target): en_core_web_trf on CPU PyTorch.
# ---------------------------------------------------------------------------
FROM base AS full

# The default Linux torch wheel on PyPI bundles CUDA libraries (several GB);
# the scanner runs NER on CPU, so the CPU build is installed first, before the
# source is copied, so a code change does not re-download it. Set to "" to
# resolve torch from PIP_INDEX_URL instead.
ARG TORCH_INDEX_URL=https://download.pytorch.org/whl/cpu
RUN if [ -n "$TORCH_INDEX_URL" ]; then \
        pip install --index-url "$TORCH_INDEX_URL" "torch>=2.6,<2.15"; \
    fi

COPY . /app
# Install with the connector extras you deploy (edit as needed). nlp-trf
# provides Presidio, spaCy and spacy-curated-transformers for the default model.
RUN pip install ".[chroma,pgvector,nlp-trf]"

ARG VECSHIELD_NLP_MODEL=en_core_web_trf
ARG VECSHIELD_NLP_MODE=required
ARG VECSHIELD_NLP_LANGUAGE_MODELS=""
ARG VECSHIELD_NLP_WHEELHOUSE=""
ARG VECSHIELD_NLP_MODELS=""
RUN set -e; \
    if [ -n "$VECSHIELD_NLP_MODELS" ]; then \
        echo "VECSHIELD_NLP_MODELS was replaced by VECSHIELD_NLP_MODEL and VECSHIELD_NLP_LANGUAGE_MODELS; see docs/nlp_models.md" >&2; exit 1; \
    fi; \
    if [ "$VECSHIELD_NLP_MODEL" = "none" ]; then \
        if [ "$VECSHIELD_NLP_MODE" != "disabled" ]; then \
            echo "VECSHIELD_NLP_MODEL=none needs --build-arg VECSHIELD_NLP_MODE=disabled" >&2; exit 1; \
        fi; \
        echo "no NLP model installed (regex-only detection)"; \
    else \
        vecshield-platform nlp install "$VECSHIELD_NLP_MODEL" $VECSHIELD_NLP_LANGUAGE_MODELS; \
    fi
ENV VECSHIELD_NLP_MODE=${VECSHIELD_NLP_MODE} \
    VECSHIELD_NLP_MODEL=${VECSHIELD_NLP_MODEL}

USER vecshield
