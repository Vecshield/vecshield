# Demo image: VecShield plus a Chroma-backed synthetic estate.
#
# Deliberately not the production Dockerfile at the repository root. That one
# bakes in a spaCy NER model and (on the full target) PyTorch, which makes for
# a multi-gigabyte image and a long first build. The demo runs the regex
# detectors only, so it builds in under a minute and needs no network at run
# time. Everything the demo detects, it detects without the NLP extra.
#
# For a deployment image, use the root Dockerfile. See docs/deployment.md.

FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    # Regex detectors only: no model download, no PyTorch, fully offline.
    VECSHIELD_NLP_MODE=disabled

WORKDIR /src

# Copy the project and install it with the Chroma connector. The demo seeds
# into a local Chroma directory, so no vector-database server is involved.
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY vecshield ./vecshield
COPY vecshield_platform ./vecshield_platform
RUN pip install --no-cache-dir ".[chroma]"

COPY demo ./demo

# Unprivileged: the console is a security tool and should not model bad habits.
RUN useradd --create-home --uid 10001 vecshield \
    && mkdir -p /data \
    && chown -R vecshield:vecshield /data /src
USER vecshield

VOLUME ["/data"]
EXPOSE 8088

ENTRYPOINT ["/src/demo/entrypoint.sh"]
