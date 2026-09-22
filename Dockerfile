# cryptoptic container image.
#
# Contains Python, the GitHub CLI, a pinned+verified CodeQL CLI bundle, the
# project's query packs and their resolved dependencies.
#
# amd64 only: the CodeQL bundle asset (codeql-bundle-linux64.tar.gz) is not
# published for arm64, so there is no arm64 variant to build.

FROM python:3.11-slim-bookworm

# Bump these together. CODEQL_BUNDLE_SHA256 is the sha256 of
# codeql-bundle-linux64.tar.gz for the tag codeql-bundle-v${CODEQL_VERSION};
# changing the version without the digest will fail the build, which is the
# intended behaviour.
ARG CODEQL_VERSION=2.27.0
ARG CODEQL_BUNDLE_SHA256=8e870433e5c80d0e916c3c1aa9005fc88aab990bcdcc649fade9dfc4d7e94305

# The GitHub CLI is not in the Debian bookworm archive, so it is installed
# from the upstream release rather than apt. The download is checked against
# the checksums file published alongside it; set GH_SHA256 to also pin the
# digest explicitly.
ARG GH_VERSION=2.63.2
ARG GH_SHA256=

LABEL org.opencontainers.image.title="cryptoptic" \
      org.opencontainers.image.description="CodeQL-based cryptographic inventory (CBOM) scanner" \
      org.opencontainers.image.source="https://github.com/nationwide-group-oss/cryptoptic" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Nationwide Building Society"

ENV DEBIAN_FRONTEND=noninteractive \
    PATH=/opt/codeql/codeql:${PATH} \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_ROOT_USER_ACTION=ignore

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# nodejs is retained from the original image definition; drop it from this
# list if nothing in scripts/ or the query packs shells out to node.
#
# DL3008: apt versions are deliberately unpinned. Debian point releases drop
# superseded versions from the archive, so pinning here breaks the build on a
# schedule nobody controls. The things that matter for reproducibility, the
# CodeQL bundle and gh, are pinned and digest-checked above.
# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        bash \
        ca-certificates \
        curl \
        findutils \
        git \
        nodejs \
        tar \
    && rm -rf /var/lib/apt/lists/*

# DL3003: cd is scoped to this one RUN; the checksums file names the tarball
# relative to its own directory, so sha256sum has to run alongside it.
# hadolint ignore=DL3003
RUN set -eux; \
    cd /tmp; \
    curl --fail --location --silent --show-error --retry 3 --remote-name \
        "https://github.com/cli/cli/releases/download/v${GH_VERSION}/gh_${GH_VERSION}_linux_amd64.tar.gz"; \
    curl --fail --location --silent --show-error --retry 3 --remote-name \
        "https://github.com/cli/cli/releases/download/v${GH_VERSION}/gh_${GH_VERSION}_checksums.txt"; \
    sha256sum --check --ignore-missing "gh_${GH_VERSION}_checksums.txt"; \
    if [[ -n "${GH_SHA256}" ]]; then \
        echo "${GH_SHA256}  gh_${GH_VERSION}_linux_amd64.tar.gz" | sha256sum --check --status; \
    fi; \
    tar --extract --gzip --file "gh_${GH_VERSION}_linux_amd64.tar.gz"; \
    install -m 0755 "gh_${GH_VERSION}_linux_amd64/bin/gh" /usr/local/bin/gh; \
    rm -rf "gh_${GH_VERSION}_linux_amd64" "gh_${GH_VERSION}_linux_amd64.tar.gz" "gh_${GH_VERSION}_checksums.txt"; \
    gh --version

RUN set -eux; \
    curl --fail --location --silent --show-error --retry 3 \
        --output /tmp/codeql-bundle.tar.gz \
        "https://github.com/github/codeql-action/releases/download/codeql-bundle-v${CODEQL_VERSION}/codeql-bundle-linux64.tar.gz"; \
    echo "${CODEQL_BUNDLE_SHA256}  /tmp/codeql-bundle.tar.gz" | sha256sum --check --status; \
    mkdir --parents /opt/codeql; \
    tar --extract --gzip --file /tmp/codeql-bundle.tar.gz --directory /opt/codeql; \
    rm /tmp/codeql-bundle.tar.gz; \
    codeql version

WORKDIR /opt/cryptoptic

COPY requirements.txt /opt/cryptoptic/requirements.txt
RUN pip install --requirement /opt/cryptoptic/requirements.txt

COPY codeql-queries /opt/cryptoptic/codeql-queries
COPY scripts /opt/cryptoptic/scripts
COPY cbom-test-suite /opt/cryptoptic/cbom-test-suite
COPY tests /opt/cryptoptic/tests

# Resolve dependencies for every query pack that is actually present, rather
# than a hard-coded language list that drifts from the tree (the previous
# list installed java, which is still on the roadmap, and skipped csharp,
# which is supported). Fails if no pack is found at all.
RUN set -eux; \
    found=0; \
    for pack in /opt/cryptoptic/codeql-queries/*/; do \
        if [[ -f "${pack}qlpack.yml" ]]; then \
            codeql pack install "${pack}"; \
            found=1; \
        fi; \
    done; \
    if [[ "${found}" -ne 1 ]]; then \
        echo "No CodeQL packs (qlpack.yml) found under codeql-queries/" >&2; \
        exit 1; \
    fi

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["scan"]
