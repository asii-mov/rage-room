# Rage Room Sandbox
# Based on trailofbits/claude-code-devcontainer, adapted for org use
ARG UV_VERSION=0.10.0
FROM ghcr.io/astral-sh/uv:${UV_VERSION} AS uv
FROM mcr.microsoft.com/devcontainers/base:ubuntu-24.04@sha256:d94c97dd9cacf183d0a6fd12a8e87b526e9e928307674ae9c94139139c0c6eae

ARG TZ
ENV TZ="$TZ"

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Install system packages
RUN apt-get update && apt-get install -y --no-install-recommends \
  bubblewrap \
  socat \
  fd-find \
  ripgrep \
  tmux \
  zsh \
  build-essential \
  jq \
  nano \
  unzip \
  vim \
  dnsutils \
  ipset \
  iptables \
  iproute2 \
  && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install git-delta
ARG GIT_DELTA_VERSION=0.18.2
RUN ARCH=$(dpkg --print-architecture) && \
  curl -fsSL "https://github.com/dandavison/delta/releases/download/${GIT_DELTA_VERSION}/git-delta_${GIT_DELTA_VERSION}_${ARCH}.deb" -o /tmp/git-delta.deb && \
  dpkg -i /tmp/git-delta.deb && \
  rm /tmp/git-delta.deb

# Install uv
COPY --from=uv /uv /usr/local/bin/uv

# Install fzf
ARG FZF_VERSION=0.67.0
RUN ARCH=$(dpkg --print-architecture) && \
  case "${ARCH}" in \
    amd64) FZF_ARCH="linux_amd64" ;; \
    arm64) FZF_ARCH="linux_arm64" ;; \
    *) echo "Unsupported architecture: ${ARCH}" && exit 1 ;; \
  esac && \
  curl -fsSL "https://github.com/junegunn/fzf/releases/download/v${FZF_VERSION}/fzf-${FZF_VERSION}-${FZF_ARCH}.tar.gz" | tar -xz -C /usr/local/bin

# Create directories and set ownership
RUN mkdir -p /commandhistory /workspace /home/vscode/.claude /home/vscode/.codex /opt && \
  touch /commandhistory/.bash_history && \
  touch /commandhistory/.zsh_history && \
  chown -R vscode:vscode /commandhistory /workspace /home/vscode/.claude /home/vscode/.codex /opt

ENV DEVCONTAINER=true
ENV SHELL=/bin/zsh
ENV TERM=xterm-256color
ENV EDITOR=nano
ENV VISUAL=nano

# Go supply-chain hardening
ENV GOPROXY="proxy.golang.org,off"
ENV GOSUMDB="sum.golang.org"

WORKDIR /workspace

USER vscode

ENV PATH="/home/vscode/.local/bin:$PATH"

# Install Claude Code (no third-party plugins)
RUN curl -fsSL https://claude.ai/install.sh | bash

# Install Python 3.13 via uv
RUN uv python install 3.13 --default

# Install ast-grep
RUN uv tool install ast-grep-cli

# Install fnm and Node 22
ARG NODE_VERSION=22
ARG FNM_VERSION=1.38.1
ENV FNM_DIR="/home/vscode/.fnm"
RUN ARCH=$(uname -m) && \
  curl -fsSL "https://github.com/Schniz/fnm/releases/download/v${FNM_VERSION}/fnm-linux.zip" -o /tmp/fnm.zip && \
  mkdir -p "$FNM_DIR" && unzip -o /tmp/fnm.zip -d "$FNM_DIR" && rm /tmp/fnm.zip && \
  chmod +x "$FNM_DIR/fnm" && \
  export PATH="$FNM_DIR:$PATH" && \
  eval "$(fnm env)" && \
  fnm install ${NODE_VERSION} && \
  fnm default ${NODE_VERSION} && \
  ln -s "$(fnm exec --using=${NODE_VERSION} which node)" /home/vscode/.local/bin/node && \
  ln -s "$(fnm exec --using=${NODE_VERSION} which npm)" /home/vscode/.local/bin/npm && \
  ln -s "$(fnm exec --using=${NODE_VERSION} which npx)" /home/vscode/.local/bin/npx

# Install Codex CLI and symlink to PATH
RUN npm install -g @openai/codex && \
  ln -s "$FNM_DIR/node-versions/v$(node --version | tr -d v)/installation/bin/codex" /home/vscode/.local/bin/codex

# Install Oh My Zsh
ARG ZSH_IN_DOCKER_VERSION=1.2.1
RUN sh -c "$(curl -fsSL https://github.com/deluan/zsh-in-docker/releases/download/v${ZSH_IN_DOCKER_VERSION}/zsh-in-docker.sh)" -- \
  -p git \
  -x

# Copy zsh configuration
COPY --chown=vscode:vscode .zshrc /home/vscode/.zshrc.custom
RUN echo 'source ~/.zshrc.custom' >> /home/vscode/.zshrc

# Copy org configs into the image
COPY --chown=vscode:vscode org-configs/settings.json /opt/org-settings.json
COPY --chown=vscode:vscode org-configs/CLAUDE.md /opt/org-CLAUDE.md
COPY --chown=vscode:vscode org-configs/codex-config.toml /opt/org-codex-config.toml

# Copy hardening configs (supply-chain security)
COPY --chown=vscode:vscode org-configs/.npmrc /home/vscode/.npmrc
COPY --chown=vscode:vscode org-configs/uv.toml /home/vscode/.config/uv/uv.toml
COPY --chown=vscode:vscode org-configs/go-env.sh /opt/go-env.sh

# Copy post_install script
COPY --chown=vscode:vscode post_install.py /opt/post_install.py

# Lock down: make org configs tamper-proof, then remove sudo
RUN sudo chown -R root:root /opt && \
  sudo chmod -R a+r,a-w /opt && \
  sudo chmod a+x /opt/post_install.py && \
  sudo deluser vscode sudo 2>/dev/null; \
  sudo rm -f /etc/sudoers.d/vscode || true
