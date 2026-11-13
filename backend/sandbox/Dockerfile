# VerifyFix Unified Multi-Runtime Sandbox Image
# ===============================================
# Hardened, isolated multi-runtime container supporting Python 3.11,
# Node.js 20 LTS, and Bash with pre-bundled web/security frameworks
# and automated workspace resolution.

FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive

# 1. Install Node.js 20 LTS, Bash, jq, and required system tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    gnupg \
    bash \
    jq \
    && mkdir -p /etc/apt/keyrings \
    && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x nodistro main" > /etc/apt/sources.list.d/nodesource.list \
    && apt-get update && apt-get install -y --no-install-recommends nodejs \
    && apt-get purge -y --auto-remove curl gnupg \
    && rm -rf /var/lib/apt/lists/*

# 2. Pre-install popular Python frameworks so third-party imports resolve natively
RUN pip install --no-cache-dir \
    flask \
    fastapi \
    sqlalchemy \
    pydantic \
    requests \
    cryptography \
    pyjwt

# 3. Pre-install popular Node.js frameworks globally so require() resolves natively
RUN npm install -g --omit=dev \
    express \
    jsonwebtoken \
    axios \
    cors \
    dotenv

# 4. Set environment paths for cross-module resolution
ENV PYTHONPATH=/app
ENV NODE_PATH=/app:/usr/lib/node_modules:/usr/local/lib/node_modules
WORKDIR /app

# 5. Bake in the auto_mock engine into global Python site-packages
COPY auto_mock.py /usr/local/lib/python3.11/site-packages/auto_mock.py

# 6. Verify installed toolchains
RUN python3 --version && node --version && npm --version && bash --version

CMD ["bash"]
