# Imagem base com Python 3
FROM python:3.11-slim

# Variável de ambiente para evitar problemas de encoding
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/tools:$PATH" \
    TOOLS_DIR="/app/tools" \
    DEBIAN_FRONTEND=noninteractive \
    GOPATH=/go \
    GOLANG_VERSION=1.22.3

# Diretório da aplicação dentro do container
WORKDIR /app

# Cria estrutura de diretórios primeiro
RUN mkdir -p ${TOOLS_DIR} && \
    chmod -R 777 ${TOOLS_DIR}

# Copia arquivos necessários
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Copia o requirements.txt antes de instalar as dependências
COPY requirements.txt /app/requirements.txt

# Instalações do sistema (ferramentas externas que o Recon usa)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl wget git dnsutils iputils-ping netcat-openbsd unzip jq \
    && rm -rf /var/lib/apt/lists/*

# Instala dependências Python
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    ln -sf /usr/local/bin/python3 /usr/local/bin/python


# Instala Go
RUN curl -LO https://go.dev/dl/go${GOLANG_VERSION}.linux-amd64.tar.gz && \
    rm -rf /usr/local/go && \
    tar -C /usr/local -xzf go${GOLANG_VERSION}.linux-amd64.tar.gz && \
    ln -s /usr/local/go/bin/go /usr/bin/go && \
    rm go${GOLANG_VERSION}.linux-amd64.tar.gz

# Copiar os arquivos da aplicação
COPY . /app

# Ferramentas externas (ajustável conforme seu recon usa)
# Exemplo: instalar amass, subfinder e httpx via binários
# Instala ferramentas binárias
ENV SKIP_FONTS=1
RUN curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash -s ${TOOLS_DIR} && \
    curl -L https://github.com/owasp-amass/amass/releases/latest/download/amass_linux_amd64.zip -o amass.zip && \
    unzip amass.zip -d /tmp/amass && \
    mv /tmp/amass/amass_Linux_amd64/amass ${TOOLS_DIR}/amass && \
    chmod +x ${TOOLS_DIR}/amass && \
    rm -rf amass.zip /tmp/amass


RUN GOBIN=${TOOLS_DIR} go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    GOBIN=${TOOLS_DIR} go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    GOBIN=${TOOLS_DIR} go install github.com/tomnomnom/assetfinder@latest && \
    GOBIN=${TOOLS_DIR} go install github.com/tomnomnom/anew@latest

# Expõe o diretório de resultados no host se necessário
VOLUME ["/root/Documents/Bugbounty"]

# Configura entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]
