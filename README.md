# Deivao-Recon

Primeiro Docker de Recon que compõe a Pipeline automatizada para Bug Bounty utilizando Docker 🐳, Python 🐍 e GO.

Este projeto executa o reconhecimento de subdomínios de forma automatizada, salvando todos os resultados em uma estrutura organizada dentro de `~/Documents/Bugbounty`.

---

## ✨ Funcionalidades

- Reconhecimento de subdomínios com:
  - **Amass**
  - **Subfinder**
  - **Assetfinder**
  - **Anew**
  - **Httpx** (para descobrir quais subdomínios estão ativos)
- Gera relatórios em Markdown, HTML e JSON
- Logging colorido e detalhado com **rich**
- Pipeline Dockerizada: não requer instalação local

---

## 🚀 Começando

### 1. Clone o projeto

```bash
git clone https://github.com/seuusuario/deivao-recon.git
cd deivao-recon
```

### 2. Crie o arquivo `alvos.txt`

No diretório `~/Documents/Bugbounty/alvos.txt`, adicione um alvo por linha:

```txt
exemplo.com
siteinteressante.com
```

### 3. Rode com Docker

```bash
docker compose build
docker compose up
```

---

## 🔍 Resultados

Os resultados serão salvos em:

```
~/Documents/Bugbounty/<domínio>/
├── recon/
│   ├── amass.txt
│   ├── subfinder.txt
│   └── active_subdomains.txt
├── reports/
│   ├── bug_bounty_report_<timestamp>.md
│   ├── ...html / .json (se habilitado)
```

---

## 📃 Exemplo de uso no terminal

```bash
echo "alvo.com" > ~/Documents/Bugbounty/alvos.txt
docker compose up
```

---

## 📁 Estrutura de Diretórios

```text
Deivao-Recon/
├── core/
├── modules/
├── tools/
├── reporting/
├── config/
├── entrypoint.sh
├── main.py
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

---


## ✅ Dependências

As dependências são instaladas automaticamente via Docker:

- Python 3.11
- Golang 1.22
- Amass, Subfinder, Httpx
- rich, markdown, requests

---

## 🚫 Problemas comuns

- Certifique-se que `~/Documents/Bugbounty/alvos.txt` existe
- Verifique se o arquivo está montado corretamente no `docker-compose.yml`

---

## 🎓 Licença

MIT