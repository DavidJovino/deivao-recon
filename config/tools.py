"""
Definições de ferramentas para a pipeline de Bug Bounty.
Contém informações sobre todas as ferramentas utilizadas, incluindo:
- Comando para execução
- Método de instalação
- Dependências
- Módulos que utilizam a ferramenta
- Alternativas disponíveis
"""

# Definição de todas as ferramentas utilizadas na pipeline
TOOLS = {
    # Ferramentas de reconhecimento de subdomínios
    "amass": {
        "command": "amass",
        "package": "github.com/owasp-amass/amass/v3/...",
        "install_method": "go",
        "required_for": ["recon"],
        "alternatives": ["subfinder", "assetfinder"],
        "description": "Ferramenta de reconhecimento de subdomínios"
    },
    "subfinder": {
        "command": "subfinder",
        "package": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder",
        "install_method": "go",
        "required_for": ["recon"],
        "alternatives": ["amass", "assetfinder"],
        "description": "Ferramenta de descoberta passiva de subdomínios"
    },
    "assetfinder": {
        "command": "assetfinder",
        "package": "github.com/tomnomnom/assetfinder",
        "install_method": "go",
        "required_for": ["recon"],
        "alternatives": ["amass", "subfinder"],
        "description": "Ferramenta para encontrar domínios e subdomínios relacionados"
    },
    "anew": {
        "command": "anew",
        "package": "github.com/tomnomnom/anew",
        "install_method": "go",
        "required_for": ["recon", "enum"],
        "alternatives": [],
        "description": "Ferramenta para adicionar linhas de um arquivo a outro, apenas se forem novas"
    },
    
    # Ferramentas de enumeração de endpoints
    "httpx": {
        "command": "httpx",
        "package": "github.com/projectdiscovery/httpx/cmd/httpx",
        "install_method": "go",
        "required_for": ["enum", "specific"],
        "alternatives": [],
        "description": "Ferramenta para probing de HTTP"
    },
}

# Ferramentas essenciais que devem estar presentes para o funcionamento básico
ESSENTIAL_TOOLS = ["curl", "wget", "git", "python3", "pip3"]

# Dependências do sistema que podem ser necessárias
SYSTEM_DEPENDENCIES = {
    "apt": [
        "git", "python3", "python3-pip", "golang", "ruby", "ruby-dev", 
        "nmap", "masscan", "whois", "nikto", "dirb", "sqlmap", "hydra", 
        "wfuzz", "curl", "wget", "zip", "unzip", "jq", "build-essential", 
        "libssl-dev", "libffi-dev", "python3-dev", "chromium-browser"
    ]
}

# Dependências Python que serão instaladas automaticamente
PYTHON_DEPENDENCIES = [
    "requests", "beautifulsoup4", "colorama", "tqdm", "argparse", 
    "pyyaml", "jinja2", "markdown", "python-dateutil"
]

# Mapeamento de módulos para ferramentas necessárias
MODULE_TOOLS = {
    "recon": ["amass", "subfinder", "assetfinder", "anew", "httpx"],
    "enum": ["httpx", "katana", "hakrawler", "waybackurls", "gau", "ffuf", "feroxbuster"],
    "scan": ["nuclei", "naabu", "sqlmap", "nikto", "dalfox", "xsstrike"],
    "specific": ["curl", "jq", "httpx", "ffuf", "unfurl", "xxeinjector", "xsrfprobe"]
}

# Função para obter ferramentas necessárias para um módulo
def get_tools_for_module(module_name):
    """
    Retorna a lista de ferramentas necessárias para um módulo específico.
    
    Args:
        module_name (str): Nome do módulo
        
    Returns:
        list: Lista de ferramentas necessárias
    """
    if module_name in MODULE_TOOLS:
        return MODULE_TOOLS[module_name]
    elif module_name == "all":
        # Combinar todas as ferramentas de todos os módulos
        all_tools = []
        for tools in MODULE_TOOLS.values():
            all_tools.extend(tools)
        return list(set(all_tools))  # Remover duplicatas
    else:
        return []

# Função para obter alternativas para uma ferramenta
def get_alternatives(tool_name):
    """
    Retorna as alternativas disponíveis para uma ferramenta.
    
    Args:
        tool_name (str): Nome da ferramenta
        
    Returns:
        list: Lista de ferramentas alternativas
    """
    if tool_name in TOOLS and "alternatives" in TOOLS[tool_name]:
        return TOOLS[tool_name]["alternatives"]
    return []

# Função para verificar se uma ferramenta requer tratamento especial
def requires_special_handling(tool_name):
    """
    Verifica se uma ferramenta requer tratamento especial.
    
    Args:
        tool_name (str): Nome da ferramenta
        
    Returns:
        bool: True se a ferramenta requer tratamento especial, False caso contrário
    """
    if tool_name in TOOLS and "special_handling" in TOOLS[tool_name]:
        return TOOLS[tool_name]["special_handling"]
    return False
