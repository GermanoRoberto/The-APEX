# 🛡️ The APEX — Plataforma de Segurança com IA (v1.0)

The APEX é uma plataforma integrada de segurança cibernética de alta performance, projetada para consolidar análise de ameaças, monitoramento de ativos e inteligência nacional em uma única interface moderna e totalmente assíncrona. Utilizando o que há de mais avançado em IA (Groq, Gemini, OpenAI) e integrações com fontes oficiais (CTIR Gov), o APEX transforma dados brutos de segurança em insights estratégicos acionáveis.

<img width="1883" height="902" alt="Captura de tela 2025-12-29 135211" src="https://github.com/user-attachments/assets/502ba01d-8118-4618-9102-344f6fae68b2" />

<img width="1914" height="904" alt="Captura de tela 2025-12-29 135300" src="https://github.com/user-attachments/assets/635ccd22-0289-400e-bf3c-2a27f8034549" />

## Descrição
The APEX é uma plataforma integrada de segurança construída em Python/Quart, que consolida:
- Malware Analyzer: análise local e multi-fonte com veredito final e IA.
- Network Monitor: descoberta de dispositivos, portas e serviços.
- Windows Vault Audit: Auditoria de credenciais do sistema em busca de riscos.
- Threat Intelligence: Alertas de ameaças nacionais via CTIR Gov com interpretação por IA.
- SIEM Integration: Exportação automática de logs e alertas para Elastic Stack.

## Módulos
- Início: visão geral e acesso pelo menu aos módulos.
- Malware Analyzer: análise de arquivos e URLs com veredito, Resumo Executivo + Orientações de Remediação.
- Network Monitor: varredura rápida/Completa com tabela de dispositivos e serviços.
- Auditoria de Sistema (Vault): Varredura de credenciais salvas no Windows para identificar exposições.
- Alertas Brasil: Monitoramento de tendências de ameaças nacionais com integração direta ao CTIR Gov (Gabinete de Segurança Institucional da Presidência da República), focando nos 5 alertas mais recentes e interpretação inteligente por IA.
- Configurações: Central de chaves de API e conexões SIEM.

## Funcionalidades
- Assíncrono com Quart e chamadas paralelas.
- IA Multi-Provider: Suporte dinâmico para Groq, Gemini, OpenAI e xAI (Grok).
- SIEM Ready: Integração nativa com Elastic Stack (via API).
- Otimização de Tokens: Pruning de dados e truncamento inteligente para evitar limites de API (Rate Limits).
- Cache Inteligente: Respostas de IA cacheadas para economizar tokens em análises repetidas.
- MITRE ATT&CK®: Mapeamento automático de táticas e técnicas em todas as análises.
- Scraping de Fontes Oficiais: Integração nativa com o portal de alertas do CTIR Gov para inteligência de ameaças brasileira.
- Cache Buster: Mecanismo de atualização forçada no frontend para garantir dados em tempo real sem dependência de cache de navegador.
- Docker-Compose Full: Inclui stack completa de Elastic (Elasticsearch + Kibana).
- Histórico de análises com limpeza total via botão.
- News diárias de Cybersecurity na barra lateral (CaveiraTech) com cache e fallback.
- Página Início com guia de uso rápido; FAQ com instruções de chaves (Groq recomendado).

✨ Módulos e Funcionalidades

### 🦠 Malware Analyzer (Módulo de Segurança Ativa)
*   **Análise Multi-Fonte:** Integração paralela com VirusTotal, Google Safe Browsing e OpenSourceMalware.com.
*   **Resumo Executivo com IA:** Gera relatórios claros com vereditos (Limpo, Suspeito, Malicioso) e orientações de remediação personalizadas.
*   **Mapeamento MITRE ATT&CK®:** Identifica automaticamente táticas e técnicas de adversários em cada análise.
*   **Análise Local:** Detecção de anomalias em arquivos PE, strings suspeitas e padrões de phishing (homógrafos).

### 🌐 Network Monitor (Monitoramento de Ativos)
*   **Descoberta de Dispositivos:** Varredura rápida de rede para identificar hosts ativos.
*   **Detecção de Serviços:** Identificação de portas abertas e serviços em execução (Banner Grabbing).
*   **Visão de Risco:** Classificação de ativos com base na exposição de serviços.

### 🔐 Windows Vault Audit (Auditoria de Sistema)
*   **Verificação de Credenciais:** Auditoria automatizada do cofre do Windows para identificar senhas salvas e potenciais exposições.
*   **Relatório de Risco:** Identifica credenciais que podem ser abusadas em ataques de movimento lateral.

### 🇧🇷 Alertas Brasil (Inteligência de Ameaças)
*   **Integração CTIR Gov:** Scraping em tempo real do portal oficial de alertas de segurança nacional do Gabinete de Segurança Institucional da Presidência da República.
*   **Foco Estratégico:** Exibição dos 5 alertas mais recentes e críticos.
*   **Interpretação Inteligente:** A IA resume e contextualiza os alertas técnicos para facilitar a tomada de decisão.

### 📊 Integração SIEM/SOAR
*   **Pronto para Produção:** Exportação automática de logs e alertas para Elastic Stack (Elasticsearch/Kibana).
*   **Central de Monitoramento:** Facilita a centralização de eventos gerados pelo APEX em grandes infraestruturas.

💻 Tecnologias Utilizadas
*   **Backend:** Python 3.12+, Quart (Framework assíncrono de alta performance)
*   **Servidor Web:** Hypercorn (Protocolos HTTP/2 e HTTP/3 prontos)
*   **Processamento Assíncrono:** aiohttp, asyncio
*   **Inteligência Artificial:** Groq (Llama-3), Google Gemini, OpenAI (GPT-4), xAI (Grok)
*   **Banco de Dados:** SQLite (com gerenciamento de contexto assíncrono)
*   **Frontend:** Interface moderna com glassmorphism, Dark Mode nativo, e JavaScript Vanilla.
*   **Cache:** Diskcache para otimização de tokens de IA e performance de rede.

🔧 Instalação e Configuração

### Pré-requisitos
*   Git para clonagem.
*   Docker & Docker Desktop (Recomendado) ou Python 3.12+.

### Opção 1: Execução com Docker (Recomendado)
Este método garante que todas as dependências e a stack de rede estejam configuradas corretamente.
1. Clone o repositório: `git clone https://github.com/GermanoRoberto/The-APEX.git`
2. Na raiz do projeto, execute:
   ```bash
   docker build -t the-apex .
   docker run -d -p 5000:5000 --name the-apex the-apex
   ```
3. Acesse `http://localhost:5000`.

### Opção 2: Execução Local (Windows/Linux)
1. Instale as dependências:
   ```bash
   pip install -r requirements.txt
   ```
2. Inicie a aplicação:
   ```bash
   python -m hypercorn "app:create_app()" --bind 127.0.0.1:5000 --reload
   ```
3. Acesse `http://127.0.0.1:5000`.

🔑 Configuração das Chaves de API
O APEX é uma plataforma "bring your own key". Ao acessar a página de **Configurações**, você poderá inserir:
*   **Chave de IA (Obrigatória):** Groq (recomendada pela velocidade), Gemini ou OpenAI. A plataforma detecta o provedor automaticamente.
*   **VirusTotal API:** Essencial para o módulo Malware Analyzer.
*   **Google Safe Browsing:** Para verificação avançada de URLs.
*   **SIEM Configs:** Endereços e chaves para Elastic e Wazuh.

🚀 Como Usar
1.  **Configuração Inicial:** Insira suas chaves na aba Configurações.
2.  **Análise de Malware:** Faça upload de um arquivo ou cole uma URL na tela principal.
3.  **Monitoramento de Rede:** Vá em Network Monitor e inicie uma varredura para conhecer seus ativos.
4.  **Acompanhamento Nacional:** Verifique a aba Alertas Brasil para saber o que está acontecendo no cenário de segurança nacional.
5.  **Dashboard:** Acompanhe as notícias de cybersecurity em tempo real na barra lateral.

📁 Estrutura do Projeto
```
The APEX/
├── app/
│   ├── ai_providers.py      # Lógica de integração com múltiplos modelos de IA
│   ├── analysis_backends.py # Motores de análise externa (VT, SafeBrowsing)
│   ├── api_routes.py        # Endpoints de API assíncronos
│   ├── local_analysis.py    # Motores de análise estática local
│   ├── main_routes.py       # Rotas de interface web
│   ├── quart_db.py          # Gerenciamento de banco de dados SQLite
│   ├── services.py          # Lógica de negócio e correlação
│   ├── static/              # Estilos (CSS) e scripts (JS)
│   └── templates/           # Templates Jinja2
├── Dockerfile               # Configuração de containerização
├── requirements.txt         # Dependências do projeto
└── run.py                   # Ponto de entrada da aplicação
```

📄 Licença
Distribuído sob a licença MIT. Veja `LICENSE` para mais informações.

---
Desenvolvido por [Germano Roberto](https://github.com/GermanoRoberto) - Foco em Segurança Cibernética e Inteligência Artificial.
