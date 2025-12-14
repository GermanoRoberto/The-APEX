# 🛡️ Analisador de Ameaças com IA (v3.2)

**O Analisador de Ameaças é uma ferramenta web moderna e assíncrona para análise de arquivos e URLs suspeitas, utilizando IA (Gemini, Groq, etc.) e múltiplas fontes de inteligência para transformar dados complexos em insights de segurança claros e acionáveis.**

---

## 🧭 Índice

* [Descrição](#-descrição)
* [Funcionalidades](#-funcionalidades)
* [Tecnologias Utilizadas](#-tecnologias-utilizadas)
* [Começando: Instalação e Configuração](#-começando-instalação-e-configuração)
    * [Pré-requisitos](#-pré-requisitos)
    * [Configuração das Chaves de API](#-configuração-das-chaves-de-api)
* [Como Usar](#-como-usar)
* [Estrutura do Projeto](#-estrutura-do-projeto-simplificada)
* [Licença](#-licença)
* [Contribuição](#-contribuição)
* [Histórico de Versões](#-histórico-de-versões)

---

## 📖 Descrição

O **Analisador de Ameaças** é uma ferramenta web de alta performance construída com Python e Quart, projetada para ser totalmente assíncrona. Ela permite a análise de arquivos e URLs suspeitas utilizando múltiplas fontes de inteligência de ameaças, como VirusTotal e Google Safe Browsing, e apresenta um relatório detalhado com vereditos de segurança, pontuações de risco e explicações geradas por IA, com foco em detecção de comportamento malicioso e padrões de phishing.

## ✨ Funcionalidades

*   **Motor Assíncrono:** Construído com **Quart** e **aiohttp**, garantindo alta performance e capacidade de resposta ao lidar com múltiplas requisições de API simultaneamente.
*   **Análise Multi-Fonte:** Analisa arquivos e URLs usando múltiplas APIs em paralelo.
    *   **Análise de Arquivos:** Faz upload de arquivos para análise de hash (SHA256) no VirusTotal.
    *   **Análise de URLs:** Verifica URLs no VirusTotal e no Google Safe Browsing.
*   **Suporte a Múltiplos Provedores de IA:**
    *   Compatível com **Google Gemini, Groq, OpenAI (GPT), e Grok (xAI)**.
    *   **Detecção Automática:** Basta colar qualquer uma das chaves suportadas, e a aplicação detecta o provedor automaticamente.
*   **Análise Local Inteligente:**
    *   **Análise Estática:** Realiza uma análise inicial segura do arquivo (tipo, strings) antes de consultas externas.
    *   **Detecção de Phishing:** Identifica e alerta sobre URLs com caracteres cirílicos (ataque de homógrafo).
    *   **Detecção de Conteúdo Sensível:** Identifica URLs relacionadas a apostas e pornografia, sugerindo ao usuário a busca por ajuda especializada.
*   **Integração com MITRE ATT&CK®:**
    *   Apresenta informações sobre táticas e técnicas do MITRE ATT&CK® associadas à análise.
    *   A **IA explica o significado** das táticas e técnicas encontradas no contexto da análise.
*   **Veredito Consolidado:** Combina os resultados para calcular um veredito final (`Limpo`, `Suspeito`, `Malicioso`).
*   **Interface Web Moderna:** Interface clara e responsiva para upload, análise e visualização de resultados, incluindo um histórico de análises.
*   **Pronto para Contêineres:** Configuração completa com **Docker** e **Docker Compose** para um ambiente de desenvolvimento isolado e reproduzível.

## 💻 Tecnologias Utilizadas

*   **Backend:** Python 3.x, **Quart** (framework web assíncrono)
*   **Requisições Assíncronas:** **aiohttp**
*   **Tarefas em Background:** **Celery**, **Redis**
*   **Containerização:** **Docker**, **Docker Compose**
*   **APIs de Inteligência de Ameaças:**
    *   VirusTotal API v3, Google Safe Browsing API v4
*   **APIs de Inteligência Artificial:**
    *   Google Gemini, Groq, OpenAI, xAI (Grok)
*   **Frontend:** HTML, Bootstrap 5, JavaScript
*   **Gerenciamento de Dependências:** `pip`
*   **Variáveis de Ambiente:** `python-dotenv`

## 🔧 Instalação e Configuração

### Pré-requisitos
*   **Git:** Para clonar o repositório.
*   **Python 3.8+:** Necessário para a execução local.
*   **Docker Desktop:** **Recomendado** para a execução mais simples e isolada.

### 🔑 Configuração das Chaves de API
A aplicação requer chaves de API para funcionar. Ao iniciar pela primeira vez (ou ao acessar a página `/setup`), você poderá inserir suas chaves.

1.  **Chave de IA (Obrigatória):**
    *   Obtenha uma chave de um dos provedores suportados (Gemini, Groq, OpenAI).
    *   Cole a chave no campo "Chave da API de IA". A aplicação detectará o provedor automaticamente.
2.  **Chave do VirusTotal (Obrigatória):**
    *   Obtenha sua chave em [VirusTotal](https://www.virustotal.com/gui/join-us).
3.  **Outras Chaves (Opcional):**
    *   Google Safe Browsing e OpenSourceMalware.com são recomendadas para uma análise mais completa.

As chaves são salvas de forma segura em um arquivo `.env` na raiz do projeto.

## 🚀 Como Usar

### Opção 1: Execução com Docker (Recomendado)
Este método garante um ambiente de desenvolvimento consistente e isolado.

1.  Abra um terminal na pasta raiz do projeto.
2.  Certifique-se de que o Docker Desktop está em execução.
3.  Execute o comando:
    ```sh
    docker-compose up -d --build
    ```
4.  Acesse a aplicação em **`http://localhost:5000`**.
5.  Na primeira execução, configure suas chaves de API na página de Configurações.

Para parar a aplicação, execute `docker-compose down`.

### Opção 2: Execução Local (Windows)
Para desenvolvimento rápido no Windows.

1.  Instale as dependências:
    ```bash
    pip install -r requirements.txt
    ```
2.  Dê um duplo clique no arquivo `iniciar.bat`.
3.  O script criará o ambiente virtual, instalará as dependências e iniciará o servidor.
4.  Acesse **`http://localhost:5000`** e configure suas chaves de API.


## 📁 Estrutura do Projeto (Simplificada)

A arquitetura do projeto foi refatorada para seguir as melhores práticas, com uma clara separação de responsabilidades.

```
Analisador-de-Malware/
│
├── app/
│   ├── __init__.py            # Inicializador da aplicação Quart (Application Factory)
│   ├── main_routes.py         # Rotas da interface web (páginas HTML)
│   ├── api_routes.py          # Rotas da API RESTful (endpoints /api/...)
│   │
│   ├── services.py            # Camada de Serviço: Orquestra a lógica de negócio
│   ├── local_analysis.py      # Funções para análise estática local
│   ├── analysis_backends.py   # Módulos para interagir com APIs externas (VirusTotal, etc.)
│   ├── ai_providers.py        # Módulos para interagir com APIs de IA (Gemini, Groq, etc.)
│   │
│   ├── quart_db.py            # Funções para interação com o banco de dados (SQLite)
│   ├── config.py              # Carrega e gerencia as configurações da aplicação
│   ├── utils.py               # Funções utilitárias
│   │
│   ├── static/                # Arquivos estáticos (CSS, JavaScript)
│   └── templates/             # Templates HTML (Jinja2)
│
├── .env.example               # Exemplo de arquivo de configuração
├── requirements.txt           # Dependências do projeto
│
├── run.py                     # Ponto de entrada principal da aplicação
├── iniciar.bat                # Script de inicialização para Windows
├── docker-compose.yml         # Configuração para execução com Docker
├── Dockerfile                 # Define a imagem Docker da aplicação
├── README.md                  # Este arquivo
└── LICENSE                    # Licença do projeto
```

## 📜 Licença

Este projeto está licenciado sob a licença MIT. Veja o arquivo `LICENSE` para mais detalhes.

## 🤝 Contribuição

Contribuições são bem-vindas! Sinta-se à vontade para abrir issues, propor melhorias ou enviar pull requests.

## 📝 Histórico de Versões

### **Versão 3.2 (Atual)**
Esta versão representa uma refatoração massiva com foco em performance, novas funcionalidades e saúde do código.

*   **Arquitetura & Performance:**
    *   **Migração para Assíncrono:** O core da aplicação foi migrado de Flask para **Quart**, tornando a aplicação totalmente assíncrona e mais performática.
    *   **Requisições Paralelas:** Substituição de `requests` por `aiohttp` para chamadas de API não-bloqueantes.
*   **Novas Funcionalidades:**
    *   **Análise de Conteúdo Sensível:** O sistema agora detecta URLs relacionadas a apostas e pornografia, orientando o usuário a procurar ajuda.
    *   **Inteligência sobre MITRE ATT&CK®:** A IA agora analisa e explica as táticas e técnicas do MITRE ATT&CK® encontradas.
    *   **Auto-preenchimento de URL:** URLs inseridas sem `http://` ou `https://` são corrigidas automaticamente.
*   **Melhorias de UI/UX:**
    *   Removido o dropdown de seleção de provedor de IA, que agora é detectado automaticamente.
    *   Aumentado o limite padrão de tamanho de arquivo para 100 MB.
    *   Páginas de "Histórico" e "FAQ" implementadas.
    *   Consistência visual melhorada nos componentes da interface.
*   **Correções de Bugs e Refatoração:**
    *   Corrigido `TypeError` na formatação de datas no template de resultados.
    *   Corrigido `BuildError` na geração de links na página de histórico.
    *   **Limpeza massiva de código:** Remoção de 9 arquivos obsoletos (`.py`, `.css`, `.js`, `.html`).
    *   Corrigido aviso de `version` obsoleta no `docker-compose.yml`.

### Versões Anteriores (Compilado)
*   **v3.0/v3.1:** Foco em integração com MITRE ATT&CK, análise de comportamento de sandbox e melhorias na lógica de pontuação e prompts de IA. Incluiu também a detecção de ataques de homógrafo.
*   **v2.0.0:** Foco em estabilidade, com melhorias no polling de resultados e tratamento de erros.
