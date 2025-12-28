# 🛡️ The APEX — Plataforma de Segurança com IA

**Aplicação web assíncrona para análise de malware, monitoramento de rede e auditoria do Windows, com relatórios em PDF, integração MITRE ATT&CK® e explicações por IA. Preparada para Docker e implantação simples.**

## Índice
- Descrição
- Módulos
- Funcionalidades
- Tecnologias
- Variáveis de Ambiente
- Execução com Docker
- Execução Local
- Estrutura do Projeto
- Licença

## Descrição
The APEX é uma plataforma integrada de segurança construída em Python/Quart, que consolida:
- Malware Analyzer: análise local e multi-fonte com veredito final e IA.
- Network Monitor: descoberta de dispositivos, portas e serviços.
- Windows Audit: auditoria de hardening, entradas de inicialização e tarefas ocultas.
- Windows Vault: coleta automática das credenciais (Credential Manager) incluída no histórico.
Todos os relatórios suportam exportação em PDF via impressão do relatório.

## Módulos
- Início: visão geral e acesso pelo menu aos módulos.
- Malware Analyzer: análise de arquivos, veredito e Resumo Executivo + Orientações de Remediação.
- Network Monitor: varredura rápida/Completa com tabela de dispositivos e serviços.
- Windows Audit: auditoria com nome da máquina, IP, programas recentes, inicialização, tarefas ocultas e reputação por processo (IA).
- Windows Vault: coleta automática integrada à auditoria e historizada.

## Funcionalidades
- Assíncrono com Quart e chamadas paralelas.
- IA para Resumo Executivo e Remediação, com limitação de tokens e cache.
- MITRE ATT&CK® quando disponível nos backends.
- Exportar PDF nos módulos e página de resultados.
- Histórico de análises com limpeza total via botão.

## Tecnologias
- Backend: Python 3.12, Quart
- Assíncrono: aiohttp
- Servidor: Hypercorn
- Frontend: HTML, CSS, JavaScript
- Banco: SQLite
- Cache de IA: diskcache

## Variáveis de Ambiente
- AI_API_KEY: chave para IA (Groq/Gemini/OpenAI/Grok); detecção automática.
- VT_API_KEY: chave do VirusTotal.
- GOOGLE_SAFE_BROWSING_API_KEY: opcional.
- OSM_API_KEY: opcional para submissão condicionada.

## Execução com Docker
1. Instale Docker Desktop.
2. Na raiz do projeto, execute:
   ```sh
   docker build -t the-apex .
   docker run -d -p 5000:5000 --name the-apex the-apex
   ```
3. Acesse http://localhost:5000 e configure chaves em Configurações.

Para atualizar:
```sh
docker rm -f the-apex
docker build -t the-apex .
docker run -d -p 5000:5000 --name the-apex the-apex
```

## Execução Local (Windows)
```bash
pip install -r requirements.txt
python -m hypercorn "app:create_app()" --bind 127.0.0.1:5000 --reload
```
Acesse http://127.0.0.1:5000.

## Estrutura do Projeto
```
The APEX/
├── app/
│   ├── __init__.py
│   ├── main_routes.py
│   ├── api_routes.py
│   ├── services.py
│   ├── local_analysis.py
│   ├── analysis_backends.py
│   ├── ai_providers.py
│   ├── quart_db.py
│   ├── config.py
│   ├── utils.py
│   ├── static/
│   └── templates/
├── requirements.txt
├── run.py
├── Dockerfile
├── .dockerignore
└── README.md
```

## Licença
MIT.
