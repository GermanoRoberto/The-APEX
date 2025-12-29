# 🛡️ The APEX — Plataforma de Segurança com IA

**Aplicação web assíncrona para análise de malware e monitoramento de rede, com integração MITRE ATT&CK® e explicações por IA. Preparada para Docker e implantação simples.**

<img width="1883" height="901" alt="Captura de tela 2025-12-29 094713" src="https://github.com/user-attachments/assets/1c4b8720-23a6-4f59-8f6d-f1de834e770d" />


## Índice
- Descrição
- Módulos
- Funcionalidades
- Tecnologias
- Variáveis de Ambiente
- Execução com Docker
- Execução Local
- Estrutura do Projeto
- Limitações Conhecidas
- Licença

## Descrição
The APEX é uma plataforma integrada de segurança construída em Python/Quart, que consolida:
- Malware Analyzer: análise local e multi-fonte com veredito final e IA.
- Network Monitor: descoberta de dispositivos, portas e serviços.
- Windows Vault Audit: Auditoria de credenciais do sistema em busca de riscos.
- Threat Intelligence: Alertas de ameaças focados no Brasil com interpretação por IA.
- SIEM Integration: Exportação automática de logs e alertas para Elastic Stack e Wazuh.

## Módulos
- Início: visão geral e acesso pelo menu aos módulos.
- Malware Analyzer: análise de arquivos e URLs com veredito, Resumo Executivo + Orientações de Remediação.
- Network Monitor: varredura rápida/Completa com tabela de dispositivos e serviços.
- Auditoria de Sistema (Vault): Varredura de credenciais salvas no Windows para identificar exposições.
- Alertas Brasil: Monitoramento de tendências de ameaças locais.
- Configurações: Central de chaves de API e conexões SIEM.

## Funcionalidades
- Assíncrono com Quart e chamadas paralelas.
- IA Multi-Provider: Suporte dinâmico para Groq, Gemini, OpenAI e xAI (Grok).
- SIEM Ready: Integração nativa com Elastic Stack (via API) e Wazuh (preparado para Syslog/API).
- Otimização de Tokens: Pruning de dados e truncamento inteligente para evitar limites de API (Rate Limits).
- Cache Inteligente: Respostas de IA cacheadas para economizar tokens em análises repetidas.
- MITRE ATT&CK®: Mapeamento automático de táticas e técnicas em todas as análises.
- Docker-Compose Full: Inclui stack completa de Elastic (Elasticsearch + Kibana) e Wazuh (Manager + Dashboard).
- Histórico de análises com limpeza total via botão.
- News diárias de Cybersecurity na barra lateral (CaveiraTech) com cache e fallback.
- Página Início com guia de uso rápido; FAQ com instruções de chaves (Groq recomendado).

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

## Limitações Conhecidas
- Exportação de PDF está desativada no momento (opção removida da UI).

## Licença
MIT.
