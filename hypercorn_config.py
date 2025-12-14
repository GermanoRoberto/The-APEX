"""
Arquivo de Configuração Programático para o Hypercorn.

Isto permite uma configuração mais limpa e extensível do servidor,
separando as preocupações do servidor das do código da aplicação.
"""
import os

# --- Configuração de Rede ---
host = os.environ.get("APP_HOST", "127.0.0.1")
port = os.environ.get("APP_PORT", "5000")
bind = [f"{host}:{port}"]

# --- Configuração do Reloader (Recarregador Automático) ---
# Habilita o reloader por padrão em ambiente de desenvolvimento.
use_reloader = os.environ.get("APP_RELOAD", "true").lower() in ("true", "1", "t")

# --- CORREÇÃO DEFINITIVA PARA O LOOP DE RELOAD ---
# Exclui explicitamente o diretório 'instance' e quaisquer arquivos de banco de dados
# SQLite de serem monitorados pelo reloader. Isso impede que a criação ou
# modificação do banco de dados acione um reinício do servidor.
reload_exclude_patterns = ["instance/*", "*.sqlite", "*.db"]
