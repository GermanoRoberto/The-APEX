# -*- coding: utf-8 -*-
"""
Módulo de Funções Utilitárias.

Este módulo fornece funções auxiliares de propósito geral usadas em toda a aplicação.

Boas práticas aplicadas:
- **Coesão:** Agrupa pequenas funções puras e reutilizáveis, como `mask_key`
  e `contains_cyrillic`.
- **Desacoplamento:** As funções aqui têm poucas dependências, tornando-as
  fáceis de testar e reutilizar.
- **Eficiência:** Funções como `extract_strings` são otimizadas para lidar
  com dados binários de forma segura.
"""
import os
import re
import secrets
import logging
import functools
import time
from quart import session

# Importa o objeto de configurações centralizado
from .config import settings

logger = logging.getLogger(__name__)

def log_execution(func):
    """Decorator para logar a execução de funções (início, fim e tempo)."""
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        func_name = func.__name__
        logger.debug(f"⚡ [START] {func_name} iniciado.")
        start_time = time.time()
        try:
            result = await func(*args, **kwargs)
            elapsed = time.time() - start_time
            logger.debug(f"✅ [END] {func_name} concluído em {elapsed:.2f}s.")
            return result
        except Exception as e:
            elapsed = time.time() - start_time
            logger.error(f"❌ [ERROR] {func_name} falhou após {elapsed:.2f}s: {e}")
            raise
    return wrapper

def generate_csrf_token():
    """Gera um token CSRF e o armazena na sessão."""
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']

def validate_csrf_token(token):
    """Valida o token CSRF fornecido contra o da sessão."""
    stored_token = session.get('_csrf_token')
    if not stored_token or not token:
        return False
    return secrets.compare_digest(stored_token, token)

def mask_key(value: str | None) -> str:
    """
    Mascara uma chave de API para exibição segura nos logs e na interface.
    Ex: "CHAVE_LONGA_DE_API" se torna "CHAV..._API"
    """
    if not value or len(value) < 8:
        return "Não definida"
    return f'{value[:4]}...{value[-4:]}'

def contains_cyrillic(text: str) -> bool:
    """Verifica se o texto contém caracteres do alfabeto cirílico."""
    # Faixa de caracteres Unicode para o alfabeto cirílico
    return any('\u0400' <= char <= '\u04FF' for char in text)

def extract_strings(content: bytes, min_len: int = 4, max_output_bytes: int = 8192) -> str:
    """
    Extrai strings de caracteres ASCII imprimíveis de um conteúdo binário.

    Args:
        content: O conteúdo binário (bytes) a ser analisado.
        min_len: O comprimento mínimo de uma sequência de caracteres para ser
                 considerada uma "string".
        max_output_bytes: O número máximo de bytes a serem retornados para
                          evitar sobrecarregar a interface com dados excessivos.

    Returns:
        Uma única string com as strings extraídas separadas por nova linha.
    """
    try:
        # Encontra todas as sequências de bytes imprimíveis (ASCII 32 a 126)
        # com o comprimento mínimo especificado.
        strings = re.findall(rb"[ -~]{%d,}" % min_len, content)
        # Junta as strings encontradas, limita o tamanho total e decodifica,
        # substituindo caracteres inválidos.
        return b'\n'.join(strings)[:max_output_bytes].decode('ascii', errors='replace')
    except Exception:
        return ""

def is_configured() -> bool:
    """
    Verifica se a aplicação parece estar configurada, delegando a verificação
    ao objeto de configurações centralizado.
    """
    return settings.is_configured()

def get_key_status() -> dict:
    """
    Retorna um dicionário com o status mascarado das chaves de API e do provedor de IA.
    Útil para exibir o status de configuração na interface do usuário sem
    expor as chaves reais.
    """
    # Lê as chaves e o provedor detectado do objeto 'settings'
    vt_key = settings.VT_API_KEY
    ai_key = settings.AI_API_KEY

    return {
        'AI_API_KEY': mask_key(ai_key),
        'AI_PROVIDER_DETECTED': settings.AI_PROVIDER_DETECTED or "Nenhum",
        'VT_API_KEY': mask_key(vt_key),
        'OSM_API_KEY': mask_key(settings.OSM_API_KEY),
        'GOOGLE_SAFE_BROWSING_API_KEY': mask_key(settings.GOOGLE_SAFE_BROWSING_API_KEY),
        'ELASTIC_API_KEY': mask_key(settings.ELASTIC_API_KEY),
        'ELASTIC_API_URL': settings.ELASTIC_API_URL or "Não definida",
        'WAZUH_API_KEY': mask_key(settings.WAZUH_API_KEY),
        'WAZUH_API_URL': settings.WAZUH_API_URL or "Não definida",
        'all_set': bool(vt_key and ai_key)
    }

def save_env_file(env_path: str, new_vars: dict) -> bool:
    """
    Salva variáveis no arquivo .env preservando o conteúdo existente (comentários, etc).
    Substitui valores existentes e adiciona novos ao final se não existirem.
    """
    try:
        # Lê o conteúdo atual
        if os.path.exists(env_path):
            with open(env_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        else:
            lines = []

        updated_keys = set()
        new_lines = []

        # Regex para identificar atribuições de variáveis (ex: CHAVE=VALOR ou CHAVE="VALOR")
        # Captura: 1=KEY, 2=Quote?, 3=VALUE, 4=Quote?
        env_pattern = re.compile(r'^([A-Z_][A-Z0-9_]*)\s*=\s*(["\']?)(.*?)(\2)\s*$')

        for line in lines:
            match = env_pattern.match(line.strip())
            if match:
                key = match.group(1)
                if key in new_vars:
                    # Substitui a linha com o novo valor
                    val = new_vars[key]
                    # Adiciona aspas se tiver espaço
                    if ' ' in val and not (val.startswith('"') and val.endswith('"')):
                        val = f'"{val}"'
                    new_lines.append(f'{key}={val}\n')
                    updated_keys.add(key)
                else:
                    # Mantém a linha original
                    new_lines.append(line)
            else:
                # Mantém comentários e linhas em branco
                new_lines.append(line)

        # Adiciona variáveis que não existiam no arquivo
        if new_lines and not new_lines[-1].endswith('\n'):
            new_lines[-1] += '\n'
            
        for key, val in new_vars.items():
            if key not in updated_keys:
                if ' ' in val and not (val.startswith('"') and val.endswith('"')):
                    val = f'"{val}"'
                new_lines.append(f'{key}={val}\n')

        # Escreve de volta
        with open(env_path, 'w', encoding='utf-8') as f:
            f.writelines(new_lines)
            
        return True
    except IOError as e:
        print(f"Erro ao escrever no arquivo .env: {e}")
        return False

def get_mitre_attack_info(analysis_result: dict) -> list:
    """
    Extrai informações do MITRE ATT&CK do resultado da análise consolidada.
    """
    # A informação do MITRE ATT&CK é primariamente obtida do backend do VirusTotal.
    vt_results = analysis_result.get('external', {}).get('virustotal', {})
    
    if vt_results and 'mitre_attack' in vt_results and vt_results['mitre_attack']:
        return vt_results['mitre_attack']
        
    # Fallback ou lógica adicional pode ser adicionada aqui se outras fontes
    # também fornecerem dados do MITRE.
    return []
