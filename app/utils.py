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

# Importa o objeto de configurações centralizado
from .config import settings

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
        'all_set': bool(vt_key and ai_key)
    }

def save_env_file(env_path: str, new_vars: dict) -> bool:
    """
    Salva um dicionário de variáveis de ambiente em um arquivo .env.
    Esta função sobrescreve o arquivo existente.

    Args:
        env_path: O caminho para o arquivo .env.
        new_vars: Um dicionário com as variáveis a serem salvas.

    Returns:
        True se o arquivo foi salvo com sucesso, False caso contrário.
    """
    try:
        with open(env_path, 'w') as f:
            for key, value in new_vars.items():
                # Garante que valores com espaços sejam envoltos em aspas
                if ' ' in value and not (value.startswith('"') and value.endswith('"')):
                    f.write(f'{key}="{value}"\n')
                else:
                    f.write(f'{key}={value}\n')
        return True
    except IOError as e:
        # Em um cenário real, um log mais detalhado seria preferível
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
