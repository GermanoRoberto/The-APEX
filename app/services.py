# -*- coding: utf-8 -*-
import re
from dotenv import dotenv_values
"""
Módulo de Serviços de Negócio.

Este módulo atua como a camada de serviço (Service Layer) da aplicação. Ele
orquestra as diferentes partes do sistema (backends de análise, banco de dados,
análise local) para executar as funcionalidades principais.

Boas práticas aplicadas:
- **Separação de Responsabilidades (SoC):** Isola a lógica de negócio das
  camadas de apresentação (rotas) e de acesso a dados (backends), tornando o
  código mais organizado e testável.
- **Orquestração:** Funções como `run_file_analysis` gerenciam o fluxo completo
  de uma operação, desde a análise inicial até a persistência do resultado.
- **Concorrência:** Utiliza threads para executar as chamadas às APIs externas
  em paralelo, melhorando significativamente a performance das análises.
- **Centralização de Lógica:** A lógica de atualização de configurações, antes
  espalhada pelas rotas, agora está centralizada em `update_settings`.
"""
import logging
import threading
import json
import os
import requests
import asyncio
import tiktoken
import hashlib
import uuid
import tempfile
from diskcache import Cache
from typing import Dict, Any, List, Tuple

# Importações refatoradas
from .config import settings
from . import quart_db as database
from . import local_analysis
from . import utils
from .analysis_backends import get_file_analysis_backends, get_url_analysis_backends, submit_osm_report
from .ai_providers import get_ai_provider, detect_provider, osm_validate_key, google_safe_browsing_validate_key

logger = logging.getLogger(__name__)

class AIProviderError(Exception):
    """Exceção personalizada para erros relacionados aos provedores de IA."""
    pass

# Inicializa o cache em disco para as respostas da IA.
# Isso cria uma pasta '.ai_cache' para armazenar os resultados.
ai_cache = Cache(".ai_cache")

CONTEXT_LIMITS = {
    'gemini-1.5-flash': 1000000,
    'llama3-70b-8192': 8000,
    'grok-beta': 128000,
}
DEFAULT_CONTEXT_LIMIT = 7500

def _truncate_prompt_by_tokens(prompt: str, model_name: str) -> str:
    """
    Trunca um prompt para garantir que ele se ajuste ao limite de contexto de um modelo.
    Usa a biblioteca tiktoken para uma contagem precisa de tokens.
    """
    limit = CONTEXT_LIMITS.get(model_name, DEFAULT_CONTEXT_LIMIT)
    
    # Otimização (Big O): Reduz O(N) para O(1) em casos de strings gigantes.
    # Heurística: 1 token ~= 4 caracteres. Se a string for muito maior que o limite,
    # cortamos antes de passar para o tiktoken (que é custoso).
    estimated_char_limit = limit * 6  # Margem de segurança generosa
    if len(prompt) > estimated_char_limit:
        prompt = prompt[:estimated_char_limit]

    try:
        encoding = tiktoken.get_encoding("cl100k_base")
        tokens = encoding.encode(prompt)
        
        if len(tokens) > limit:
            logger.warning(f"Prompt com {len(tokens)} tokens excedeu o limite de {limit} para o modelo {model_name}. Truncando...")
            truncated_tokens = tokens[:limit]
            return encoding.decode(truncated_tokens, errors='ignore')
        
        return prompt
        
    except Exception as e:
        logger.error(f"Erro ao usar tiktoken: {e}. Usando fallback de contagem de caracteres.")
        char_limit = limit * 3
        if len(prompt) > char_limit:
            logger.warning(f"Prompt com {len(prompt)} caracteres excedeu o limite estimado. Truncando...")
            return prompt[:char_limit]
        return prompt


# --- LÓGICA DE ORQUESTRAÇÃO DE ANÁLISE ---

# --- ASYNCHRONOUS LÓGICA DE ORQUESTRAÇÃO DE ANÁLISE ---

async def run_file_analysis(content: bytes, filename: str, ai_provider: str = None) -> str:
    """
    Orquestra a análise completa de um arquivo de forma assíncrona.
    """
    logger.info(f"Iniciando análise para o arquivo: {filename}")

    # 1. Análise Estática Local
    # Executa em thread separada pois hashing e análise de bytes são CPU-bound e bloqueiam o loop async
    local_result = await asyncio.to_thread(local_analysis.analyze_bytes, content, filename)
    
    sha256 = local_result.get('sha256')
    if not sha256:
        raise ValueError("Não foi possível calcular o hash SHA256 do arquivo.")

    # 2. Análise Externa em Paralelo com asyncio.gather
    file_backends = get_file_analysis_backends()
    tasks = [backend.analyze_file(sha256, content, filename) for backend in file_backends]
    external_results_list = await asyncio.gather(*tasks)
    
    # Mapeia os resultados de volta para um dicionário
    external_results = {backend.name: result for backend, result in zip(file_backends, external_results_list)}

    # 3. Consolidação e Veredito Final
    final_result = local_result
    final_result['external'] = external_results
    final_result['final_verdict'] = local_analysis.calculate_final_verdict(
        local_result.get('verdict'), external_results
    )

    # 3.1. Submissão Condicional ao OpenSourceMalware
    if final_result['final_verdict'] == 'malicious' and settings.OSM_API_KEY:
        logger.info(f"Veredito malicioso. Submetendo hash {sha256} para o OpenSourceMalware.com.")
        submission_result = await submit_osm_report(
            sha256=sha256,
            api_key=settings.OSM_API_KEY,
            threat_description="Hash identificado como malicioso pela ferramenta de análise automatizada."
        )
        # Atualiza o resultado no dicionário 'external'
        if 'opensource_malware' in final_result['external']:
            final_result['external']['opensource_malware'].update(submission_result)
        else:
            final_result['external']['opensource_malware'] = submission_result


    # 4. Análise MITRE ATT&CK
    final_result['mitre_attack'] = utils.get_mitre_attack_info(final_result)

    # 5. Análise com IA
    # Executa em thread separada para não bloquear o loop de eventos do Quart
    final_result['ai_analysis'] = await asyncio.to_thread(get_ai_explanation, final_result, ai_provider)

    # 6. Persistência
    # Executa em thread separada se o driver de banco de dados for síncrono (sqlite3 padrão)
    result_id = await asyncio.to_thread(database.save_analysis, final_result)
    logger.info(f"Análise concluída para {filename}. ID do resultado: {result_id}")
    return result_id

def enqueue_file_analysis(content: bytes, filename: str, ai_provider: str = None) -> str:
    """
    Salva o arquivo em disco e enfileira a análise no Celery (Redis).
    Retorna o ID da Tarefa (Task ID) para monitoramento, não o resultado final.
    """
    # 1. Salvar arquivo temporariamente
    # Não passamos 'content' (bytes) para o Celery/Redis para economizar memória do broker.
    temp_dir = tempfile.gettempdir()
    unique_name = f"{uuid.uuid4()}_{filename}"
    temp_path = os.path.join(temp_dir, unique_name)
    
    with open(temp_path, 'wb') as f:
        f.write(content)
    
    # 2. Importação Local para evitar Dependência Circular
    # services.py -> tasks.py -> services.py
    from .tasks import execute_file_analysis_task
    
    # 3. Disparar a tarefa
    # .delay() é o método do Celery para enviar para a fila
    task = execute_file_analysis_task.delay(temp_path, filename, ai_provider)
    
    logger.info(f"Análise enfileirada para {filename}. Task ID: {task.id}")
    return task.id

async def run_url_analysis(url: str, ai_provider: str = None) -> str:
    """
    Orquestra a análise completa de uma URL de forma assíncrona.
    """
    logger.info(f"Iniciando análise para a URL: {url}")

    # 1. Análise Externa em Paralelo com asyncio.gather
    url_backends = get_url_analysis_backends()
    tasks = [backend.analyze_url(url) for backend in url_backends]
    external_results_list = await asyncio.gather(*tasks)
    
    # Mapeia os resultados de volta para um dicionário
    external_results = {backend.name: result for backend, result in zip(url_backends, external_results_list)}

    # 2. Consolidação e Veredito Final
    final_result = local_analysis.build_url_analysis_result(url, external_results)
    
    # 3. Análise MITRE ATT&CK
    final_result['mitre_attack'] = utils.get_mitre_attack_info(final_result)
    
    # 4. Análise com IA
    # Executa em thread separada para não bloquear o loop de eventos do Quart
    final_result['ai_analysis'] = await asyncio.to_thread(get_ai_explanation, final_result, ai_provider)

    # 5. Persistência
    result_id = await asyncio.to_thread(database.save_analysis, final_result)
    logger.info(f"Análise concluída para {url}. ID do resultado: {result_id}")
    return result_id


async def update_settings(form_data: Dict[str, str]) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Salva as chaves de API no arquivo .env e recarrega as configurações.
    Valida as chaves, salva as válidas e reporta erros para as inválidas.
    """
    env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.env')
    current_env = dotenv_values(dotenv_path=env_path) if os.path.exists(env_path) else {}
    
    updated = False
    messages = []
    invalid_key_messages = []

    # --- Refatoração: Lógica Unificada para Chaves Individuais ---
    # Mapeia o nome do campo no formulário para sua função de validação e nome amigável
    single_key_validators = {
        'VT_API_KEY': (None, "VirusTotal"), # VT não tem validador online simples por enquanto
        'OSM_API_KEY': (osm_validate_key, "OpenSourceMalware"),
        'GOOGLE_SAFE_BROWSING_API_KEY': (google_safe_browsing_validate_key, "Google Safe Browsing"),
    }

    for key_name, (validator, friendly_name) in single_key_validators.items():
        key_input = form_data.get(key_name, '').strip()

        # Apenas processa se uma nova chave foi realmente inserida
        if key_input:
            is_valid, message = True, ""
            if validator:
                is_valid, message = await asyncio.to_thread(validator, key_input)

            if is_valid:
                # Apenas atualiza se a nova chave for diferente da antiga
                if key_input != current_env.get(key_name):
                    current_env[key_name] = key_input
                    messages.append(f"Chave do {friendly_name} salva.")
                    updated = True
            else:
                invalid_key_messages.append(f"Chave {friendly_name}: {message}")

    # --- Lida com as chaves de IA (lógica mais complexa de múltiplos provedores) ---
    ai_keys_input = form_data.get('AI_API_KEY', '').strip()
    
    # Apenas processa se novas chaves de IA foram inseridas
    if ai_keys_input:
        ai_keys = [key for key in re.split(r'[\n, ]+', ai_keys_input) if key]
        valid_ai_keys = []
        detected_providers = set()

        if ai_keys:
            for key in ai_keys:
                provider, message = await asyncio.to_thread(detect_provider, key)
                if provider:
                    valid_ai_keys.append(key)
                    detected_providers.add(provider)
                    messages.append(f"Chave de IA para {provider.upper()} (final {key[-4:]}) validada.")
                else:
                    invalid_key_messages.append(f"Chave de IA com final {key[-4:]}: {message}")

            if valid_ai_keys:
                all_valid_keys_str = ",".join(valid_ai_keys)
                if all_valid_keys_str != current_env.get('AI_API_KEY'):
                    current_env['AI_API_KEY'] = all_valid_keys_str
                    # Mantém o provedor detectado anteriormente se nenhum novo for detectado
                    if detected_providers:
                        current_env['AI_PROVIDER_DETECTED'] = list(detected_providers)[0]
                    messages.append("Configurações de IA salvas.")
                    updated = True
            # Se nenhuma chave de IA válida foi fornecida, não fazemos nada, mantendo as antigas.
            
    # Adiciona mensagens de erro das chaves inválidas
    if invalid_key_messages:
        messages.append("Algumas chaves falharam na validação:")
        messages.extend(invalid_key_messages)

    if not updated and not invalid_key_messages:
        return True, "Nenhuma configuração foi alterada.", utils.get_key_status()

    # Salva as alterações no arquivo .env
    if not await asyncio.to_thread(utils.save_env_file, env_path, current_env):
        logger.error(f"Falha ao escrever no arquivo .env em {env_path}")
        return False, "Erro de permissão ao tentar salvar o arquivo de configuração.", utils.get_key_status()

    # Recarrega as configurações na aplicação
    settings.reload()
    
    final_message = " ".join(messages) if messages else "Configurações salvas com sucesso."
    return True, final_message, utils.get_key_status()


# --- LÓGICA DE SERVIÇOS DE IA ---

def get_ai_explanation(analysis_result: Dict[str, Any], ai_provider: str = None) -> Dict[str, Any]:
    """
    Gera uma explicação em linguagem natural do resultado da análise.
    Ele lida com múltiplas chaves de IA configuradas, selecionando a correta para o provedor.
    """
    provider_name = ai_provider or settings.AI_PROVIDER_DETECTED
    if not provider_name:
        raise AIProviderError("Nenhum provedor de IA configurado ou detectado.")

    all_keys = [key.strip() for key in (settings.AI_API_KEY or "").split(',') if key.strip()]
    if not all_keys:
        raise AIProviderError("Nenhuma chave de IA está configurada.")

    # Encontra a chave apropriada para o provedor selecionado
    key_for_provider = None
    for key in all_keys:
        if (provider_name == 'groq' and key.startswith('gsk_')) or \
           (provider_name == 'gemini' and key.startswith('AIza')) or \
           (provider_name == 'openai' and key.startswith('sk-')) or \
           (provider_name == 'grok' and key.startswith('xai-')):
            key_for_provider = key
            break
    
    if not key_for_provider:
        # Fallback: se nenhum prefixo corresponder, tenta a primeira chave da lista
        # Isso pode acontecer se o usuário fornecer uma chave de um provedor não esperado
        key_for_provider = all_keys[0]
        logger.warning(f"Não foi encontrada uma chave com prefixo correspondente para o provedor {provider_name}. Tentando com a primeira chave disponível.")

    # Guarda a configuração original e a substitui temporariamente
    original_api_keys = settings.AI_API_KEY
    settings.AI_API_KEY = key_for_provider

    try:
        provider_config = get_ai_provider(provider_name)
        if not provider_config:
            # Este erro não deveria acontecer se a lógica de salvar estiver correta
            raise AIProviderError("Provedor de IA não pôde ser carregado, mesmo com uma chave válida.")

        prompt = _build_ai_prompt(analysis_result, provider_name)
        
        cache_key = hashlib.sha256(f"{provider_name}:{prompt}".encode('utf-8')).hexdigest()
        cached_response = ai_cache.get(cache_key)
        
        if cached_response:
            logger.info(f"Retornando resposta de IA do cache para {provider_name}")
            return cached_response

        generate_func = provider_config['generate']
        summary = generate_func(prompt)
        
        result = {
            "summary": summary,
            "provider": provider_name
        }
        
        ai_cache.set(cache_key, result, expire=604800)
        
        return result
    except AIProviderError:
        raise
    except Exception as e:
        logger.error(f"Erro ao gerar explicação com IA (provedor: {provider_name}): {e}")
        raise AIProviderError(f"Houve um erro de comunicação com o serviço de IA: {e}. A análise não pôde ser gerada.")
    finally:
        # Restaura a configuração original para não afetar outras operações
        settings.AI_API_KEY = original_api_keys


def _prune_data_for_prompt(data: Any) -> Any:
    """
    Reduz a complexidade dos dados (Big O) antes da serialização JSON.
    Remove campos verbosos e trunca listas para economizar tokens e processamento.
    """
    if isinstance(data, dict):
        # Remove campos binários ou muito grandes que não ajudam no resumo executivo
        return {k: _prune_data_for_prompt(v) for k, v in data.items() 
                if k not in ['strings', 'hex_dump', 'raw_response', 'response_body', 'content']}
    elif isinstance(data, list):
        # Limita listas a 20 itens (ex: listas de imports/exports podem ter milhares)
        return [_prune_data_for_prompt(i) for i in data[:20]]
    elif isinstance(data, str):
        # Trunca strings individuais muito longas
        return data[:500] + "..." if len(data) > 500 else data
    return data

def _build_ai_prompt(result: Dict[str, Any], ai_provider: str = None) -> str:
    """Função auxiliar para construir o prompt para a IA."""
    item_type = "arquivo" if "sha256" in result else "URL"
    identifier = result.get('filename') or result.get('url')
    verdict = result.get('final_verdict', 'desconhecido')
    
    # Otimização: Prepara uma versão leve dos dados para o prompt
    pruned_result = _prune_data_for_prompt(result)

    prompt = (
        f"Você é um analista de segurança cibernética sênior. Sua tarefa é fornecer um resumo executivo "
        f"claro e conciso sobre a análise de um {item_type} suspeito.\n\n"
        f"**Item Analisado:** `{identifier}`\n"
        f"**Veredito Final:** **{verdict.upper()}**\n\n"
        f"**Contexto:**\n"
        f"O item foi analisado por múltiplas ferramentas de segurança. Abaixo estão os dados brutos. "
        f"Com base nesses dados, explique em LINGUAGEM SIMPLES E DIRETA (para um público não técnico) o que foi encontrado. "
        f"Se o veredito for 'malicioso' ou 'suspeito', explique os principais riscos. Se for 'limpo', confirme que "
        f"nenhuma ameaça foi detectada pelas ferramentas. "
        f"Se houver dados do MITRE ATT&CK na análise, inclua uma seção separada chamada 'Análise MITRE ATT&CK' e explique o que as táticas e técnicas identificadas significam neste contexto.\n\n"
        f"Seja objetivo e evite jargões.\n\n"
        f"**Dados da Análise:**\n"
        f"```json\n{json.dumps(pruned_result, indent=2, ensure_ascii=False)}\n```\n\n"
        f"**Seu Resumo Executivo (em português, formato Markdown):**\n"
    )

    # Determina o modelo de IA que será usado para obter o limite correto de tokens
    ai_provider_name = ai_provider or settings.AI_PROVIDER_DETECTED
    if ai_provider_name == 'gemini':
        model_name = settings.GEMINI_MODEL
    elif ai_provider_name == 'grok':
        model_name = getattr(settings, 'GROK_MODEL', 'grok-beta')
    else:
        model_name = settings.GROQ_MODEL

    return _truncate_prompt_by_tokens(prompt, model_name)
