# -*- coding: utf-8 -*-
"""
Módulo para Provedores de IA.

Este módulo abstrai a lógica de comunicação com diferentes APIs de IA,
como Gemini e Groq. Cada provedor implementa uma interface comum para
gerar explicações e validar chaves.
"""
import logging
import google.generativeai as genai
import openai
import requests

from .config import settings

logger = logging.getLogger(__name__)

class AIProviderError(Exception):
    """Exceção customizada para erros de provedores de IA."""
    pass

# --- Interface Comum (Conceitual) ---
# Cada provedor deve, idealmente, expor:
# - uma função `generate_explanation(prompt)`
# - uma função `validate_key(api_key)`

# --- Provedor Gemini ---

def gemini_generate_explanation(prompt: str) -> str:
    """Gera a explicação usando a API do Gemini."""
    try:
        genai.configure(api_key=settings.AI_API_KEY)
        model = genai.GenerativeModel(settings.GEMINI_MODEL)
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        logger.error(f"Erro na API do Gemini: {e}")
        raise AIProviderError(f"Falha ao gerar explicação com Gemini: {e}")

def gemini_validate_key(api_key: str) -> tuple[bool, str]:
    """Valida a chave da API do Gemini."""
    if not api_key:
        return False, "A chave não pode estar vazia."
    if not api_key.startswith("AIza"):
        return False, "Formato de chave Gemini inválido (deve começar com 'AIza')."
    try:
        genai.configure(api_key=api_key)
        models = [m for m in genai.list_models() if 'generateContent' in m.supported_generation_methods]
        if not models:
            return False, "Nenhum modelo compatível encontrado para esta chave Gemini."
        return True, "Chave do Gemini AI válida."
    except Exception as e:
        logger.error(f"Erro ao validar chave Gemini: {e}")
        return False, f"A chave parece inválida ou ocorreu um erro na API: {e}"

# --- Provedor Groq ---

def groq_generate_explanation(prompt: str) -> str:
    """Gera a explicação usando a API da Groq."""
    api_key = settings.AI_API_KEY
    if not api_key:
        raise AIProviderError("A chave da API da Groq não está configurada.")
    try:
        client = openai.OpenAI(
            api_key=api_key,
            base_url="https://api.groq.com/openai/v1"
        )
        response = client.chat.completions.create(
            model=settings.GROQ_MODEL,
            messages=[{"role": "user", "content": prompt}]
        )
        return response.choices[0].message.content
    except Exception as e:
        logger.error(f"Erro na API da Groq: {e}")
        raise AIProviderError(f"Falha ao gerar explicação com Groq: {e}")

def groq_validate_key(api_key: str) -> tuple[bool, str]:
    """Valida a chave da API da Groq."""
    if not api_key.startswith("gsk_"):
        return False, "Formato de chave Groq inválido (deve começar com 'gsk_')."
    try:
        client = openai.OpenAI(
            api_key=api_key,
            base_url="https://api.groq.com/openai/v1"
        )
        client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": "test"}],
            max_tokens=2,
        )
        return True, "Chave da Groq válida."
    except openai.AuthenticationError:
        return False, "A chave da API da Groq é inválida ou expirou."
    except Exception as e:
        logger.error(f"Erro de rede ao validar chave Groq: {e}")
        return False, f"Falha de rede ao tentar validar a chave: {e}"

# --- Provedor Grok (xAI) ---

def grok_generate_explanation(prompt: str) -> str:
    """Gera a explicação usando a API do Grok (xAI)."""
    try:
        client = openai.OpenAI(
            api_key=settings.AI_API_KEY,
            base_url="https://api.x.ai/v1"
        )
        response = client.chat.completions.create(
            model=settings.GROK_MODEL,
            messages=[
                {"role": "system", "content": "You are a helpful security analyst."},
                {"role": "user", "content": prompt}
            ],
            temperature=0
        )
        return response.choices[0].message.content
    except Exception as e:
        logger.error(f"Erro na API do Grok: {e}")
        raise AIProviderError(f"Falha ao gerar explicação com Grok: {e}")

def grok_validate_key(api_key: str) -> tuple[bool, str]:
    """Valida a chave da API do Grok (xAI)."""
    if not api_key or not api_key.startswith("xai-"):
        return False, "Formato de chave Grok inválido (deve começar com 'xai-')."
    try:
        client = openai.OpenAI(
            api_key=api_key,
            base_url="https://api.x.ai/v1"
        )
        client.chat.completions.create(
            model="grok-beta",
            messages=[{"role": "user", "content": "test"}],
            max_tokens=1,
        )
        return True, "Chave do Grok válida."
    except openai.AuthenticationError:
        return False, "A chave da API do Grok é inválida ou expirou."
    except Exception as e:
        logger.error(f"Erro de rede ao validar chave Grok: {e}")
        return False, f"Falha de rede ao tentar validar a chave: {e}"

# --- Provedor OpenAI ---

def openai_generate_explanation(prompt: str) -> str:
    """Gera a explicação usando a API da OpenAI."""
    try:
        client = openai.OpenAI(api_key=settings.AI_API_KEY)
        response = client.chat.completions.create(
            model="gpt-4-turbo",
            messages=[{"role": "user", "content": prompt}]
        )
        return response.choices[0].message.content
    except Exception as e:
        logger.error(f"Erro na API da OpenAI: {e}")
        raise AIProviderError(f"Falha ao gerar explicação com OpenAI: {e}")

def openai_validate_key(api_key: str) -> tuple[bool, str]:
    """Valida a chave da API da OpenAI."""
    if not api_key or not api_key.startswith("sk-"):
        return False, "Formato de chave da OpenAI inválido."
    try:
        client = openai.OpenAI(api_key=api_key)
        # Tenta uma conclusão simples para validar a chave e permissões
        client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": "test"}],
            max_tokens=1
        )
        return True, "Chave da OpenAI válida."
    except openai.AuthenticationError:
        return False, "A chave da API da OpenAI é inválida ou expirou."
    except Exception as e:
        logger.error(f"Erro ao validar chave OpenAI: {e}")
        return False, f"Ocorreu um erro na API da OpenAI: {e}"

# --- Provedor Open Source Malware ---

def osm_validate_key(api_key: str) -> tuple[bool, str]:
    """Valida a chave da API do OpenSourceMalware.com."""
    if not api_key or not api_key.startswith("osm_"):
        return False, "Formato de chave OSM inválido (deve começar com 'osm_')."
    
    headers = {"Authorization": f"Bearer {api_key}"}
    test_url = "https://api.opensourcemalware.com/functions/v1/" # Endpoint base para teste

    try:
        # Tenta acessar um endpoint protegido para validar a chave.
        # Não há um endpoint de "teste", então esperamos um 401/403 para uma chave
        # com formato válido mas incorreta, ou um 200/404 se o endpoint existir.
        response = requests.get(test_url, headers=headers, timeout=settings.REQUEST_TIMEOUT)

        # Se a chave for inválida, a API retorna 401 ou 403
        if response.status_code in [401, 403]:
            return False, "A chave da API do OpenSourceMalware é inválida ou expirou."
        
        # Se a chave for válida, a API pode retornar 200 ou 404 (se o endpoint não for um GET)
        # Qualquer um desses códigos indica que a autenticação passou.
        if response.status_code in [200, 404]:
             return True, "Chave do OpenSourceMalware válida."

        # Outros códigos de erro
        return False, f"Erro inesperado ao validar a chave OSM: Status {response.status_code}"

    except requests.exceptions.RequestException as e:
        logger.error(f"Erro de rede ao validar chave OSM: {e}")
        return False, f"Falha de rede ao tentar validar a chave OSM: {e}"

# --- Provedor Google Safe Browsing ---

def google_safe_browsing_validate_key(api_key: str) -> tuple[bool, str]:
    """Valida a chave da API do Google Safe Browsing."""
    if not api_key:
        return False, "A chave não pode estar vazia."

    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    request_body = {
        "client": {"clientId": "analisador-malware", "clientVersion": settings.APP_VERSION},
        "threatInfo": {
            "threatTypes": ["MALWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": "http://testsafebrowsing.appspot.com/s/malware.html"}]
        }
    }
    
    try:
        response = requests.post(api_url, json=request_body, timeout=settings.REQUEST_TIMEOUT)
        
        if response.status_code == 200:
            return True, "Chave do Google Safe Browsing válida."
        
        if response.status_code in [400, 403]:
            # O erro 400 pode indicar uma chave malformatada ou inválida.
            # O erro 403 geralmente é permissão.
            error_details = response.json().get("error", {}).get("message", "sem detalhes")
            logger.error(f"Erro de validação do Google Safe Browsing: {error_details}")
            return False, f"Chave do Google Safe Browsing inválida ou com permissões incorretas: {error_details}"

        return False, f"Erro inesperado ao validar a chave: Status {response.status_code}"

    except requests.exceptions.RequestException as e:
        logger.error(f"Erro de rede ao validar chave Google Safe Browsing: {e}")
        return False, f"Falha de rede ao tentar validar a chave: {e}"


# --- Fábrica de Provedores ---

PROVIDER_MAP = {
    "openai": {
        "generate": openai_generate_explanation,
        "validate": openai_validate_key,
    },
    "gemini": {
        "generate": gemini_generate_explanation,
        "validate": gemini_validate_key,
    },
    "groq": {
        "generate": groq_generate_explanation,
        "validate": groq_validate_key,
    },
    "grok": {
        "generate": grok_generate_explanation,
        "validate": grok_validate_key,
    },
    "osm": {
        "validate": osm_validate_key,
    }
}

VALIDATION_ORDER = [
    ('openai', openai_validate_key),
    ('gemini', gemini_validate_key),
    ('groq', groq_validate_key),
    ('grok', grok_validate_key),
    ('osm', osm_validate_key),
]

def detect_provider(api_key: str) -> tuple[str | None, str]:
    """
    Tenta detectar o provedor de IA, retorna o nome do provedor e uma mensagem.
    """
    if not api_key:
        return None, "A chave não pode estar vazia."

    last_error = "Formato de chave desconhecido ou provedor não suportado."
    for provider_name, validation_func in VALIDATION_ORDER:
        is_valid, message = validation_func(api_key)
        if is_valid:
            logger.info(f"Chave de IA detectada como sendo do provedor: {provider_name}")
            return provider_name, message
        
        # Se a chave tem o prefixo de um provedor, guarda essa mensagem de erro como a mais provável.
        if (provider_name == 'groq' and api_key.startswith('gsk_')) or \
           (provider_name == 'gemini' and api_key.startswith('AIza')) or \
           (provider_name == 'openai' and api_key.startswith('sk-')) or \
           (provider_name == 'grok' and api_key.startswith('xai-')) or \
           (provider_name == 'osm' and api_key.startswith('osm_')):
            last_error = message

    logger.warning(f"Nenhum provedor de IA pôde ser validado para a chave que termina em '...{api_key[-4:]}'. Erro provável: {last_error}")
    return None, last_error

def get_ai_provider(provider_name: str = None):
    """Retorna as funções para o provedor de IA detectado e configurado."""
    if not provider_name:
        provider_name = settings.AI_PROVIDER_DETECTED
    
    provider = PROVIDER_MAP.get(provider_name)
    if not provider:
        raise ValueError(f"Provedor de IA desconhecido: {provider_name}")
    
    # Verifica se a chave de API para o provedor selecionado está configurada
    api_key = settings.AI_API_KEY
    if not api_key:
        raise AIProviderError(f"A chave de IA para o provedor detectado '{provider_name}' não está configurada.")
        
    return provider
