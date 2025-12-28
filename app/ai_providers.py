from abc import ABC, abstractmethod
import logging
import google.generativeai as genai
import openai
import requests

from .config import settings

logger = logging.getLogger(__name__)

class AIProviderError(Exception):
    """Exceção customizada para erros de provedores de IA."""
    pass

class BaseAIProvider(ABC):
    """Interface base para todos os provedores de IA."""

    @abstractmethod
    def generate_explanation(self, prompt: str, api_key: str) -> str:
        """Gera uma explicação a partir do prompt fornecido."""
        pass

    @abstractmethod
    def validate_key(self, api_key: str) -> tuple[bool, str]:
        """Valida a chave de API fornecida."""
        pass

class GeminiProvider(BaseAIProvider):
    def generate_explanation(self, prompt: str, api_key: str) -> str:
        try:
            genai.configure(api_key=api_key)
            model = genai.GenerativeModel(settings.GEMINI_MODEL)
            response = model.generate_content(prompt)
            return response.text
        except Exception as e:
            logger.error(f"Erro na API do Gemini: {e}")
            raise AIProviderError(f"Falha ao gerar explicação com Gemini: {e}")

    def validate_key(self, api_key: str) -> tuple[bool, str]:
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

class GroqProvider(BaseAIProvider):
    def generate_explanation(self, prompt: str, api_key: str) -> str:
        if not api_key:
            raise AIProviderError("A chave da API da Groq não está configurada.")
        try:
            client = openai.OpenAI(
                api_key=api_key,
                base_url="https://api.groq.com/openai/v1"
            )
            response = client.chat.completions.create(
                model=settings.GROQ_MODEL,
                messages=[{"role": "user", "content": prompt}],
                temperature=0,
                max_tokens=800
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"Erro na API da Groq: {e}")
            raise AIProviderError(f"Falha ao gerar explicação com Groq: {e}")

    def validate_key(self, api_key: str) -> tuple[bool, str]:
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

class GrokProvider(BaseAIProvider):
    def generate_explanation(self, prompt: str, api_key: str) -> str:
        try:
            client = openai.OpenAI(
                api_key=api_key,
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

    def validate_key(self, api_key: str) -> tuple[bool, str]:
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

class OpenAIProvider(BaseAIProvider):
    def generate_explanation(self, prompt: str, api_key: str) -> str:
        try:
            client = openai.OpenAI(api_key=api_key)
            response = client.chat.completions.create(
                model="gpt-4-turbo",
                messages=[{"role": "user", "content": prompt}]
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"Erro na API da OpenAI: {e}")
            raise AIProviderError(f"Falha ao gerar explicação com OpenAI: {e}")

    def validate_key(self, api_key: str) -> tuple[bool, str]:
        if not api_key or not api_key.startswith("sk-"):
            return False, "Formato de chave da OpenAI inválido."
        try:
            client = openai.OpenAI(api_key=api_key)
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

class OSMProvider(BaseAIProvider):
    """
    Nota: OSM não é exatamente um provedor de IA Generativa, mas segue a interface de validação.
    A geração de explicação não é suportada.
    """
    def generate_explanation(self, prompt: str, api_key: str) -> str:
        raise NotImplementedError("OpenSourceMalware não suporta geração de explicação.")

    def validate_key(self, api_key: str) -> tuple[bool, str]:
        if not api_key or not api_key.startswith("osm_"):
            return False, "Formato de chave OSM inválido (deve começar com 'osm_')."
        
        headers = {"Authorization": f"Bearer {api_key}"}
        test_url = "https://api.opensourcemalware.com/functions/v1/"
        try:
            response = requests.get(test_url, headers=headers, timeout=settings.REQUEST_TIMEOUT)
            if response.status_code in [401, 403]:
                return False, "A chave da API do OpenSourceMalware é inválida ou expirou."
            if response.status_code in [200, 404]:
                 return True, "Chave do OpenSourceMalware válida."
            return False, f"Erro inesperado ao validar a chave OSM: Status {response.status_code}"
        except requests.exceptions.RequestException as e:
            logger.error(f"Erro de rede ao validar chave OSM: {e}")
            return False, f"Falha de rede ao tentar validar a chave OSM: {e}"

class AIProviderFactory:
    _providers = {
        "openai": OpenAIProvider(),
        "gemini": GeminiProvider(),
        "groq": GroqProvider(),
        "grok": GrokProvider(),
        "osm": OSMProvider(),
    }

    @classmethod
    def get_provider(cls, provider_name: str) -> BaseAIProvider:
        provider = cls._providers.get(provider_name)
        if not provider:
            raise ValueError(f"Provedor de IA desconhecido: {provider_name}")
        return provider

    @classmethod
    def get_all_providers(cls):
        return cls._providers.items()

# --- Funções de Compatibilidade e Auxiliares ---

def detect_provider(api_key: str) -> tuple[str | None, str]:
    """
    Tenta detectar o provedor de IA, retorna o nome do provedor e uma mensagem.
    """
    if not api_key:
        return None, "A chave não pode estar vazia."

    last_error = "Formato de chave desconhecido ou provedor não suportado."
    
    # Ordem de validação
    validation_order = ['openai', 'gemini', 'groq', 'grok', 'osm']
    
    for provider_name in validation_order:
        provider = AIProviderFactory.get_provider(provider_name)
        is_valid, message = provider.validate_key(api_key)
        
        if is_valid:
            logger.info(f"Chave de IA detectada como sendo do provedor: {provider_name}")
            return provider_name, message
        
        # Heurística de erro baseada no prefixo
        if (provider_name == 'groq' and api_key.startswith('gsk_')) or \
           (provider_name == 'gemini' and api_key.startswith('AIza')) or \
           (provider_name == 'openai' and api_key.startswith('sk-')) or \
           (provider_name == 'grok' and api_key.startswith('xai-')) or \
           (provider_name == 'osm' and api_key.startswith('osm_')):
            last_error = message

    logger.warning(f"Nenhum provedor de IA pôde ser validado para a chave que termina em '...{api_key[-4:]}'. Erro provável: {last_error}")
    return None, last_error

def get_ai_provider(provider_name: str = None) -> BaseAIProvider:
    """Retorna a instância do provedor de IA detectado e configurado."""
    if not provider_name:
        provider_name = settings.AI_PROVIDER_DETECTED
    
    return AIProviderFactory.get_provider(provider_name)

# Exporta validação específica para uso direto se necessário
def osm_validate_key(api_key: str) -> tuple[bool, str]:
    return AIProviderFactory.get_provider("osm").validate_key(api_key)

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
            error_details = response.json().get("error", {}).get("message", "sem detalhes")
            logger.error(f"Erro de validação do Google Safe Browsing: {error_details}")
            return False, f"Chave do Google Safe Browsing inválida ou com permissões incorretas: {error_details}"

        return False, f"Erro inesperado ao validar a chave: Status {response.status_code}"

    except requests.exceptions.RequestException as e:
        logger.error(f"Erro de rede ao validar chave Google Safe Browsing: {e}")
        return False, f"Falha de rede ao tentar validar a chave: {e}"
