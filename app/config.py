import os
import secrets
import warnings
from dotenv import load_dotenv
from pathlib import Path

# --- Best Practice: Define Project Root ---
# Isso garante que o .env seja procurado no lugar certo, evitando buscas em diretórios pais
# que podem causar lentidão em drives de rede ou sistemas de arquivos grandes.
# Path(__file__) é o caminho para este arquivo (config.py)
# .parent é o diretório 'app'
# .parent novamente é a raiz do projeto
PROJECT_ROOT = Path(__file__).parent.parent
DOTENV_PATH = PROJECT_ROOT / '.env'

class Config:
    """
    Carrega as configurações da aplicação a partir de variáveis de ambiente de forma segura e flexível.
    """
    def __init__(self):
        self.reload()

    def reload(self):
        """
        Recarrega todas as configurações do arquivo .env, garantindo que a aplicação
        possa ser atualizada sem reiniciar, se necessário.
        """
        # --- FIX: Evita o bug de travamento ---
        # Carrega o .env a partir de um caminho explícito, desabilitando a busca.
        load_dotenv(dotenv_path=DOTENV_PATH)

        # --- Security: Chave Secreta Robusta ---
        # Usa uma chave do .env ou gera uma chave segura e temporária.
        # Evita o uso de chaves fixas e previsíveis em ambientes de desenvolvimento.
        secret = os.environ.get('SECRET_KEY')
        if not secret:
            warnings.warn(
                "A SECRET_KEY não está definida no seu arquivo .env. "
                "Gerando e salvando uma chave permanente para sessões seguras.",
                UserWarning
            )
            secret = secrets.token_hex(24)
            # Anexa a nova chave ao arquivo .env para persistência
            try:
                with open(DOTENV_PATH, 'a') as f:
                    f.write(f"\nSECRET_KEY={secret}\n")
            except IOError as e:
                warnings.warn(f"Não foi possível salvar a nova SECRET_KEY no arquivo .env: {e}")

        self.SECRET_KEY = secret
        
        # --- Refactor: Centralização e Flexibilidade ---
        # Move valores antes fixos para variáveis de ambiente com padrões sensatos.
        self.APP_VERSION = "3.2"
        self.MAX_FILE_SIZE = int(os.environ.get('MAX_FILE_SIZE_MB', 100)) * 1024 * 1024
        self.REQUEST_TIMEOUT = int(os.environ.get('REQUEST_TIMEOUT_SECONDS', 30))

        # Chaves de API
        self.AI_API_KEY = os.environ.get('AI_API_KEY')
        self.AI_PROVIDER_DETECTED = os.environ.get('AI_PROVIDER_DETECTED')
        self.VT_API_KEY = os.environ.get('VT_API_KEY')
        self.OSM_API_KEY = os.environ.get('OSM_API_KEY')
        self.GOOGLE_SAFE_BROWSING_API_KEY = os.environ.get('GOOGLE_SAFE_BROWSING_API_KEY')

        # SIEM/SOAR Integrations
        self.ELASTIC_API_KEY = os.environ.get('ELASTIC_API_KEY')
        self.ELASTIC_API_URL = os.environ.get('ELASTIC_API_URL')

        # Modelos de IA
        self.GEMINI_MODEL = os.environ.get('GEMINI_MODEL', "gemini-1.5-flash")
        self.GROQ_MODEL = os.environ.get('GROQ_MODEL', "llama-3.3-70b-versatile")
        self.GROK_MODEL = os.environ.get('GROK_MODEL', "grok-beta") # Exemplo, pode não existir

        # URLs de Endpoints de API (raramente mudam, mas podem ser externalizadas se necessário)
        self.VT_API_URL_FILES = "https://www.virustotal.com/api/v3/files/{sha256}"
        self.VT_API_URL_URLS = "https://www.virustotal.com/api/v3/urls"
        self.VT_API_URL_ANALYSES = "https://www.virustotal.com/api/v3/analyses/{id}"
        self.VT_API_URL_UPLOAD = "https://www.virustotal.com/api/v3/files/upload_url"
        self.GOOGLE_SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    def is_configured(self) -> bool:
        """Verifica se as chaves de API essenciais estão configuradas."""
        return bool(self.VT_API_KEY and self.AI_API_KEY)

# Cria uma instância única das configurações para ser importada em toda a aplicação.
settings = Config()