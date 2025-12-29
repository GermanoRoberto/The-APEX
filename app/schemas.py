from pydantic import BaseModel, Field, HttpUrl, validator
from typing import Optional, List, Literal

class ScanRequest(BaseModel):
    ai_provider: Optional[str] = Field(None, description="Provedor de IA escolhido para análise")

class FileAnalysisRequest(BaseModel):
    ai_provider: Optional[str] = Field(None, description="Provedor de IA escolhido para análise")

class UrlAnalysisRequest(BaseModel):
    url: HttpUrl = Field(..., description="URL a ser analisada")
    ai_provider: Optional[str] = Field(None, description="Provedor de IA escolhido")

    @validator('url', pre=True)
    def validate_url_string(cls, v):
        if not v:
            raise ValueError("URL não pode ser vazia")
        return v

class NetworkAnalysisRequest(BaseModel):
    mode: Literal['quick', 'full'] = Field(..., description="Modo de varredura de rede")
    cidr: Optional[str] = Field(None, description="CIDR da rede a ser analisada")
    ai_provider: Optional[str] = Field(None, description="Provedor de IA escolhido")

class SetupRequest(BaseModel):
    VT_API_KEY: Optional[str] = None
    AI_API_KEY: Optional[str] = None
    OSM_API_KEY: Optional[str] = None
    GOOGLE_SAFE_BROWSING_API_KEY: Optional[str] = None
    GEMINI_MODEL: Optional[str] = None
    GROQ_MODEL: Optional[str] = None
    
    # SIEM/SOAR Integrations
    ELASTIC_API_KEY: Optional[str] = None
    ELASTIC_API_URL: Optional[str] = None
    WAZUH_API_KEY: Optional[str] = None
    WAZUH_API_URL: Optional[str] = None
    
    # Validação customizada pode ser adicionada aqui, ex: checar formato de chaves
