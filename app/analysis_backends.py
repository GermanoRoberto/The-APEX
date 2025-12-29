# -*- coding: utf-8 -*-
"""
Módulo de Backends de Análise (Assíncrono).

Este módulo foi refatorado para usar E/S não bloqueante (asyncio) e a biblioteca
`aiohttp` para as chamadas de API externas. Isso resolve o problema crítico de
bloqueio de thread causado por `time.sleep()` e `requests` síncronos, melhorando
drasticamente a performance e a concorrência da aplicação.
"""
import logging
import asyncio
import aiohttp
from abc import ABC, abstractmethod
from typing import Dict, Any

from .config import settings

logger = logging.getLogger(__name__)

# --- Classe Base Abstrata ---

class AnalysisService(ABC):
    """Define a interface para todos os serviços de análise externa."""
    def __init__(self, name: str):
        self.name = name

    @abstractmethod
    async def analyze_file(self, sha256: str, content: bytes, filename: str) -> Dict[str, Any]:
        """Analisa um arquivo de forma assíncrona."""
        raise NotImplementedError

    @abstractmethod
    async def analyze_url(self, url: str) -> Dict[str, Any]:
        """Analisa uma URL de forma assíncrona."""
        raise NotImplementedError

# --- Implementações Concretas dos Serviços ---

class VirusTotalService(AnalysisService):
    """Serviço de análise para a API do VirusTotal."""
    def __init__(self, api_key: str):
        super().__init__("virustotal")
        self.api_key = api_key

    async def analyze_file(self, sha256: str, content: bytes, filename: str) -> Dict[str, Any]:
        return await _query_virustotal_file(sha256, self.api_key, content, filename)

    async def analyze_url(self, url: str) -> Dict[str, Any]:
        return await _query_virustotal_url(url, self.api_key)

class GoogleSafeBrowsingService(AnalysisService):
    """Serviço de análise para a API do Google Safe Browsing."""
    def __init__(self, api_key: str):
        super().__init__("google_safe_browsing")
        self.api_key = api_key

    async def analyze_file(self, sha256: str, content: bytes, filename: str) -> Dict[str, Any]:
        return {}

    async def analyze_url(self, url: str) -> Dict[str, Any]:
        return await _query_google_safe_browsing(url, self.api_key)

class LocalHomographService(AnalysisService):
    """Serviço "virtual" para análises locais."""
    def __init__(self):
        super().__init__("local_homograph_analysis")

    async def analyze_file(self, sha256: str, content: bytes, filename: str) -> Dict[str, Any]:
        return {}

    async def analyze_url(self, url: str) -> Dict[str, Any]:
        from .utils import contains_cyrillic
        if contains_cyrillic(url):
            return {
                'verdict': 'suspicious',
                'tags': ['cyrillic-homograph-attack'],
                'score': 80,
                'summary': 'A URL contém caracteres cirílicos que podem estar sendo usados para se passar por um domínio legítimo.'
            }
        return {}

class OpenSourceMalwareService(AnalysisService):
    """Serviço de submissão para a API do OpenSourceMalware.com."""
    def __init__(self, api_key: str):
        super().__init__("opensource_malware")
        self.api_key = api_key

    async def analyze_file(self, sha256: str, content: bytes, filename: str) -> Dict[str, Any]:
        # A lógica aqui é de SUBMISSÃO, não de consulta.
        # Por padrão, não faz nada. A submissão deve ser acionada por uma lógica de negócio de nível superior.
        # Por exemplo, apenas submeter se o veredito final for malicioso.
        # Para fins de exemplo, vamos retornar um dicionário vazio.
        # Em uma implementação futura, poderíamos chamar `_submit_osm_report` aqui.
        return {"status": "submission_skipped"}

    async def analyze_url(self, url: str) -> Dict[str, Any]:
        return {}

class SensitiveContentService(AnalysisService):
    """Serviço 'virtual' para análise de conteúdo sensível em URLs."""
    def __init__(self):
        super().__init__("sensitive_content_analysis")

    async def analyze_file(self, sha256: str, content: bytes, filename: str) -> Dict[str, Any]:
        return {}

    async def analyze_url(self, url: str) -> Dict[str, Any]:
        from . import local_analysis
        # Esta é uma função de CPU-bound, então a executamos em um thread para não bloquear o loop de eventos.
        return await asyncio.to_thread(local_analysis.analyze_url_for_sensitive_content, url)


# --- Funções "Fábrica" ---

def get_file_analysis_backends() -> list[AnalysisService]:
    """Retorna uma lista de instâncias de serviços que analisam arquivos."""
    backends = []
    if settings.VT_API_KEY:
        backends.append(VirusTotalService(settings.VT_API_KEY))
    if settings.OSM_API_KEY:
        backends.append(OpenSourceMalwareService(settings.OSM_API_KEY))
    return backends

def get_url_analysis_backends() -> list[AnalysisService]:
    """Retorna uma lista de instâncias de serviços que analisam URLs."""
    backends = [LocalHomographService(), SensitiveContentService()]
    if settings.VT_API_KEY:
        backends.append(VirusTotalService(settings.VT_API_KEY))
    if settings.GOOGLE_SAFE_BROWSING_API_KEY:
        backends.append(GoogleSafeBrowsingService(settings.GOOGLE_SAFE_BROWSING_API_KEY))
    return backends


# --- Lógica de Consulta de APIs (Funções Assíncronas) ---

async def _query_virustotal_url(url: str, api_key: str) -> dict:
    headers = {"x-apikey": api_key, "Accept": "application/json"}
    payload = {"url": url}
    timeout = aiohttp.ClientTimeout(total=settings.REQUEST_TIMEOUT)

    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            # Envia a URL para análise
            async with session.post(settings.VT_API_URL_URLS, headers=headers, data=payload) as response:
                response.raise_for_status()
                analysis_id = (await response.json()).get("data", {}).get("id")
                if not analysis_id:
                    return {"error": "Falha ao obter ID de análise do VirusTotal."}

            # Espera assíncrona não bloqueante
            await asyncio.sleep(15)
            
            # Busca o resultado da análise
            result_url = settings.VT_API_URL_ANALYSES.format(id=analysis_id)
            async with session.get(result_url, headers=headers) as result_response:
                result_response.raise_for_status()
                return _process_vt_response(await result_response.json())

    except asyncio.TimeoutError:
        logger.error("VT URL Scan Timeout")
        return {"error": "Timeout ao conectar com o VirusTotal."}
    except aiohttp.ClientError as e:
        logger.error(f"VT URL Scan Client Error: {e}")
        return {"error": f"Erro de conexão com o VirusTotal: {e}"}


async def _query_virustotal_file(sha256: str, api_key: str, content: bytes, filename: str) -> dict:
    url = settings.VT_API_URL_FILES.format(sha256=sha256)
    headers = {"x-apikey": api_key, "Accept": "application/json"}
    timeout = aiohttp.ClientTimeout(total=settings.REQUEST_TIMEOUT)
    main_result = {}

    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            # 1. Tenta obter o relatório pelo hash
            async with session.get(url, headers=headers) as response:
                if response.status == 200:
                    logger.info(f"VT File Scan: Relatório encontrado para o hash {sha256}.")
                    main_result = _process_vt_response(await response.json())
                
                # 2. Se não encontrado (404), faz o upload
                elif response.status == 404:
                    logger.info(f"VT File Scan: Hash {sha256} não encontrado. Fazendo upload.")
                    # Obtém a URL de upload
                    async with session.get(settings.VT_API_URL_UPLOAD, headers=headers) as upload_url_response:
                        upload_url_response.raise_for_status()
                        upload_url = (await upload_url_response.json()).get("data")

                    # Faz o upload do arquivo
                    form = aiohttp.FormData()
                    form.add_field('file', content, filename=filename)
                    async with session.post(upload_url, headers={"x-apikey": api_key}, data=form) as upload_response:
                        upload_response.raise_for_status()
                        analysis_id = (await upload_response.json()).get("data", {}).get("id")
                        logger.info(f"VT File Scan: Upload completo. ID da análise: {analysis_id}.")

                    # Espera assíncrona
                    await asyncio.sleep(20)
                    
                    # Busca o resultado da análise
                    result_url = settings.VT_API_URL_ANALYSES.format(id=analysis_id)
                    async with session.get(result_url, headers=headers) as result_response:
                        result_response.raise_for_status()
                        main_result = _process_vt_response(await result_response.json())
                else:
                    response.raise_for_status()

            # 3. Se o relatório foi obtido, busca o resumo de comportamento
            if main_result.get("found"):
                try:
                    behaviour_url = f"https://www.virustotal.com/api/v3/files/{sha256}/behaviour_summary"
                    async with session.get(behaviour_url, headers=headers) as behaviour_response:
                        if behaviour_response.status == 200:
                            logger.info(f"VT Behaviour Scan: Resumo de comportamento encontrado para {sha256}.")
                            main_result['mitre_attack'] = _process_vt_behaviour_summary(await behaviour_response.json())
                        else:
                            logger.warning(f"VT Behaviour Scan: Não foi possível obter resumo de comportamento para {sha256} (status: {behaviour_response.status}).")
                except Exception as e:
                    logger.error(f"Erro ao buscar resumo de comportamento do VT: {e}")
        
        return main_result

    except asyncio.TimeoutError:
        logger.error("VT File Scan Timeout")
        return {"error": "Timeout ao conectar com o VirusTotal."}
    except aiohttp.ClientError as e:
        logger.error(f"VT File Scan Client Error: {e}")
        return {"error": f"Erro de conexão com o VirusTotal: {e}"}

async def _query_google_safe_browsing(url: str, api_key: str) -> dict:
    api_url = f"{settings.GOOGLE_SAFE_BROWSING_URL}?key={api_key}"
    request_body = {
        "client": {"clientId": "analisador-malware", "clientVersion": settings.APP_VERSION},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    timeout = aiohttp.ClientTimeout(total=settings.REQUEST_TIMEOUT)

    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(api_url, json=request_body) as response:
                response.raise_for_status()
                data = await response.json()
                if data and data.get("matches"):
                    return {"found": True, "verdict": "malicious", "score": 100, "details": data["matches"]}
                return {"found": False, "verdict": "clean", "score": 0}
    except asyncio.TimeoutError:
        logger.error("GSB Scan Timeout")
        return {"error": "Timeout ao conectar com o Google Safe Browsing."}
    except aiohttp.ClientError as e:
        logger.error(f"GSB Scan Client Error: {e}")
        return {"error": f"Erro de conexão com o Google Safe Browsing: {e}"}


async def submit_osm_report(sha256: str, api_key: str, threat_description: str) -> dict:
    """Submete um relatório de ameaça para a API do OpenSourceMalware.com."""
    api_url = "https://api.opensourcemalware.com/functions/v1/submit-threat-report"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    payload = {
        "report_type": "file_hash",
        "resource_identifier": sha256,
        "threat_description": threat_description
    }
    timeout = aiohttp.ClientTimeout(total=settings.REQUEST_TIMEOUT)

    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(api_url, headers=headers, json=payload) as response:
                if response.status == 201:
                    logger.info(f"Relatório para o hash {sha256} submetido com sucesso ao OpenSourceMalware.")
                    return {"submitted": True, "details": await response.json()}
                
                # Trata erros de autenticação ou validação
                if response.status in [401, 403]:
                    logger.error(f"Erro de autenticação ao submeter para OSM: {await response.text()}")
                    return {"submitted": False, "error": "Chave da API inválida ou sem permissão."}
                if response.status == 400:
                    logger.error(f"Erro de dados inválidos ao submeter para OSM: {await response.text()}")
                    return {"submitted": False, "error": "Dados do relatório inválidos."}
                
                # Outros erros
                response.raise_for_status()
                return {"submitted": False, "error": f"Erro inesperado com status {response.status}."}

    except asyncio.TimeoutError:
        logger.error("OSM Submission Timeout")
        return {"submitted": False, "error": "Timeout ao conectar com o OpenSourceMalware."}
    except aiohttp.ClientError as e:
        logger.error(f"OSM Submission Client Error: {e}")
        return {"submitted": False, "error": f"Erro de conexão com o OpenSourceMalware: {e}"}


def _process_vt_response(response_json: dict) -> dict:
    """Processa a resposta JSON do VirusTotal para um formato padronizado."""
    try:
        attrs = response_json.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        total = sum(stats.values())
        
        score = 0
        if total > 0:
            score = ((malicious * 100) + (suspicious * 50)) / total
        
        verdict = "clean"
        if score >= 50:
            verdict = "malicious"
        elif score >= 10:
            verdict = "suspicious"

        return {
            "found": True,
            "verdict": verdict,
            "score": round(score, 2),
            "categories": attrs.get("categories", {}),
            "title": attrs.get("title"),
            "details": {
                "stats": stats,
                "results": attrs.get("last_analysis_results", {})
            },
            "mitre_attack": []
        }
    except Exception as e:
        logger.error(f"Erro ao processar resposta do VT: {e} - JSON: {response_json}")
        return {"error": "Falha ao processar a resposta do VirusTotal."}

def _process_vt_behaviour_summary(summary_json: dict) -> list:
    """Extrai e formata as táticas e técnicas do MITRE ATT&CK."""
    mitre_data = []
    if not summary_json or 'data' not in summary_json:
        return mitre_data

    tactics = {}
    for technique in summary_json.get('data', {}).get('mitre_attack_techniques', []):
        for tactic_info in technique.get('tactics', []):
            tactic_name = tactic_info.get('name')
            if tactic_name not in tactics:
                tactics[tactic_name] = []
            
            tactics[tactic_name].append({
                "id": technique.get('id'),
                "name": technique.get('name'),
                "link": f"https://attack.mitre.org/techniques/{technique.get('id', '').replace('.', '/')}/"
            })

    for tactic, techniques in tactics.items():
        mitre_data.append({
            "tactic": tactic,
            "techniques": techniques
        })
        
    return mitre_data

