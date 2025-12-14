import hashlib
import time
from typing import Dict, Any

from .utils import extract_strings, contains_cyrillic


def analyze_bytes(content: bytes, filename: str) -> Dict[str, Any]:
    """
    Realiza uma análise estática local e segura do conteúdo de um arquivo.

    Calcula o SHA256, identifica tipos de arquivos por magic bytes e busca
    por strings suspeitas no conteúdo.

    Args:
        content (bytes): O conteúdo binário do arquivo a ser analisado.
        filename (str): O nome original do arquivo.

    Returns:
        Dict[str, Any]: Um dicionário contendo os resultados da análise, incluindo:
                        - 'file_name' (str): Nome do arquivo.
                        - 'sha256' (str): Hash SHA256 do conteúdo.
                        - 'size_bytes' (int): Tamanho do arquivo em bytes.
                        - 'verdict' (str): Veredito inicial ('suspicious', 'unknown').
                        - 'tags' (list[str]): Lista de tags identificadas (ex: 'pe_executable', 'suspicious_strings').
                        - 'strings_snippet' (str | None): Um trecho das strings extraídas.
                        - 'scanned_at' (int): Timestamp Unix do momento da análise.
    """
    sha256 = hashlib.sha256(content).hexdigest()
    tags = []
    if content.startswith(b'MZ'): tags.append('pe_executable')
    if content.startswith(b'\x7fELF'): tags.append('elf_executable')
    if content.startswith(b'%PDF'): tags.append('pdf')
    if content.startswith(b'PK\x03\x04'): tags.append('zip_like')
    
    strings = extract_strings(content, min_len=8, max_output_bytes=8192)
    if strings:
        lower_strings = strings.lower()
        if any(s in lower_strings for s in ['powershell', 'eval(', 'base64', 'suspicious']):
            tags.append('suspicious_strings')
            
    verdict = 'suspicious' if 'pe_executable' in tags or 'elf_executable' in tags or 'suspicious_strings' in tags else 'unknown'
    
    return {
        'filename': filename, 
        'sha256': sha256, 
        'size_bytes': len(content), 
        'verdict': verdict, 
        'tags': tags, 
        'strings_snippet': strings or None, 
        'scanned_at': int(time.time())
    }

def build_url_analysis_result(url: str, external_results: Dict[str, Any]) -> Dict[str, Any]:
    """Constrói o dicionário de resultado final para uma análise de URL."""
    results = {
        "url": url,
        "scanned_at": int(time.time()),
        "results": {k: v for k, v in external_results.items() if v and not v.get("error")},
        "final_verdict": calculate_final_verdict('unknown', external_results)
    }
    return results

def calculate_final_verdict(local_verdict: str, external_results: Dict[str, Any]) -> str:

    """Calcula o veredito final com base nos resultados locais e externos, seguindo uma lógica de prioridade."""

    all_verdicts = [res.get('verdict') for res in external_results.values() if res and 'verdict' in res]

    if local_verdict != 'unknown':

        all_verdicts.append(local_verdict)



    if not all_verdicts: return 'unknown'

    if 'malicious' in all_verdicts: return 'malicious'

    if 'suspicious' in all_verdicts: return 'suspicious'

    if all(v == 'clean' for v in all_verdicts): return 'clean'

    return 'unknown'



SENSITIVE_KEYWORDS = {

    "betting": ["bet", "aposta", "casino", "poker", "roleta", "betano", "bet365", "pixbet", "sportingbet"],

    "pornography": ["porn", "sex", "xxx", "adulto", "puta", "brasileirinhas", "redtube", "xvideos"]

}



def analyze_url_for_sensitive_content(url: str) -> dict:

    """

    Realiza uma análise local simples na string da URL em busca de palavras-chave sensíveis.

    """

    # Extrai o nome do domínio para análise (ex: 'www.betano.com' de 'https://www.betano.com/path')

    try:

        domain = url.split('/')[2]

    except IndexError:

        domain = url # Fallback caso a URL não tenha o formato esperado



    domain_lower = domain.lower()

    tags = []

    message = None

    verdict = "unknown"



    for category, keywords in SENSITIVE_KEYWORDS.items():

        if any(keyword in domain_lower for keyword in keywords):

            tags.append(category)



    if "betting" in tags:

        message = "Este site parece ser relacionado a apostas. Se você ou alguém que conhece tem problemas com jogos de azar, procure ajuda especializada. Existem organizações que podem oferecer suporte."

        verdict = "suspicious"

    elif "pornography" in tags:

        message = "Este site parece conter conteúdo pornográfico. Se o acesso a este tipo de conteúdo é um problema para você, considere procurar ajuda profissional ou utilizar ferramentas de bloqueio."

        verdict = "suspicious"



    if message:

        return {

            "verdict": verdict,

            "tags": tags,

            "summary": message

        }

    return {}
