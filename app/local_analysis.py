import hashlib
import time
import logging
from typing import Dict, Any

from .utils import extract_strings, contains_cyrillic

logger = logging.getLogger(__name__)

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False
    logger.warning("Biblioteca 'pefile' não encontrada. Análise avançada de arquivos PE desativada.")

def analyze_pe_file(content: bytes) -> Dict[str, Any]:
    """
    Analisa um arquivo PE para detectar técnicas de malware como DLL side loading,
    execução em memória e dead drop resolver.
    """
    if not PEFILE_AVAILABLE:
        return {}

    try:
        pe = pefile.PE(data=content)
    except Exception as e:
        logger.warning(f"Erro ao analisar arquivo PE: {e}")
        return {}

    detections = {
        'dll_side_loading': False,
        'in_memory_execution': False,
        'dead_drop_resolver': False,
        'details': []
    }

    try:
        # Verificar imports para DLL side loading e execução em memória
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                try:
                    dll_name = entry.dll.decode('utf-8', errors='ignore').lower()
                except AttributeError:
                    continue
                    
                for imp in entry.imports:
                    if not imp.name: continue
                    func_name = imp.name.decode('utf-8', errors='ignore')
                    # DLL side loading indicators
                    if func_name in ['LoadLibraryA', 'LoadLibraryW', 'LoadLibraryExA', 'LoadLibraryExW', 'GetProcAddress', 'GetModuleHandleA', 'GetModuleHandleW']:
                        detections['dll_side_loading'] = True
                        detections['details'].append(f"Importa função de carregamento dinâmico: {dll_name} -> {func_name}")
                    # In-memory execution indicators
                    if func_name in ['VirtualAlloc', 'VirtualAllocEx', 'VirtualProtect', 'CreateThread', 'CreateRemoteThread', 'WriteProcessMemory', 'ReadProcessMemory']:
                        detections['in_memory_execution'] = True
                        detections['details'].append(f"Importa função de manipulação de memória: {dll_name} -> {func_name}")

        # Verificar seções executáveis para execução em memória
        if hasattr(pe, 'sections'):
            for section in pe.sections:
                section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                if section.Characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
                    # Verificar se há seções suspeitas
                    if section.SizeOfRawData > 0x100000:  # Maior que 1MB
                        detections['in_memory_execution'] = True
                        detections['details'].append(f"Seção executável muito grande: {section_name}")
                    # Seções com nomes suspeitos
                    if section_name in ['.text', '.code'] and section.SizeOfRawData > 0x50000:  # Maior que 320KB
                        detections['in_memory_execution'] = True
                        detections['details'].append(f"Seção de código suspeita: {section_name}")

        # Procurar por strings suspeitas para dead drop e outras técnicas
        # Limitamos a extração para evitar overhead em arquivos gigantes
        strings = extract_strings(content, min_len=5, max_output_bytes=16384)
        if strings:
            lower_strings = strings.lower()
            dead_drop_indicators = [
                'http://', 'https://', 'ftp://', 'pastebin.com', 'dropbox.com', 'mega.nz', 
                'anonfiles.com', 'transfer.sh', '0x0.st', 'catbox.moe', 'litterbox.catbox.moe',
                'dead.drop', 'dropper', 'resolver'
            ]
            
            for indicator in dead_drop_indicators:
                if indicator in lower_strings:
                    detections['dead_drop_resolver'] = True
                    detections['details'].append(f"Possível indicador de dead drop: {indicator}")
            
            # Verificar caminhos suspeitos para DLL side loading
            # Iterar sobre linhas pode ser mais seguro que substrings arbitrárias se strings contiver newlines
            # Mas extract_strings retorna uma única string larga.
            if '.dll' in lower_strings:
                 # Refinamento: tentar achar o contexto da dll
                 pass 

    except Exception as e:
        logger.error(f"Erro durante análise detalhada de PE: {e}", exc_info=True)

    return detections

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
            
    # Análise específica para PE files
    pe_analysis = {}
    if content.startswith(b'MZ'):
        pe_analysis = analyze_pe_file(content)
        if pe_analysis.get('dll_side_loading'):
            tags.append('dll_side_loading')
            verdict = 'suspicious'
        if pe_analysis.get('in_memory_execution'):
            tags.append('in_memory_execution')
            verdict = 'suspicious'
        if pe_analysis.get('dead_drop_resolver'):
            tags.append('dead_drop_resolver')
            verdict = 'suspicious'
    
    verdict = 'suspicious' if 'pe_executable' in tags or 'elf_executable' in tags or 'suspicious_strings' in tags or any(t in tags for t in ['dll_side_loading', 'in_memory_execution', 'dead_drop_resolver']) else 'unknown'
    
    result = {
        'filename': filename, 
        'item_type': 'file',
        'sha256': sha256, 
        'size_bytes': len(content), 
        'verdict': verdict, 
        'tags': tags, 
        'strings_snippet': strings or None, 
        'scanned_at': int(time.time())
    }
    
    if pe_analysis:
        result['pe_analysis'] = pe_analysis
    
    return result

def build_url_analysis_result(url: str, external_results: Dict[str, Any]) -> Dict[str, Any]:
    """Constrói o dicionário de resultado final para uma análise de URL."""
    return {
        "url": url,
        "item_type": "url",
        "scanned_at": int(time.time()),
        "external": {k: v for k, v in external_results.items() if v and not v.get("error")},
        "final_verdict": calculate_final_verdict('unknown', external_results)
    }

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
