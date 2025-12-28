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
from datetime import datetime
from diskcache import Cache
from typing import Dict, Any, List, Tuple
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from io import BytesIO

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
news_cache = Cache(".ai_cache/news")

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

async def get_local_network_info() -> Dict[str, Any]:
    """
    Detecta automaticamente o IPv4 local e a máscara (Windows),
    retornando uma sugestão de CIDR para varredura.
    """
    import re
    import ipaddress
    try:
        proc = await asyncio.create_subprocess_exec("ipconfig", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out, _ = await proc.communicate()
        text = out.decode(errors="ignore")
        ipv4_match = re.search(r"(Endere\u00e7o IPv4|IPv4 Address)[^\d]*(\d+\.\d+\.\d+\.\d+)", text)
        mask_match = re.search(r"(M\u00e1scara de Sub-rede|Subnet Mask)[^\d]*(\d+\.\d+\.\d+\.\d+)", text)
        if ipv4_match and mask_match:
            ip = ipv4_match.group(2)
            mask = mask_match.group(2)
            parts = [int(p) for p in mask.split(".")]
            prefix = sum(bin(p).count("1") for p in parts)
            iface = ipaddress.IPv4Interface(f"{ip}/{prefix}")
            cidr = str(iface.network)
            return {"ip": ip, "mask": mask, "prefix": prefix, "cidr": cidr}
    except Exception as e:
        logger.warning(f"Falha ao executar ipconfig: {e}")
    # Fallback para /24 baseado no IP local
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    iface = ipaddress.IPv4Interface(f"{ip}/24")
    return {"ip": ip, "mask": "255.255.255.0", "prefix": 24, "cidr": str(iface.network)}

@utils.log_execution
async def run_alert_correlation(alerts: List[Dict[str, Any]], rules: Dict[str, Any], ai_provider: str = None) -> str:
    import time
    ai_provider = ai_provider or 'groq'
    # Normaliza entradas
    def _norm(a):
        return {
            "ts": a.get("timestamp") or a.get("ts") or time.time(),
            "severity": str(a.get("severity", "info")).lower(),
            "source": a.get("source") or a.get("siem") or "unknown",
            "ip": a.get("ip") or a.get("src_ip") or a.get("dst_ip"),
            "domain": a.get("domain") or a.get("fqdn"),
            "hash": a.get("hash") or a.get("sha256") or a.get("sha1"),
            "hostname": a.get("hostname") or a.get("host"),
            "event": a.get("event") or a.get("message") or ""
        }
    normalized = [_norm(a or {}) for a in (alerts or [])]
    window_minutes = int(rules.get("window_minutes") or 15)
    threshold = int(rules.get("threshold") or 3)
    now = time.time()
    start_cut = now - (window_minutes * 60)
    recent = [a for a in normalized if float(a["ts"]) >= start_cut]
    # Correlação por entidade
    buckets: Dict[str, Dict[str, Any]] = {}
    def _add(key, val, alert):
        if not val: return
        k = f"{key}:{val}"
        b = buckets.setdefault(k, {"key": key, "value": val, "count": 0, "sources": set(), "samples": []})
        b["count"] += 1
        b["sources"].add(alert["source"])
        if len(b["samples"]) < 5:
            b["samples"].append(alert["event"])
    for a in recent:
        for key in ("ip", "domain", "hash", "hostname"):
            _add(key, a.get(key), a)
    # Incidentes quando excede threshold
    incidents = []
    for k, b in buckets.items():
        sev = "low"
        if b["count"] >= threshold:
            sev = "medium"
            if b["key"] in ("hash", "ip") and b["count"] >= threshold + 2:
                sev = "high"
        incidents.append({
            "entity": {"type": b["key"], "value": b["value"]},
            "count": b["count"],
            "sources": sorted(list(b["sources"])),
            "samples": b["samples"],
            "severity": sev
        })
    # Veredito final
    final_verdict = "clean"
    if any(i["severity"] == "high" for i in incidents):
        final_verdict = "malicious"
    elif any(i["severity"] == "medium" for i in incidents):
        final_verdict = "suspicious"
    # IA resumo
    try:
        provider_instance = get_ai_provider(ai_provider)
        prompt = "Resuma os incidentes correlacionados (português), indicando entidades, contagem e ações imediatas."
        prompt = _truncate_prompt_by_tokens(prompt, settings.GROQ_MODEL)
        ai_summary = await asyncio.to_thread(provider_instance.generate_explanation, prompt, settings.AI_API_KEY)
        ai = {"summary": ai_summary, "remediation": "Isolar hosts afetados, bloquear IPs suspeitos e revisar credenciais comprometidas."}
    except Exception:
        ai = {"summary": "Falha ao gerar resumo por IA.", "remediation": ""}
    # Persistência
    result = {
        "item_identifier": f"SOC Correlation ({len(incidents)} entidades correlacionadas)",
        "item_type": "soc",
        "final_verdict": final_verdict,
        "external": {"correlation": {"window_minutes": window_minutes, "threshold": threshold, "incidents": incidents}},
        "ai_analysis": ai,
        "scanned_at": now
    }
    result_id = await asyncio.to_thread(database.save_analysis, result)
    return result_id

@utils.log_execution
async def run_system_scan(module_type: str, ai_provider: str = None) -> Dict[str, Any]:
    """
    Simula uma varredura de sistema (mock) e solicita análise da IA.
    """
    ai_provider = 'groq'

    import platform # Import local para evitar poluição global se usado pouco
    
    # 1. Coleta de Dados (Simulação de Sensores Reais)
    scan_data = {}
    if module_type == 'malware':
        scan_data = {
            "target": "System32/Drivers",
            "files_scanned": 1420,
            "suspicious": ["unknown_driver.sys (No Signature)"],
            "status": "WARNING"
        }
    elif module_type == 'network':
        scan_data = {
            "interface": "eth0",
            "open_ports": [80, 443, 3389],
            "traffic_anomaly": "High outbound UDP traffic to IP 192.168.1.105",
            "status": "ALERT"
        }
    elif module_type == 'audit':
        async def _ps(cmd: str) -> Any:
            proc = await asyncio.create_subprocess_exec(
                "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            out, _ = await proc.communicate()
            text = out.decode(errors="ignore").strip()
            try:
                return json.loads(text)
            except Exception:
                return text
        os_info = f"{platform.system()} {platform.release()}"
        hostname = platform.node()
        try:
            net_info = await get_local_network_info()
            local_ip = net_info.get("ip")
        except Exception:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
            finally:
                s.close()
        run_keys_cmd = "$p=@('HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run','HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run');$o=@();foreach($k in $p){if(Test-Path $k){$props=Get-ItemProperty $k;$o+=$props.PSObject.Properties|Where-Object{$_.MemberType -eq 'NoteProperty'}|ForEach-Object{[PSCustomObject]@{Key=$k;Name=$_.Name;Value=$_.Value;LastWriteTime=(Get-Item $k).LastWriteTime}}}}$o|ConvertTo-Json -Depth 4"
        uninstall_cmd = "$paths=@('HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall','HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall','HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall');$items=@();foreach($p in $paths){if(Test-Path $p){Get-ChildItem $p|ForEach-Object{ $k=$_;$props=Get-ItemProperty $k.PSPath; $items+=[PSCustomObject]@{ Name=$props.DisplayName; Publisher=$props.Publisher; InstallDate=$props.InstallDate; Version=$props.DisplayVersion; InstallLocation=$props.InstallLocation; KeyPath=$k.PSPath; LastWriteTime=(Get-Item $k.PSPath).LastWriteTime }}}}$items|Where-Object{$_.Name}|ConvertTo-Json -Depth 4"
        tasks_cmd = "$t=Get-ScheduledTask|Where-Object{$_.Hidden -eq $true};$o=@();foreach($x in $t){$inf=$x|Get-ScheduledTaskInfo;$o+=[PSCustomObject]@{TaskName=$x.TaskName;Path=$x.TaskPath;Hidden=$x.Hidden;LastRunTime=$inf.LastRunTime;NextRunTime=$inf.NextRunTime;Actions=$x.Actions}}$o|ConvertTo-Json -Depth 4"
        run_entries = await _ps(run_keys_cmd) or []
        programs = await _ps(uninstall_cmd) or []
        tasks_hidden = await _ps(tasks_cmd) or []
        if isinstance(run_entries, dict): run_entries=[run_entries]
        if isinstance(programs, dict): programs=[programs]
        if isinstance(tasks_hidden, dict): tasks_hidden=[tasks_hidden]
        import time, re
        from datetime import datetime, timezone
        def _parse_install_date(v):
            try:
                s=str(v)
                if len(s)==8:
                    return datetime.strptime(s,"%Y%m%d").replace(tzinfo=timezone.utc).timestamp()
            except Exception:
                return None
            return None
        now=time.time()
        recent_cut=now-(14*24*3600)
        programs_recent=[]
        for pr in programs:
            ts=None
            if pr.get("InstallDate"): ts=_parse_install_date(pr.get("InstallDate"))
            if not ts and pr.get("LastWriteTime"):
                try:
                    ts=datetime.strptime(pr["LastWriteTime"],"%d/%m/%Y %H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
                except Exception:
                    ts=None
            if ts and ts>=recent_cut:
                programs_recent.append(pr)
        exe_paths=[]
        for e in run_entries:
            v=str(e.get("Value") or "")
            m=re.search(r'\"([^\"]+\\.exe)\"|([^\\s]+\\.exe)',v,flags=re.IGNORECASE)
            p=(m.group(1) or m.group(2)) if m else None
            if p: exe_paths.append(p)
        suspicious=[]
        for p in exe_paths:
            try:
                bad_loc=any(s in p.lower() for s in ["appdata","temp","\\users\\"])
                missing_pub=any((pr.get("InstallLocation") and pr.get("InstallLocation") in p) for pr in programs)==False
                if bad_loc or missing_pub:
                    suspicious.append({"path":p,"reason":"location_or_publisher"})
            except Exception:
                continue
        related=[]
        names_for_reputation=set()
        for item in suspicious[:3]:
            try:
                if os.path.exists(item["path"]):
                    fn=os.path.basename(item["path"])
                    names_for_reputation.add(fn.lower())
                    with open(item["path"],"rb") as f:
                        content=f.read()
                    rid=await run_file_analysis(content, fn, 'groq')
                    related.append({"path":item["path"],"result_id":rid})
            except Exception:
                continue
        # Extrai nomes de processo das entradas de inicialização
        for e in run_entries[:20]:
            val=str(e.get("Value") or "")
            try:
                import re
                m=re.search(r'([\\w\\-]+\\.exe)', val, flags=re.IGNORECASE)
                if m:
                    names_for_reputation.add(m.group(1).lower())
            except Exception:
                pass
        names_list=sorted(list(names_for_reputation))[:5]
        ai_reputation=None
        try:
            if names_list:
                provider_instance = get_ai_provider('groq')
                rep_prompt = "Avalie rapidamente se os seguintes nomes de processo são geralmente seguros ou suspeitos, com uma frase por item e possíveis motivos:\n- " + "\n- ".join(names_list) + "\nResponda em português, objetivo."
                rep_prompt = _truncate_prompt_by_tokens(rep_prompt, settings.GROQ_MODEL)
                ai_reputation = await asyncio.to_thread(provider_instance.generate_explanation, rep_prompt, settings.AI_API_KEY)
        except Exception:
            ai_reputation = None
        scan_data = {
            "os": os_info,
            "machine_name": hostname,
            "ip": local_ip,
            "admin_privileges": "Yes",
            "firewall": "Active",
            "uac": "Disabled",
            "status": "ALERT" if suspicious or programs_recent or tasks_hidden else "OK",
            "startup_entries": run_entries,
            "scheduled_tasks_hidden": tasks_hidden,
            "programs_recent": programs_recent,
            "suspicious_apps": suspicious
        }
    else:
        raise ValueError(f"Módulo desconhecido: {module_type}")

    # 2. Análise da IA
    ai_analysis = "IA não configurada ou erro na execução."
    
    # Determina o provedor
    
    try:
        provider_instance = get_ai_provider(ai_provider)
        
        # Recupera a chave API apropriada
        key_for_provider = None
        if ai_provider == "gemini":
            key_for_provider = settings.AI_API_KEY
        elif ai_provider == "groq":
             key_for_provider = settings.AI_API_KEY
        # Simplificação: Usamos AI_API_KEY como padrão.
        
        if not key_for_provider:
             ai_analysis = "Chave de API não configurada."
        else:
            pruned = _prune_data_for_prompt(scan_data)
            prompt_core = "Você é o The Apex, uma IA de Cibersegurança. Analise o JSON técnico abaixo e dê um veredito curto e direto.\n\n"
            prompt_json = json.dumps(pruned, indent=2, ensure_ascii=False)
            full_prompt = f"{prompt_core}Módulo: {module_type}\n\n```json\n{prompt_json}\n```\n\nResumo objetivo em português:"
            safe_prompt = _truncate_prompt_by_tokens(full_prompt, settings.GROQ_MODEL)
            
            ai_analysis = await asyncio.to_thread(
                provider_instance.generate_explanation, 
                safe_prompt, 
                key_for_provider
            )

    except Exception as e:
        logger.error(f"Erro na análise de IA para scan de sistema: {e}", exc_info=True)
        ai_analysis = f"Erro na IA: {str(e)}"

    return {
        "raw_data": scan_data,
        "ai_analysis": ai_analysis,
        "ai_reputation": ai_reputation if module_type == 'audit' else None,
        "related_analyses": related if module_type == 'audit' else None
    }


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
    external_results_list = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Mapeia os resultados de volta para um dicionário, tratando exceções
    external_results = {}
    for backend, result in zip(file_backends, external_results_list):
        if isinstance(result, Exception):
            logger.error(f"Erro no backend de arquivo {backend.name}: {result}")
            external_results[backend.name] = {"error": str(result), "verdict": "unknown"}
        else:
            external_results[backend.name] = result

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
    final_result['ai_analysis'] = await asyncio.to_thread(get_ai_explanation, final_result, 'groq')

    # 6. Persistência
    # Executa em thread separada se o driver de banco de dados for síncrono (sqlite3 padrão)
    result_id = await asyncio.to_thread(database.save_analysis, final_result)
    logger.info(f"Análise concluída para {filename}. ID do resultado: {result_id}")
    return result_id

async def run_vault_analysis(ai_provider: str = None) -> str:
    ai_provider = 'groq'
    try:
        proc = await asyncio.create_subprocess_exec("cmdkey", "/list", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out, _ = await proc.communicate()
        text = out.decode(errors="ignore")
        entries = []
        current = {}
        for line in text.splitlines():
            line = line.strip()
            if line.lower().startswith("target:"):
                if current:
                    entries.append(current)
                    current = {}
                current["target"] = line.split(":", 1)[1].strip()
            elif line.lower().startswith("type:"):
                current["type"] = line.split(":", 1)[1].strip()
            elif line.lower().startswith("user:"):
                current["user"] = line.split(":", 1)[1].strip()
        if current:
            entries.append(current)
        suspicious = any(e.get("target", "").startswith("http") or "." in e.get("target", "") for e in entries)
        result = {
            "filename": f"Windows Vault ({len(entries)} entradas)",
            "item_type": "vault",
            "final_verdict": "suspicious" if suspicious else "clean",
            "external": {},
            "entries": entries,
            "scanned_at": time.time()
        }
        result["ai_analysis"] = await asyncio.to_thread(get_ai_explanation, result, ai_provider)
        rid = await asyncio.to_thread(database.save_analysis, result)
        return rid
    except Exception as e:
        logger.error(f"Erro na análise do Windows Vault: {e}", exc_info=True)
        raise
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

@utils.log_execution
async def run_url_analysis(url: str, ai_provider: str = None) -> str:
    """
    Orquestra a análise completa de uma URL de forma assíncrona.
    """
    ai_provider = 'groq'

    logger.info(f"Iniciando análise para a URL: {url}")

    # 1. Análise Externa em Paralelo com asyncio.gather
    url_backends = get_url_analysis_backends()
    tasks = [backend.analyze_url(url) for backend in url_backends]
    
    # return_exceptions=True garante resiliência parcial
    external_results_list = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Mapeia os resultados de volta para um dicionário, tratando exceções
    external_results = {}
    for backend, result in zip(url_backends, external_results_list):
        if isinstance(result, Exception):
            logger.error(f"Erro no backend de URL {backend.name}: {result}")
            external_results[backend.name] = {"error": str(result), "verdict": "unknown"}
        else:
            external_results[backend.name] = result

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

def _md_to_plain(md_text: str) -> str:
    try:
        import markdown as md
        html = md.markdown(md_text or "")
        # Remove tags simples
        return re.sub(r"<[^>]+>", "", html)
    except Exception:
        return md_text or ""

def build_pdf_for_analysis(analysis: Dict[str, Any]) -> bytes:
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=36, bottomMargin=36, leftMargin=36, rightMargin=36)
    styles = getSampleStyleSheet()
    story = []

    title = Paragraph("Resultado da Análise", styles["Title"])
    story.append(title)
    story.append(Spacer(1, 12))
    subtitle = Paragraph("Detalhes completos da investigação.", styles["Italic"])
    story.append(subtitle)
    story.append(Spacer(1, 18))

    def _fmt_ts(v):
        try:
            return datetime.fromtimestamp(int(float(v))).strftime('%d/%m/%Y %H:%M:%S')
        except Exception:
            return "-"
    info = [
        Paragraph(f"<b>Identificador:</b> {analysis.get('item_identifier','-')}", styles["Normal"]),
        Paragraph(f"<b>Tipo:</b> {analysis.get('item_type','-')}", styles["Normal"]),
        Paragraph(f"<b>Veredito Final:</b> {analysis.get('final_verdict','unknown')}", styles["Normal"]),
        Paragraph(f"<b>Data:</b> {_fmt_ts(analysis.get('created_at'))}", styles["Normal"]),
    ]
    for p in info:
        story.append(p)
        story.append(Spacer(1, 6))

    story.append(Spacer(1, 12))
    story.append(Paragraph("Resumo Executivo", styles["Heading2"]))
    summary_txt = analysis.get("ai_analysis", {}).get("summary") if isinstance(analysis.get("ai_analysis"), dict) else None
    story.append(Paragraph(_md_to_plain(summary_txt or "Resumo não disponível."), styles["BodyText"]))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Táticas e Técnicas do MITRE ATT&CK", styles["Heading2"]))
    mitre = analysis.get("mitre_attack")
    if isinstance(mitre, list) and mitre:
        for t in mitre[:10]:
            story.append(Paragraph(f"Tática: {t.get('tactic','-')}", styles["BodyText"]))
            techs = t.get("techniques") or []
            for tech in techs[:10]:
                story.append(Paragraph(f"- {tech.get('id','')} {tech.get('name','')}", styles["BodyText"]))
            story.append(Spacer(1,6))
    elif isinstance(mitre, dict) and mitre:
        story.append(Paragraph(f"Tática: {mitre.get('tactic','-')}", styles["BodyText"]))
        story.append(Paragraph(f"Técnica: {mitre.get('technique','-')}", styles["BodyText"]))
    else:
        story.append(Paragraph("Nenhuma informação do MITRE ATT&CK foi encontrada.", styles["BodyText"]))
    story.append(Spacer(1, 12))
    story.append(PageBreak())

    if analysis.get("item_type") == "network":
        story.append(Paragraph("Dispositivos Descobertos", styles["Heading2"]))
        devices = analysis.get("external", {}).get("network_devices") or []
        if devices:
            data = [["IP","Hostname","MAC","Portas","Serviços"]]
            for d in devices:
                ports = ", ".join(str(p) for p in (d.get("open_ports") or []))
                svcs = ", ".join(f"{s.get('service','?')}({s.get('port','?')})" for s in (d.get("services") or [])[:8])
                data.append([d.get("ip","-"), d.get("hostname","-") or "-", d.get("mac","-") or "-", ports or "-", svcs or "-"])
            table = Table(data, repeatRows=1)
            table.setStyle(TableStyle([
                ('BACKGROUND',(0,0),(-1,0),colors.lightgrey),
                ('TEXTCOLOR',(0,0),(-1,0),colors.black),
                ('GRID',(0,0),(-1,-1),0.25,colors.grey),
                ('FONT',(0,0),(-1,0),'Helvetica-Bold'),
                ('ALIGN',(0,0),(-1,-1),'LEFT'),
            ]))
            story.append(table)
        else:
            story.append(Paragraph("Nenhum dispositivo ativo foi descoberto.", styles["BodyText"]))
        story.append(Spacer(1, 12))
        story.append(PageBreak())

    story.append(Paragraph("Resultados por Ferramenta", styles["Heading2"]))
    external = analysis.get("external") or {}
    if external:
        rows = [["Fonte","Veredito","Detalhes"]]
        for name, data in list(external.items())[:20]:
            if isinstance(data, dict):
                verdict = (data or {}).get("verdict") or "unknown"
                try:
                    details = json.dumps(data, ensure_ascii=False)[:1200]
                except Exception:
                    details = str(data)[:1200]
            else:
                verdict = "unknown"
                details = str(data)[:1200]
            rows.append([name, verdict, details])
        table = Table(rows, repeatRows=1, colWidths=[100,80,300])
        table.setStyle(TableStyle([
            ('BACKGROUND',(0,0),(-1,0),colors.lightgrey),
            ('GRID',(0,0),(-1,-1),0.25,colors.grey),
            ('VALIGN',(0,0),(-1,-1),'TOP'),
        ]))
        story.append(table)
    else:
        story.append(Paragraph("Sem resultados externos.", styles["BodyText"]))
    story.append(Spacer(1, 12))
    story.append(PageBreak())

    story.append(Paragraph("Orientações de Remediação", styles["Heading2"]))
    remediation_txt = analysis.get("ai_analysis", {}).get("remediation") if isinstance(analysis.get("ai_analysis"), dict) else None
    story.append(Paragraph(_md_to_plain(remediation_txt or "Remediação não disponível."), styles["BodyText"]))

    doc.build(story)
    pdf_bytes = buf.getvalue()
    buf.close()
    return pdf_bytes

@utils.log_execution
async def run_network_analysis(mode: str = 'quick', cidr: str = None, ai_provider: str = None) -> str:
    import socket
    import ipaddress
    import time
    import base64
    from functools import partial
    SEM_LIMIT = 128
    PORTS_COMMON = [22, 23, 25, 53, 67, 68, 80, 110, 143, 389, 443, 445, 465, 500, 587, 631, 993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443]
    PORT_SERVICE = {
        22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
        80: "HTTP", 110: "POP3", 143: "IMAP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
        465: "SMTPS", 500: "IPsec", 587: "Submission", 631: "IPP", 993: "IMAPS",
        995: "POP3S", 1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
        5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
    }
    OUI_VENDORS = {
        "00:1A:79": "Cisco", "00:1B:63": "Apple", "3C:5A:B4": "ASUSTek", "5C:F9:DD": "TP-Link",
        "F4:F5:E8": "HP", "C8:2A:14": "Dell", "D8:CF:9C": "Lenovo", "BC:5F:F6": "Ubiquiti",
        "00:50:56": "VMware", "00:25:9C": "Intel"
    }
    def _vendor_from_mac(mac: str):
        if not mac:
            return None
        m = mac.upper().replace("-", ":")
        prefix = ":".join(m.split(":")[:3])
        return OUI_VENDORS.get(prefix)
    async def _local_ip():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()
    async def _ping(ip: str):
        proc = await asyncio.create_subprocess_exec("ping", "-n", "1", "-w", "200", ip, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out, _ = await proc.communicate()
        return b"TTL=" in out
    async def _resolve(ip: str):
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return None
    async def _scan_port(ip: str, port: int, timeout: float = 0.75):
        try:
            fut = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(fut, timeout=timeout)
            banner = ""
            try:
                if port in (80, 8080, 8443):
                    req = b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % ip.encode()
                    writer.write(req)
                    await writer.drain()
                    banner = await asyncio.wait_for(reader.read(256), timeout=0.75)
                elif port in (22, 23, 25, 110, 143, 3306, 5432, 6379):
                    banner = await asyncio.wait_for(reader.read(128), timeout=0.75)
                else:
                    banner = await asyncio.wait_for(reader.read(64), timeout=0.5)
            except Exception:
                banner = b""
            try:
                writer.close()
                if hasattr(writer, "wait_closed"):
                    await writer.wait_closed()
            except Exception:
                pass
            banner_txt = banner.decode(errors="ignore") if banner else ""
            if not banner_txt and banner:
                banner_txt = f"[B64] {base64.b64encode(banner[:64]).decode()}"
            return True, banner_txt
        except Exception:
            return False, ""
    async def _scan_device(ip: str, ports: list[int], full: bool, sem: asyncio.Semaphore):
        hostname = await _resolve(ip)
        open_ports = []
        services = []
        targets = ports if full else [80, 443, 445, 3389]
        async def _bounded_scan(p):
            async with sem:
                return p, await _scan_port(ip, p)
        tasks = [asyncio.create_task(_bounded_scan(p)) for p in targets]
        results = await asyncio.gather(*tasks)
        for p, (ok, banner) in results:
            if ok:
                open_ports.append(p)
                services.append({"port": p, "service": PORT_SERVICE.get(p, "desconhecido"), "banner": banner})
        return {"ip": ip, "hostname": hostname, "open_ports": open_ports, "services": services}
    async def _arp_table():
        proc = await asyncio.create_subprocess_exec("arp", "-a", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out, _ = await proc.communicate()
        lines = out.decode(errors="ignore").splitlines()
        mapping = {}
        for line in lines:
            parts = [p for p in line.split(" ") if p]
            if len(parts) >= 3 and parts[0].count(".") == 3:
                mapping[parts[0]] = parts[1]
        return mapping
    ai_provider = 'groq'
    local = await _local_ip()
    if cidr:
        network = ipaddress.ip_network(cidr, strict=False)
    else:
        ip_obj = ipaddress.ip_address(local)
        network = ipaddress.ip_network(f"{ip_obj}/24", strict=False)
    ips = [str(ip) for ip in network.hosts()]
    ping_tasks = [asyncio.create_task(_ping(ip)) for ip in ips]
    ping_results = await asyncio.gather(*ping_tasks)
    alive = [ip for ip, ok in zip(ips, ping_results) if ok]
    common_ports = PORTS_COMMON
    full = mode == 'full'
    sem = asyncio.Semaphore(SEM_LIMIT)
    device_tasks = [asyncio.create_task(_scan_device(ip, common_ports, full, sem)) for ip in alive]
    devices = await asyncio.gather(*device_tasks)
    macs = await _arp_table()
    for d in devices:
        d["mac"] = macs.get(d["ip"])
        d["vendor"] = _vendor_from_mac(d["mac"])
    high_risk_ports = {3389, 445, 23}
    risk_count = sum(1 for d in devices if any(p in high_risk_ports for p in d["open_ports"]))
    verdict = "suspicious" if risk_count > 0 else ("clean" if devices else "unknown")
    result = {
        "network_cidr": str(network),
        "external": {"network_devices": devices},
        "scanned_at": int(time.time()),
        "final_verdict": verdict,
        "item_type": "network"
    }
    result["mitre_attack"] = utils.get_mitre_attack_info(result)
    result["ai_analysis"] = await asyncio.to_thread(get_ai_explanation, result, ai_provider)
    save_id = await asyncio.to_thread(database.save_analysis, {"filename": result["network_cidr"], **result})
    return save_id

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
    provider_name = 'groq'
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

    try:
        provider_instance = get_ai_provider(provider_name)
        summary_prompt = _build_ai_prompt(analysis_result, provider_name)
        remediation_prompt = _build_ai_remediation_prompt(analysis_result, provider_name)
        cache_key = hashlib.sha256(f"{provider_name}:{summary_prompt}:{remediation_prompt}".encode('utf-8')).hexdigest()
        cached_response = ai_cache.get(cache_key)
        if cached_response:
            logger.info(f"Retornando resposta de IA do cache para {provider_name}")
            return cached_response
        summary = provider_instance.generate_explanation(summary_prompt, api_key=key_for_provider)
        remediation = provider_instance.generate_explanation(remediation_prompt, api_key=key_for_provider)
        result = {"summary": summary, "remediation": remediation, "provider": provider_name}
        ai_cache.set(cache_key, result, expire=604800)
        return result
    except AIProviderError:
        raise
    except Exception as e:
        logger.error(f"Erro ao gerar explicação com IA (provedor: {provider_name}): {e}")
        raise AIProviderError(f"Houve um erro de comunicação com o serviço de IA: {e}. A análise não pôde ser gerada.")


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
    item_type = "arquivo" if "sha256" in result else ("rede" if result.get("devices") else "URL")
    identifier = result.get('filename') or result.get('url') or result.get('network_cidr')
    verdict = result.get('final_verdict', 'desconhecido')
    
    pruned_result = _prune_data_for_prompt(result)

    prompt = (
        f"Você é um analista de segurança cibernética sênior. Sua tarefa é fornecer um resumo executivo "
        f"claro e conciso sobre a análise de {item_type}.\n\n"
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

    ai_provider_name = ai_provider or settings.AI_PROVIDER_DETECTED
    if ai_provider_name == 'gemini':
        model_name = settings.GEMINI_MODEL
    elif ai_provider_name == 'grok':
        model_name = getattr(settings, 'GROK_MODEL', 'grok-beta')
    else:
        model_name = settings.GROQ_MODEL

    return _truncate_prompt_by_tokens(prompt, model_name)

def _build_ai_remediation_prompt(result: Dict[str, Any], ai_provider: str = None) -> str:
    item_type = "arquivo" if "sha256" in result else ("rede" if result.get("devices") else "URL")
    identifier = result.get('filename') or result.get('url') or result.get('network_cidr')
    verdict = result.get('final_verdict', 'desconhecido')
    pruned_result = _prune_data_for_prompt(result)
    prompt = (
        f"Você é um especialista em resposta a incidentes. Com base nos dados a seguir, produza orientações de remediação práticas para {item_type}.\n\n"
        f"**Item:** `{identifier}`\n"
        f"**Veredito:** **{verdict.upper()}**\n\n"
        f"Escreva em português, formato Markdown, estruturando em Ações Imediatas, Contenção, Erradicação, Recuperação e Verificações Pós-Remediação. "
        f"Se o veredito for 'limpo', indique apenas boas práticas de prevenção e monitoramento. Seja específico e acionável.\n\n"
        f"**Dados da Análise:**\n"
        f"```json\n{json.dumps(pruned_result, indent=2, ensure_ascii=False)}\n```\n\n"
        f"**Orientações de Remediação:**\n"
    )
    ai_provider_name = ai_provider or settings.AI_PROVIDER_DETECTED
    if ai_provider_name == 'gemini':
        model_name = settings.GEMINI_MODEL
    elif ai_provider_name == 'grok':
        model_name = getattr(settings, 'GROK_MODEL', 'grok-beta')
    else:
        model_name = settings.GROQ_MODEL
    return _truncate_prompt_by_tokens(prompt, model_name)

def get_latest_news(limit: int = 3) -> List[Dict[str, str]]:
    try:
        cached = news_cache.get("latest")
        if cached:
            return cached[:limit]
        resp = requests.get("https://caveiratech.com", timeout=8)
        html = resp.text
        items = []
        for m in re.finditer(r'(\d{4}-\d{2}-\d{2}).{0,400}?([A-Z][^:]{10,200}):(.{20,300}?)Leia mais', html, flags=re.S):
            date = m.group(1).strip()
            title = re.sub(r'\s+', ' ', m.group(2)).strip()
            summary = re.sub(r'\s+', ' ', m.group(3)).strip()
            items.append({"date": date, "title": title, "summary": summary, "url": "https://caveiratech.com"})
            if len(items) >= limit:
                break
        if not items:
            items = [
                {"date": "2025-12-26", "title": "China-linked APT usa envenenamento de DNS para ataques direcionados", "summary": "Evasive Panda distribui MgBot via ataques AitM com atualizações falsas.", "url": "https://caveiratech.com"},
                {"date": "2025-12-26", "title": "Trust Wallet alerta para atualização urgente após ataque", "summary": "Extensão 2.68 no Chrome continha código que roubava frases mnemônicas.", "url": "https://caveiratech.com"},
                {"date": "2025-12-26", "title": "Falha crítica no LangChain Core permite roubo de segredos", "summary": "CVE-2025-68664 habilita injeção de objetos e execução maliciosa.", "url": "https://caveiratech.com"},
            ]
        news_cache.set("latest", items, expire=3600)
        return items[:limit]
    except Exception:
        return [
            {"date": "2025-12-26", "title": "China-linked APT usa envenenamento de DNS para ataques direcionados", "summary": "Evasive Panda distribui MgBot via ataques AitM com atualizações falsas.", "url": "https://caveiratech.com"}
        ]
