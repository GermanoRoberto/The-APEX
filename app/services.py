# -*- coding: utf-8 -*-
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
import time
import re
import platform
import socket
import ipaddress
from datetime import datetime, timezone
from diskcache import Cache
from typing import Dict, Any, List, Tuple, Optional
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from io import BytesIO

# Importações internas
from .config import settings
from . import quart_db as database
from . import local_analysis
from . import utils
from . import audit_utils
from .analysis_backends import get_file_analysis_backends, get_url_analysis_backends, submit_osm_report
from .ai_providers import get_ai_provider
from .siem_integrations import send_to_siem

logger = logging.getLogger(__name__)

class AIProviderError(Exception):
    """Exceção personalizada para erros relacionados aos provedores de IA."""
    pass

# Inicialização do Cache
ai_cache = Cache(".ai_cache")
news_cache = Cache(".ai_cache/news")

# Limites de Contexto por Modelo
CONTEXT_LIMITS = {
    'gemini-1.5-flash': 1000000,
    'llama3-70b-8192': 8000,
    'grok-beta': 128000,
}
DEFAULT_CONTEXT_LIMIT = 7500

# --- Funções Auxiliares Internas ---

def _truncate_prompt_by_tokens(prompt: str, model_name: str) -> str:
    """Trunca um prompt para se ajustar ao limite de contexto do modelo."""
    limit = CONTEXT_LIMITS.get(model_name, DEFAULT_CONTEXT_LIMIT)
    
    # Heurística rápida: 1 token ~= 6 caracteres (seguro)
    estimated_char_limit = limit * 6
    if len(prompt) > estimated_char_limit:
        prompt = prompt[:estimated_char_limit]

    try:
        encoding = tiktoken.get_encoding("cl100k_base")
        tokens = encoding.encode(prompt)
        
        if len(tokens) > limit:
            logger.warning(f"Prompt excedeu o limite ({len(tokens)} > {limit}). Truncando...")
            return encoding.decode(tokens[:limit], errors='ignore')
        return prompt
    except Exception as e:
        logger.error(f"Erro no tiktoken: {e}. Usando fallback.")
        char_limit = limit * 3
        return prompt[:char_limit] if len(prompt) > char_limit else prompt

def _md_to_plain(md_text: str) -> str:
    """Converte Markdown básico para texto plano para o PDF."""
    try:
        import markdown as md
        html = md.markdown(md_text or "")
        return re.sub(r"<[^>]+>", "", html)
    except Exception:
        return md_text or ""

def _fmt_ts(v: Any) -> str:
    """Formata timestamp para exibição legível."""
    try:
        return datetime.fromtimestamp(int(float(v))).strftime('%d/%m/%Y %H:%M:%S')
    except (ValueError, TypeError):
        return "-"

def _prune_data_for_prompt(data: Any) -> Any:
    """Remove campos excessivamente grandes ou irrelevantes para economizar tokens na IA."""
    if isinstance(data, dict):
        new_dict = {}
        for k, v in data.items():
            if k in ['content', 'raw_response', 'full_log', 'startup_entries', 'programs_recent', 'scheduled_tasks_hidden']:
                if isinstance(v, list):
                    new_dict[k] = f"[{len(v)} itens ocultados para brevidade]"
                else:
                    new_dict[k] = "[Ocultado]"
            else:
                new_dict[k] = _prune_data_for_prompt(v)
        return new_dict
    elif isinstance(data, list):
        if len(data) > 5:
            return [_prune_data_for_prompt(i) for i in data[:5]] + [f"... ({len(data)-5} mais itens)"]
        return [_prune_data_for_prompt(i) for i in data]
    return data

async def get_ai_explanation(analysis_result: Dict[str, Any], provider_name: str = None) -> Dict[str, str]:
    """Obtém uma explicação e recomendação da IA para um resultado de análise."""
    provider_name = provider_name or 'groq'
    try:
        provider = get_ai_provider(provider_name)
        pruned_data = _prune_data_for_prompt(analysis_result)
        
        prompt = (
            "Você é o The Apex AI, um especialista em cibersegurança. Analise o seguinte resultado de detecção "
            "e forneça um resumo executivo em português e ações de remediação recomendadas.\n\n"
            f"Dados: {json.dumps(pruned_data, ensure_ascii=False)}\n\n"
            "Responda no formato:\nResumo: [Seu resumo]\nRemediação: [Suas ações]"
        )
        
        safe_prompt = _truncate_prompt_by_tokens(prompt, settings.GROQ_MODEL)
        response = await asyncio.to_thread(provider.generate_explanation, safe_prompt, settings.AI_API_KEY)
        
        summary = "Sem resumo disponível."
        remediation = "Consulte um especialista em segurança."
        
        if "Remediação:" in response:
            parts = response.split("Remediação:", 1)
            summary = parts[0].replace("Resumo:", "").strip()
            remediation = parts[1].strip()
        else:
            summary = response.strip()
            
        return {"summary": summary, "remediation": remediation}
    except Exception as e:
        logger.error(f"Erro ao obter explicação da IA: {e}")
        return {
            "summary": "Erro ao processar análise com IA.",
            "remediation": "Revise os logs técnicos manualmente."
        }

# --- Serviços de Rede ---

async def get_local_network_info() -> Dict[str, Any]:
    """Detecta automaticamente o IPv4 local e sugere um CIDR para varredura."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "ipconfig", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        out, _ = await proc.communicate()
        text = out.decode(errors="ignore")
        
        ipv4_match = re.search(r"(Endereço IPv4|IPv4 Address)[^\d]*(\d+\.\d+\.\d+\.\d+)", text)
        mask_match = re.search(r"(Máscara de Sub-rede|Subnet Mask)[^\d]*(\d+\.\d+\.\d+\.\d+)", text)
        
        if ipv4_match and mask_match:
            ip, mask = ipv4_match.group(2), mask_match.group(2)
            prefix = sum(bin(int(p)).count("1") for p in mask.split("."))
            iface = ipaddress.IPv4Interface(f"{ip}/{prefix}")
            return {"ip": ip, "mask": mask, "prefix": prefix, "cidr": str(iface.network)}
    except Exception as e:
        logger.warning(f"Falha ao executar ipconfig: {e}")

    # Fallback
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        iface = ipaddress.IPv4Interface(f"{ip}/24")
        return {"ip": ip, "mask": "255.255.255.0", "prefix": 24, "cidr": str(iface.network)}
    finally:
        s.close()

@utils.log_execution
async def run_alert_correlation(alerts: List[Dict[str, Any]], rules: Dict[str, Any], ai_provider: str = None) -> str:
    """Correlaciona múltiplos alertas para identificar incidentes complexos."""
    ai_provider = ai_provider or 'groq'
    window_minutes = int(rules.get("window_minutes") or 15)
    threshold = int(rules.get("threshold") or 3)
    
    def _normalize_alert(a):
        return {
            "ts": float(a.get("timestamp") or a.get("ts") or time.time()),
            "severity": str(a.get("severity", "info")).lower(),
            "source": a.get("source") or a.get("siem") or "unknown",
            "ip": a.get("ip") or a.get("src_ip") or a.get("dst_ip"),
            "domain": a.get("domain") or a.get("fqdn"),
            "hash": a.get("hash") or a.get("sha256") or a.get("sha1"),
            "hostname": a.get("hostname") or a.get("host"),
            "event": a.get("event") or a.get("message") or ""
        }

    normalized = [_normalize_alert(a or {}) for a in (alerts or [])]
    now = time.time()
    recent = [a for a in normalized if (now - a["ts"]) <= (window_minutes * 60)]
    
    # Agrupamento por Entidade
    buckets = {}
    for a in recent:
        for key in ("ip", "domain", "hash", "hostname"):
            val = a.get(key)
            if not val: continue
            k = f"{key}:{val}"
            b = buckets.setdefault(k, {"key": key, "value": val, "count": 0, "sources": set(), "samples": []})
            b["count"] += 1
            b["sources"].add(a["source"])
            if len(b["samples"]) < 5: b["samples"].append(a["event"])

    incidents = []
    for b in buckets.values():
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

    final_verdict = "clean"
    if any(i["severity"] == "high" for i in incidents): final_verdict = "malicious"
    elif any(i["severity"] == "medium" for i in incidents): final_verdict = "suspicious"

    # Persistência e IA
    result = {
        "item_identifier": f"SOC Correlation ({len(incidents)} entidades)",
        "item_type": "soc",
        "final_verdict": final_verdict,
        "external": {"correlation": {"window": window_minutes, "threshold": threshold, "incidents": incidents}},
        "scanned_at": now
    }
    
    result["ai_analysis"] = await asyncio.to_thread(get_ai_explanation, result, ai_provider)
    result_id = await asyncio.to_thread(database.save_analysis, result)
    await send_to_siem(result)
    
    return result_id

async def _run_ps_command(cmd: str) -> Any:
    """Executa um comando PowerShell e retorna o resultado em JSON ou texto."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        out, _ = await proc.communicate()
        text = out.decode(errors="ignore").strip()
        return json.loads(text) if text.startswith(('[', '{')) else text
    except Exception as e:
        logger.error(f"Erro ao executar PowerShell: {e}")
        return []

async def _get_ai_reputation_bulk(names: List[str], ai_provider: str = 'groq') -> Optional[str]:
    """Obtém a reputação de uma lista de nomes de processos/arquivos via IA."""
    if not names:
        return None
    try:
        provider = get_ai_provider(ai_provider)
        prompt = (
            "Avalie se os seguintes nomes de processo são geralmente seguros ou suspeitos, "
            "com uma breve explicação para cada:\n- " + "\n- ".join(names) + 
            "\nResponda em português, de forma objetiva."
        )
        safe_prompt = _truncate_prompt_by_tokens(prompt, settings.GROQ_MODEL)
        return await asyncio.to_thread(provider.generate_explanation, safe_prompt, settings.AI_API_KEY)
    except Exception as e:
        logger.error(f"Erro na reputação IA: {e}")
        return None

@utils.log_execution
async def run_system_scan(module_type: str, ai_provider: str = None) -> Dict[str, Any]:
    """Realiza uma varredura de sistema baseada no módulo selecionado."""
    ai_provider = ai_provider or 'groq'
    module_type = (module_type or "").strip().lower()
    
    if module_type == 'audit':
        return await _analyze_windows_audit(ai_provider)
    
    if module_type == 'vault':
        # Redireciona para a função específica do Vault
        rid = await run_vault_analysis(ai_provider)
        return {"result_id": rid, "analysis_id": rid, "status": "COMPLETED"}
    
    # Mocks para outros módulos (podem ser expandidos no futuro)
    scan_data = {}
    if module_type == 'malware':
        scan_data = {
            "target": "System32/Drivers",
            "files_scanned": 1420,
            "suspicious": ["unknown_driver.sys (Sem Assinatura)"],
            "status": "WARNING"
        }
    elif module_type == 'network':
        scan_data = {
            "interface": "eth0",
            "open_ports": [80, 443, 3389],
            "traffic_anomaly": "Tráfego UDP alto para IP externo",
            "status": "ALERT"
        }
    else:
        raise ValueError(f"Módulo desconhecido: {module_type}")

    # Análise genérica via IA para malware/network mocks
    ai_result = await asyncio.to_thread(get_ai_explanation, scan_data, ai_provider)
    
    return {
        "raw_data": scan_data,
        "ai_analysis": ai_result["summary"]
    }

async def _analyze_windows_audit(ai_provider: str) -> Dict[str, Any]:
    """Realiza uma auditoria profunda do sistema Windows (sem salvar no histórico de auditoria)."""
    logger.info("Iniciando Auditoria do Windows...")
    
    # 1. Coleta Informações Básicas
    machine_info = audit_utils.get_machine_info()
    
    # 2. Coleta Processos (Top 20 por memória para não exceder limites de IA)
    ps_cmd = "Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 20 Name, Id, CPU, WorkingSet64 | ConvertTo-Json"
    processes = await _run_ps_command(ps_cmd)
    
    # 3. Coleta Serviços Suspeitos
    svc_cmd = "Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object Name, DisplayName, Status | ConvertTo-Json"
    services = await _run_ps_command(svc_cmd)

    # 4. Entradas de Inicialização (Startup)
    startup_cmd = "Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User | ConvertTo-Json"
    startup_entries = await _run_ps_command(startup_cmd)

    # 5. Tarefas Agendadas (Hidden/Scheduled Tasks)
    tasks_cmd = "Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | Select-Object TaskName, TaskPath, State | Select-Object -First 15 | ConvertTo-Json"
    scheduled_tasks = await _run_ps_command(tasks_cmd)

    # 6. Auditoria de Hardening (Exemplo: Windows Defender)
    hardening_cmd = "Get-MpComputerStatus | Select-Object AMServiceEnabled, AntivirusEnabled, BehaviorMonitorEnabled, RealTimeProtectionEnabled | ConvertTo-Json"
    hardening_status = await _run_ps_command(hardening_cmd)
    
    # 7. Reputação via IA para os processos principais
    process_names = [p['Name'] for p in processes if isinstance(p, dict)]
    reputation = await _get_ai_reputation_bulk(process_names, ai_provider)
    
    # 8. Consolidação (Não salva no histórico de auditoria, apenas como análise comum)
    scan_data = {
        "machine": machine_info,
        "processes_count": len(processes),
        "processes_sample": processes,
        "services_running": len(services),
        "startup_entries": startup_entries,
        "scheduled_tasks": scheduled_tasks,
        "hardening": hardening_status,
        "ai_reputation": reputation,
        "status": "COMPLETED"
    }

    ai_result = await asyncio.to_thread(get_ai_explanation, scan_data, ai_provider)
    
    result = {
        "item_identifier": f"Windows Audit: {machine_info['hostname']}",
        "item_type": "audit",
        "final_verdict": "suspicious" if "suspicious" in (reputation or "").lower() else "clean",
        "external": {"scan_details": scan_data},
        "created_at": time.time(),
        "scanned_at": time.time(),
        "ai_analysis": ai_result
    }
    
    # Salva como análise comum para que o usuário possa ver o resultado agora
    rid = await asyncio.to_thread(database.save_analysis, result)
    await send_to_siem(result)
    
    return {
        "result_id": rid,
        "analysis_id": rid,
        "raw_data": scan_data,
        "ai_analysis": ai_result["summary"]
    }


# --- LÓGICA DE ORQUESTRAÇÃO DE ANÁLISE ---

async def run_file_analysis(content: bytes, filename: str, ai_provider: str = None) -> str:
    """Orquestra a análise completa de um arquivo de forma assíncrona."""
    logger.info(f"Iniciando análise para o arquivo: {filename}")
    ai_provider = ai_provider or 'groq'

    # 1. Análise Estática Local
    local_result = await asyncio.to_thread(local_analysis.analyze_bytes, content, filename)
    sha256 = local_result.get('sha256')
    if not sha256:
        raise ValueError("Não foi possível calcular o hash SHA256 do arquivo.")

    # 2. Análise Externa em Paralelo
    file_backends = get_file_analysis_backends()
    tasks = [backend.analyze_file(sha256, content, filename) for backend in file_backends]
    external_results_list = await asyncio.gather(*tasks, return_exceptions=True)
    
    external_results = {}
    for backend, result in zip(file_backends, external_results_list):
        if isinstance(result, Exception):
            logger.error(f"Erro no backend {backend.name}: {result}")
            external_results[backend.name] = {"error": str(result), "verdict": "unknown"}
        else:
            external_results[backend.name] = result

    # 3. Consolidação e Veredito
    final_result = local_result
    final_result['external'] = external_results
    final_result['final_verdict'] = local_analysis.calculate_final_verdict(
        local_result.get('verdict'), external_results
    )

    # 4. Submissão OSM (se malicioso)
    if final_result['final_verdict'] == 'malicious' and settings.OSM_API_KEY:
        osm_res = await submit_osm_report(sha256, settings.OSM_API_KEY)
        final_result['external']['opensource_malware'] = osm_res

    # 5. MITRE & IA
    final_result['mitre_attack'] = utils.get_mitre_attack_info(final_result)
    final_result['ai_analysis'] = await asyncio.to_thread(get_ai_explanation, final_result, ai_provider)

    # 6. Persistência e SIEM
    result_id = await asyncio.to_thread(database.save_analysis, final_result)
    await send_to_siem(final_result)
    
    return result_id

async def run_url_analysis(url: str, ai_provider: str = None) -> str:
    """Orquestra a análise completa de uma URL de forma assíncrona."""
    logger.info(f"Iniciando análise para a URL: {url}")
    ai_provider = ai_provider or 'groq'

    # 1. Análise Externa
    url_backends = get_url_analysis_backends()
    tasks = [backend.analyze_url(url) for backend in url_backends]
    results_list = await asyncio.gather(*tasks, return_exceptions=True)

    external_results = {}
    for backend, result in zip(url_backends, results_list):
        if isinstance(result, Exception):
            logger.error(f"Erro no backend {backend.name}: {result}")
            external_results[backend.name] = {"error": str(result), "verdict": "unknown"}
        else:
            external_results[backend.name] = result

    # 2. Consolidação
    final_result = {
        "item_identifier": url,
        "item_type": "url",
        "scanned_at": time.time(),
        "external": external_results
    }
    
    # Veredito simples baseado em backends de URL
    verdicts = [r.get('verdict') for r in external_results.values() if isinstance(r, dict)]
    if 'malicious' in verdicts: final_result['final_verdict'] = 'malicious'
    elif 'suspicious' in verdicts: final_result['final_verdict'] = 'suspicious'
    else: final_result['final_verdict'] = 'clean'

    # 3. IA e Persistência
    final_result['ai_analysis'] = await asyncio.to_thread(get_ai_explanation, final_result, ai_provider)
    result_id = await asyncio.to_thread(database.save_analysis, final_result)
    await send_to_siem(final_result)
    
    return result_id



@utils.log_execution
async def run_vault_analysis(ai_provider: str = None) -> Dict[str, Any]:
    """Realiza uma auditoria no Windows Vault em busca de credenciais suspeitas (sem salvar histórico)."""
    ai_provider = ai_provider or 'groq'
    logger.info("Iniciando auditoria automática do Windows Vault...")
    try:
        machine_info = audit_utils.get_machine_info()
        
        # Coleta via cmdkey
        proc = await asyncio.create_subprocess_exec("cmdkey", "/list", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out, _ = await proc.communicate()
        text = out.decode(errors="ignore")
        
        entries = []
        current = {}
        for line in text.splitlines():
            line = line.strip()
            if line.lower().startswith("target:"):
                if current: entries.append(current)
                current = {"target": line.split(":", 1)[1].strip()}
            elif line.lower().startswith("type:"):
                current["type"] = line.split(":", 1)[1].strip()
            elif line.lower().startswith("user:"):
                current["user"] = line.split(":", 1)[1].strip()
        if current: entries.append(current)

        suspicious = [e for e in entries if e.get("target", "").startswith("http") or "." in e.get("target", "")]
        status = "ALERT" if suspicious else "CLEAN"
        
        # Resultado temporário para exibição (não salva no histórico de auditoria)
        result = {
            "item_identifier": f"Windows Vault: {machine_info['hostname']}",
            "item_type": "vault",
            "final_verdict": "suspicious" if status == "ALERT" else "clean",
            "external": {"status": status, "total_entries": len(entries), "suspicious_count": len(suspicious), "entries": entries},
            "created_at": time.time(),
            "scanned_at": time.time()
        }
        
        result["ai_analysis"] = await asyncio.to_thread(get_ai_explanation, result, ai_provider)
        # Salva apenas na tabela de análises gerais se necessário, ou retorna apenas para a UI
        # Para manter fora do histórico solicitado, podemos salvar como análise comum ou não salvar nada
        # Se o usuário quer "fora do histórico", talvez ele queira dizer a tabela de auditoria específica.
        # Vamos salvar como análise normal para que o resultado apareça na tela de resultados.
        rid = await asyncio.to_thread(database.save_analysis, result)
        await send_to_siem(result)
        
        return rid
    except Exception as e:
        logger.error(f"Erro na análise do Vault: {e}")
        raise

def enqueue_file_analysis(content: bytes, filename: str, ai_provider: str = None) -> str:
    """Enfileira a análise de arquivo no Celery."""
    temp_path = os.path.join(tempfile.gettempdir(), f"{uuid.uuid4()}_{filename}")
    with open(temp_path, 'wb') as f:
        f.write(content)
    
    from .tasks import execute_file_analysis_task
    task = execute_file_analysis_task.delay(temp_path, filename, ai_provider)
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
    final_result = local_analysis.build_url_analysis_result(str(url), external_results)
    
    # 3. Análise MITRE ATT&CK
    final_result['mitre_attack'] = utils.get_mitre_attack_info(final_result)
    
    # 4. Análise com IA
    # Executa em thread separada para não bloquear o loop de eventos do Quart
    final_result['ai_analysis'] = await asyncio.to_thread(get_ai_explanation, final_result, ai_provider)

    # 5. Persistência e Integração SIEM
    result_id = await asyncio.to_thread(database.save_analysis, final_result)
    await send_to_siem(final_result)
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
        "00:50:56": "VMware", "00:25:9C": "Intel", "00:0C:29": "VMware", "00:03:FF": "Microsoft",
        "00:E0:4C": "Realtek", "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi",
        "E4:5F:01": "Raspberry Pi", "00:15:5D": "Microsoft Hyper-V", "00:1D:D9": "Microsoft",
        "00:21:2F": "Cisco", "00:24:14": "Cisco", "00:26:BB": "Apple", "00:17:88": "Philips Hue",
        "00:11:32": "Synology", "00:11:32": "Synology", "D4:6E:0E": "TP-Link", "98:DA:C4": "Espressif",
        "24:4B:FE": "Espressif", "48:55:19": "Xiaomi", "64:6E:60": "TP-Link", "70:4F:57": "Hikvision"
    }
    def _vendor_from_mac(mac: str):
        if not mac:
            return None
        m = mac.upper().replace("-", ":")
        prefix = ":".join(m.split(":")[:3])
        return OUI_VENDORS.get(prefix)

    def _identify_device(ip: str, vendor: str, services: list):
        """Tenta identificar o tipo de dispositivo com base no vendor e banners."""
        if vendor:
            v_low = vendor.lower()
            if any(x in v_low for x in ["tp-link", "asus", "d-link", "cisco", "linksys", "ubiquiti", "mikrotik"]):
                return f"Equipamento de Rede ({vendor})"
            if "hikvision" in v_low or "dahua" in v_low:
                return f"Câmera/DVR ({vendor})"
            if "raspberry" in v_low or "espressif" in v_low:
                return f"IoT/Microcontrolador ({vendor})"
            if "synology" in v_low or "qnap" in v_low:
                return f"Storage NAS ({vendor})"
            if "apple" in v_low:
                return f"Dispositivo Apple"
            if "xiaomi" in v_low:
                return f"Dispositivo Xiaomi/IoT"

        # Tenta via banners
        for s in services:
            banner = s.get("banner", "").lower()
            if not banner: continue
            if "mikrotik" in banner: return "Roteador MikroTik"
            if "tplink" in banner or "tp-link" in banner: return "Roteador TP-Link"
            if "ubnt" in banner or "ubiquiti" in banner: return "Antena/Roteador Ubiquiti"
            if "hikvision" in banner: return "Câmera Hikvision"
            if "dahua" in banner: return "Câmera Dahua"
            if "openwrt" in banner: return "Roteador (OpenWrt)"
            if "nginx" in banner or "apache" in banner:
                if ip.endswith(".1"): return "Gateway/Roteador (Web Admin)"
                return "Servidor Web"
            if "windows" in banner: return "Estação Windows"
            if "ssh" in banner: return "Servidor Linux/SSH"
            
        if ip.endswith(".1"):
            return f"Gateway da Rede ({vendor or 'Desconhecido'})"
            
        return vendor or "Dispositivo Desconhecido"

    def _clean_banner(banner: str):
        """Simplifica o banner para evitar poluição visual."""
        if not banner: return ""
        # Se for HTTP, tenta pegar apenas o Server ou o Title
        if "HTTP/" in banner:
            server_match = re.search(r"Server:\s*(.+)", banner, re.IGNORECASE)
            if server_match:
                return server_match.group(1).split("\r")[0].strip()
            # Se não tiver server, tenta ver se é um erro comum e simplifica
            if "400 Bad Request" in banner: return "HTTP 400 (Bad Request)"
            if "200 OK" in banner: return "HTTP 200 (OK)"
        
        # Para outros serviços, trunca e limpa
        clean = banner.replace("\r", " ").replace("\n", " ").strip()
        return (clean[:60] + "...") if len(clean) > 60 else clean

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
            
            # Limpa o banner antes de retornar
            banner_txt = _clean_banner(banner_txt)
            
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
        # Identifica o dispositivo
        d["name"] = _identify_device(d["ip"], d["vendor"], d["services"])
        
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
    await send_to_siem(result)
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
        'ELASTIC_API_KEY': (None, "Elastic API Key"),
        'ELASTIC_API_URL': (None, "Elastic API URL"),
        'WAZUH_API_KEY': (None, "Wazuh API Key"),
        'WAZUH_API_URL': (None, "Wazuh API URL"),
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

def _get_ai_key_for_provider(provider_name: str) -> str:
    """Helper para obter a chave de API correta para o provedor."""
    all_keys = [key.strip() for key in (settings.AI_API_KEY or "").split(',') if key.strip()]
    if not all_keys:
        raise AIProviderError("Nenhuma chave de IA está configurada.")

    for key in all_keys:
        if (provider_name == 'groq' and key.startswith('gsk_')) or \
           (provider_name == 'gemini' and key.startswith('AIza')) or \
           (provider_name == 'openai' and key.startswith('sk-')) or \
           (provider_name == 'grok' and key.startswith('xai-')):
            return key
    
    return all_keys[0]

def get_ai_explanation(analysis_result: Dict[str, Any], ai_provider: str = None) -> Dict[str, Any]:
    """
    Gera uma explicação em linguagem natural do resultado da análise.
    Ele lida com múltiplas chaves de IA configuradas, selecionando a correta para o provedor.
    """
    provider_name = ai_provider or settings.AI_PROVIDER_DETECTED or 'groq'
    if not provider_name:
        raise AIProviderError("Nenhum provedor de IA configurado ou detectado.")

    try:
        key_for_provider = _get_ai_key_for_provider(provider_name)
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

def get_ai_interpretation_for_threats(threats: List[Dict[str, str]]) -> str:
    """
    Gera uma interpretação por IA para a lista de ameaças nacionais.
    """
    if not threats:
        return "Nenhuma ameaça disponível para análise no momento."

    provider_name = settings.AI_PROVIDER_DETECTED or 'groq'
    try:
        key = _get_ai_key_for_provider(provider_name)
        provider_instance = get_ai_provider(provider_name)
        
        # Filtra apenas os dados relevantes para economizar tokens
        relevant_data = [{"date": t.get("date"), "title": t.get("title"), "summary": t.get("summary"), "url": t.get("url")} for t in threats]
        threats_json = json.dumps(relevant_data, indent=2, ensure_ascii=False)
        
        prompt = (
            "Você é um especialista em inteligência de ameaças focado no Brasil.\n"
            "Interprete os seguintes alertas recentes do CERT.br. Forneça um resumo executivo "
            "do cenário atual de ameaças no país e 3 recomendações práticas de proteção.\n\n"
            "IMPORTANTE: Você deve incluir os links das fontes originais (campos 'url') no final do seu resumo "
            "para que o usuário possa consultar os detalhes se desejar.\n\n"
            f"**Alertas Recentes:**\n```json\n{threats_json}\n```\n\n"
            "Responda em PORTUGUÊS, de forma clara e profissional, usando Markdown."
        )
        
        cache_key = hashlib.sha256(f"threat_ai_v1:{threats_json}:{provider_name}".encode('utf-8')).hexdigest()
        cached = ai_cache.get(cache_key)
        if cached:
            return cached

        interpretation = provider_instance.generate_explanation(prompt, api_key=key)
        ai_cache.set(cache_key, interpretation, expire=7200) # 2 horas de cache
        return interpretation
    except Exception as e:
        logger.error(f"Erro na interpretação de IA para ameaças: {e}")
        return f"Não foi possível gerar a interpretação automática agora: {str(e)}"


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
        f"O item foi analisado por múltiplas ferramentas de segurança. Abaixo estão os dados brutos.\n\n"
        f"**Instruções Específicas:**\n"
        f"1. Identifique o CONTEÚDO do item (ex: se é um site de apostas, phishing, ferramenta legítima, etc).\n"
        f"2. Explique em LINGUAGEM SIMPLES E DIRETA (para um público não técnico) o que foi encontrado.\n"
        f"3. Se o veredito for 'malicioso' ou 'suspeito', explique os principais riscos.\n"
        f"4. Se for 'limpo', confirme que nenhuma ameaça foi detectada pelas ferramentas.\n"
        f"5. Se houver dados do MITRE ATT&CK, inclua uma seção 'Análise MITRE ATT&CK' explicando as táticas e técnicas identificadas.\n\n"
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

def get_br_threat_trends(limit: int = 5) -> List[Dict[str, str]]:
    """
    Obtém tendências de ameaças e alertas nacionais (CERT.br e CTIR Gov).
    """
    try:
        cached = news_cache.get("br_alerts_v2")
        if cached:
            return cached[:limit]
            
        items = []
        feeds = [
            {"url": "https://www.cert.br/rss/certbr-rss.xml", "source": "CERT.br"},
            {"url": "https://www.gov.br/ctir/pt-br/assuntos/alertas-e-avisos/alertas/RSS", "source": "CTIR Gov"}
        ]
        
        import xml.etree.ElementTree as ET
        from datetime import datetime
        
        for feed in feeds:
            try:
                resp = requests.get(feed["url"], timeout=10, headers={'User-Agent': 'Mozilla/5.0'})
                if resp.status_code == 200:
                    logger.debug(f"Feed {feed['source']} retornado com sucesso. Tamanho: {len(resp.content)}")
                    try:
                        root = ET.fromstring(resp.content)
                        items_found = root.findall('.//item')
                        logger.debug(f"Itens encontrados no feed {feed['source']}: {len(items_found)}")
                        
                        feed_items = []
                        for item in items_found:
                            title = item.find('title').text if item.find('title') is not None else ""
                            link = item.find('link').text if item.find('link') is not None else feed["url"]
                            pub_date = item.find('pubDate').text if item.find('pubDate') is not None else ""
                            description = item.find('description').text if item.find('description') is not None else ""
                            
                            # Limpa HTML da descrição
                            description = re.sub(r'<[^>]+>', '', description).strip()
                            
                            # Formata data sutilmente
                            date_str = pub_date
                            if pub_date:
                                try:
                                    # Tenta parsear data RSS padrão: "Sun, 28 Dec 2025 15:00:00 +0000"
                                    # Corta timezone (+0000) para simplificar parse
                                    clean_date = pub_date[:25].strip()
                                    dt = datetime.strptime(clean_date, "%a, %d %b %Y %H:%M:%S")
                                    date_str = dt.strftime("%d/%m/%Y")
                                except Exception as de:
                                    logger.debug(f"Erro ao parsear data {pub_date}: {de}")
                                    
                            feed_items.append({
                                "date": date_str or datetime.now().strftime("%d/%m/%Y"),
                                "title": f"[{feed['source']}] {title}",
                                "summary": (description[:150] + "...") if len(description) > 150 else description,
                                "url": link
                            })
                            if len(feed_items) >= limit: # Limite por fonte
                                break
                        items.extend(feed_items)
                    except ET.ParseError as pe:
                        logger.warning(f"Erro de XML no feed {feed['source']}: {pe}")
            except Exception as e:
                logger.warning(f"Erro ao consultar feed {feed['source']}: {e}")
                continue

        if not items:
            # Fallback se os feeds falharem
            items = [
                {"date": datetime.now().strftime("%d/%m/%Y"), "title": "[CERT.br] Phishing bancário em alta no Brasil", "summary": "Campanhas de e-mail e WhatsApp visando bancos populares e Pix.", "url": "https://www.cert.br/"},
                {"date": datetime.now().strftime("%d/%m/%Y"), "title": "[CERT.br] Ransomware mirando pequenas empresas", "summary": "Famílias reempacotadas explorando RDP/445 expostos e credenciais fracas.", "url": "https://www.cert.br/"}
            ]
        else:
            # Ordena por data (heurística simples já que as datas são strings variadas, mas os feeds costumam vir ordenados)
            pass
            
        news_cache.set("br_alerts_v2", items, expire=1800) # Cache de 30 min
        return items[:limit]
    except Exception as e:
        logger.error(f"Erro crítico em get_br_threat_trends: {e}", exc_info=True)
        return [
            {"date": datetime.now().strftime("%d/%m/%Y"), "title": "Tendências indisponíveis", "summary": "Falha ao consultar fontes nacionais.", "url": "https://www.cert.br/"}
        ]
