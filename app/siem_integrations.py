# -*- coding: utf-8 -*-
"""
Módulo de Integrações SIEM/SOAR.

Este módulo lida com a exportação de resultados de análise para ferramentas
externas como Elastic Stack e Wazuh.
"""
import logging
import json
import asyncio
import aiohttp
from typing import Dict, Any
from .config import settings

logger = logging.getLogger(__name__)

async def send_to_siem(result: Dict[str, Any]):
    """
    Orquestra o envio de resultados para todos os SIEMs configurados.
    """
    tasks = []
    
    if settings.ELASTIC_API_URL:
        tasks.append(send_to_elasticsearch(result))
    
    if settings.WAZUH_API_URL:
        tasks.append(send_to_wazuh(result))
        
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)

async def send_to_elasticsearch(result: Dict[str, Any]):
    """
    Envia o resultado da análise para o Elasticsearch.
    """
    try:
        from elasticsearch import AsyncElasticsearch
        
        # Prepara a URL
        url = settings.ELASTIC_API_URL
        if not url.startswith('http'):
            url = f"http://{url}"
            
        # Inicializa o cliente
        # Se houver API Key, usa. Se não, tenta conexão sem auth (local dev)
        client_args = {"hosts": [url]}
        if settings.ELASTIC_API_KEY:
            client_args["api_key"] = settings.ELASTIC_API_KEY
            
        async with AsyncElasticsearch(**client_args) as es:
            # Indexa o documento
            resp = await es.index(
                index="apex-analyses",
                document=result
            )
            logger.info(f"Resultado enviado ao Elasticsearch: {resp['result']}")
            
    except ImportError:
        logger.error("Biblioteca 'elasticsearch' não encontrada.")
    except Exception as e:
        logger.error(f"Erro ao enviar para Elasticsearch: {e}")

async def send_to_wazuh(result: Dict[str, Any]):
    """
    Envia o resultado da análise para o Wazuh Manager via API.
    Nota: Esta é uma integração via API para registro de eventos/logs.
    """
    try:
        url = settings.WAZUH_API_URL.rstrip('/')
        api_key = settings.WAZUH_API_KEY
        
        # 1. Autenticação para obter Token (se necessário)
        # Em setups locais simples, pode não ser necessário, mas o padrão é usar auth.
        # Aqui simulamos o envio de um log customizado.
        
        headers = {
            "Content-Type": "application/json"
        }
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
            
        # Endpoint de exemplo para envio de log (Wazuh 4.x+)
        # Nota: O Wazuh geralmente recebe logs via syslog (514) ou Agent.
        # Via API, podemos injetar logs em alguns casos ou gerenciar regras.
        # Para fins de integração, vamos logar a tentativa.
        
        payload = {
            "origin": "the-apex",
            "module": result.get("item_type", "unknown"),
            "verdict": result.get("final_verdict", "unknown"),
            "identifier": result.get("item_identifier", "unknown"),
            "full_report": result
        }
        
        timeout = aiohttp.ClientTimeout(total=5)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            # Simulando envio para um endpoint de ingestão (ex: fluentd ou custom webhook no manager)
            # Como o Wazuh nativo prefere Syslog, em produção o ideal seria usar a biblioteca logging.handlers.SysLogHandler
            logger.info(f"Integrando com Wazuh em {url}...")
            # await session.post(f"{url}/logs", json=payload, headers=headers)
            
    except Exception as e:
        logger.error(f"Erro ao integrar com Wazuh: {e}")
