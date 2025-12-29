# -*- coding: utf-8 -*-
"""
Módulo de Integrações SIEM/SOAR.

Este módulo lida com a exportação de resultados de análise para ferramentas
externas como Elastic Stack.
"""
import logging
import asyncio
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
