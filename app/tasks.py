# -*- coding: utf-8 -*-
import os
import asyncio
from celery import Celery
from . import services

# Configuração do Celery
# Em produção, use variáveis de ambiente para o broker URL
celery_app = Celery(
    'malware_tasks',
    broker=os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0'),
    backend=os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0')
)

@celery_app.task(bind=True)
def execute_file_analysis_task(self, filepath: str, filename: str, ai_provider: str = None):
    """
    Tarefa do Celery que executa a análise em background.
    Lê o arquivo do disco (para não sobrecarregar o Redis com bytes) e chama o service.
    """
    try:
        # Lê o arquivo salvo temporariamente
        with open(filepath, 'rb') as f:
            content = f.read()

        # Executa a função async dentro do contexto síncrono do Celery
        # Nota: services.run_file_analysis retorna o ID do banco de dados
        result_id = asyncio.run(services.run_file_analysis(content, filename, ai_provider))
        
        return {"status": "completed", "result_id": result_id}

    except Exception as e:
        # Em caso de erro, podemos logar ou tentar novamente
        return {"status": "failed", "error": str(e)}
    
    finally:
        # Limpeza: Remove o arquivo temporário após o processamento
        if os.path.exists(filepath):
            try:
                os.remove(filepath)
            except OSError:
                pass