# -*- coding: utf-8 -*-
"""
Módulo de Banco de Dados (Compatível com Quart).
Substitui o antigo database.py para corrigir erros de contexto.
"""
import sqlite3
import json
import time
import os
import logging
import hashlib
from contextlib import contextmanager
from quart import g, current_app

logger = logging.getLogger(__name__)

class DatabaseConnection:
    """
    Gerenciador de conexão com o banco de dados.
    Pode ser usado com 'with' para garantir fechamento da conexão,
    funcionando tanto dentro quanto fora do contexto de aplicação (g).
    """
    def __init__(self, db_path=None):
        self.db_path = db_path
        self.connection = None

    def __enter__(self):
        if not self.db_path:
            # Tenta pegar do config se estiver no contexto da app, senão usa padrão
            try:
                self.db_path = os.path.join(current_app.instance_path, 'analisador.sqlite')
            except RuntimeError:
                # Fallback para execução fora de contexto (ex: scripts ou threads isoladas)
                # Assume estrutura padrão de pastas
                base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                self.db_path = os.path.join(base_dir, 'instance', 'analisador.sqlite')

        # Garante diretório
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        self.connection = sqlite3.connect(
            self.db_path,
            detect_types=sqlite3.PARSE_DECLTYPES,
            check_same_thread=False # Necessário para acesso via threads diferentes
        )
        self.connection.row_factory = sqlite3.Row
        return self.connection

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.connection:
            self.connection.close()

def get_db():
    """
    Obtém uma conexão reutilizável ligada ao contexto da requisição (g).
    Use APENAS dentro de rotas/handlers do Quart.
    """
    if 'db' not in g:
        # Usa o gerenciador para criar a conexão, mas não fecha automaticamente
        # O fechamento é tratado pelo teardown_appcontext
        cm = DatabaseConnection()
        g.db = cm.__enter__()
        # Hack: guardamos o cm no g para não perdê-lo (embora __exit__ feche a conexao, 
        # aqui queremos manter aberta até o fim da request)
        # Na verdade, basta armazenar a conexão. O close_db fará o trabalho.
    return g.db

def close_db(e=None):
    """Fecha a conexão com o banco de dados ao fim da requisição."""
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    """Cria as tabelas se não existirem."""
    with DatabaseConnection() as db:
        db.execute('''
            CREATE TABLE IF NOT EXISTS analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                item_identifier TEXT NOT NULL,
                item_type TEXT NOT NULL,
                final_verdict TEXT NOT NULL,
                created_at REAL NOT NULL,
                external_results TEXT,
                ai_analysis TEXT,
                mitre_attack TEXT
            )
        ''')
        db.commit()
        logger.info("Banco de dados inicializado/verificado com sucesso.")

def init_app(app):
    """Registra as funções de banco de dados na aplicação."""
    app.teardown_appcontext(close_db)
    # Opcional: inicializar DB no start
    # init_db() 

def save_analysis(result: dict) -> int:
    """
    Salva o resultado de uma análise no banco.
    Thread-safe e Context-safe: Cria uma nova conexão para cada chamada
    para evitar conflitos de thread e dependência de 'g'.
    """
    item_identifier = result.get('filename') or result.get('url') or result.get('network_cidr') or result.get('item_identifier')
    if not item_identifier:
        logger.error(f"Erro ao salvar análise: item_identifier ausente. Dados parciais: {list(result.keys())}")
        return -1

    try:
        # Usa Context Manager para garantir conexão limpa e fechamento
        with DatabaseConnection() as db:
            cursor = db.cursor()
            item_type = result.get('item_type') or ('file' if 'sha256' in result else ('url' if result.get('url') else ('network' if result.get('network_cidr') else 'unknown')))
            
            # Prepara dados extras (tudo que não é coluna principal) para salvar no JSON external_results
            main_cols = ['item_identifier', 'item_type', 'final_verdict', 'created_at', 'ai_analysis', 'mitre_attack']
            extra_data = {k: v for k, v in result.items() if k not in main_cols}

            cursor.execute(
                'INSERT INTO analyses (item_identifier, item_type, final_verdict, created_at, external_results, ai_analysis, mitre_attack) VALUES (?, ?, ?, ?, ?, ?, ?)',
                (
                    item_identifier,
                    item_type,
                    result.get('final_verdict', 'unknown'),
                    float(result.get('scanned_at', result.get('created_at', time.time()))),
                    json.dumps(extra_data),
                    json.dumps(result.get('ai_analysis', {})),
                    json.dumps(result.get('mitre_attack', {}))
                )
            )
            db.commit()
            logger.info(f"Análise salva com sucesso. ID: {cursor.lastrowid}")
            return cursor.lastrowid
    except Exception as e:
        logger.error(f"Falha crítica ao persistir análise no banco: {e}", exc_info=True)
        raise

def get_all_analyses():
    """Retorna todas as análises ordenadas por data (recente primeiro)."""
    with DatabaseConnection() as db:
        analyses = db.execute('SELECT * FROM analyses ORDER BY created_at DESC').fetchall()
        return [dict(row) for row in analyses]

def get_analysis(analysis_id):
    """Retorna uma análise específica pelo ID, com campos JSON decodificados e mesclados."""
    with DatabaseConnection() as db:
        row = db.execute('SELECT * FROM analyses WHERE id = ?', (analysis_id,)).fetchone()
        if row is None:
            return None
        
        data = dict(row)
        # Decodifica JSONs com tratamento de erro básico
        for field in ['external_results', 'ai_analysis', 'mitre_attack']:
            try:
                content = data.pop(field) # Remove o campo original de texto
                decoded = json.loads(content) if content else {}
                
                if field == 'external_results':
                    # Mescla dados extras de volta no dicionário principal
                    data.update(decoded)
                else:
                    data[field] = decoded
            except json.JSONDecodeError:
                if field != 'external_results':
                    data[field] = {}
                logger.warning(f"Falha ao decodificar JSON do campo {field} para análise {analysis_id}")
        
        # Garante que 'external' exista se foi mesclado de external_results
        if 'external' not in data:
            data['external'] = {}

        return data

def clear_all_analyses() -> int:
    with DatabaseConnection() as db:
        cur = db.execute('DELETE FROM analyses')
        db.commit()
        return cur.rowcount
