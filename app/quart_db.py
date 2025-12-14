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
from quart import g, current_app

def get_db():
    """Obtém a conexão com o banco de dados vinculada ao contexto atual."""
    if 'db' not in g:
        # Define o caminho do banco. Usa instance/analisador.sqlite como padrão.
        db_path = os.path.join(current_app.instance_path, 'analisador.sqlite')
        
        # Garante que o diretório instance existe
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        g.db = sqlite3.connect(
            db_path,
            detect_types=sqlite3.PARSE_DECLTYPES,
            check_same_thread=False  # Necessário para Quart/Hypercorn gerenciarem a conexão entre threads
        )
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(e=None):
    """Fecha a conexão com o banco de dados."""
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    """Cria as tabelas se não existirem."""
    db = get_db()
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

def init_app(app):
    """Registra as funções de banco de dados na aplicação."""
    app.teardown_appcontext(close_db)

import logging

def save_analysis(result):
    """Salva o resultado de uma análise no banco."""
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    logger.info(f"save_analysis received result dictionary: {result.keys()}")
    
    db = get_db()
    cursor = db.cursor()
    
    item_identifier = result.get('filename') or result.get('url')
    if not item_identifier:
        logger.error(f"CRITICAL: item_identifier is None or empty. Result keys: {result.keys()}")
        logger.error(f"Full result object: {result}")


    cursor.execute(
        'INSERT INTO analyses (item_identifier, item_type, final_verdict, created_at, external_results, ai_analysis, mitre_attack) VALUES (?, ?, ?, ?, ?, ?, ?)',
        (
            item_identifier,
            'file' if 'sha256' in result else 'url',
            result.get('final_verdict'),
            time.time(),
            json.dumps(result.get('external', {})),
            json.dumps(result.get('ai_analysis', {})),
            json.dumps(result.get('mitre_attack', {}))
        )
    )
    db.commit()
    return cursor.lastrowid

def get_all_analyses():
    """Retorna todas as análises ordenadas por data."""
    db = get_db()
    analyses = db.execute('SELECT * FROM analyses ORDER BY created_at DESC').fetchall()
    return [dict(row) for row in analyses]

def get_analysis(analysis_id):
    """Retorna uma análise específica pelo ID, com campos JSON decodificados."""
    db = get_db()
    row = db.execute('SELECT * FROM analyses WHERE id = ?', (analysis_id,)).fetchone()
    if row is None:
        return None
    
    data = dict(row)
    # Decodifica os campos JSON para dicionários Python
    data['external'] = json.loads(data['external_results']) if data.get('external_results') else {}
    data['ai_analysis'] = json.loads(data['ai_analysis']) if data.get('ai_analysis') else {}
    data['mitre_attack'] = json.loads(data['mitre_attack']) if data.get('mitre_attack') else {}
    
    return data