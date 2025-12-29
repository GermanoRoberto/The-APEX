# -*- coding: utf-8 -*-
"""
Fábrica da Aplicação Quart (Application Factory).

Este módulo é responsável por criar e configurar a instância da aplicação Quart,
registrando blueprints, extensões e configurações.

Padrões aplicados:
- **Application Factory:** Permite criar múltiplas instâncias da app (útil para testes)
  e evita problemas de contexto circular.
- **Blueprint Registration:** Centraliza o registro de rotas.
- **Database Initialization:** Garante que o banco e tabelas existam no boot.
"""
from quart import Quart
from .config import settings
from . import quart_db as database
from .main_routes import main_bp
from .api_routes import api_bp
import logging

# Configuração de Logs
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def create_app():
    """Cria e configura a instância da aplicação Quart."""
    app = Quart(__name__)
    
    # --- Configuração ---
    # Carrega configurações do objeto settings (Config)
    app.config.update(settings.__dict__)
    app.config['TEMPLATES_AUTO_RELOAD'] = True
    try:
        app.jinja_env.auto_reload = True
    except Exception:
        pass
    
    # --- Inicialização do Banco de Dados ---
    database.init_app(app)
    
    # --- Filtros Customizados do Jinja2 ---
    @app.template_filter('from_json')
    def from_json_filter(s):
        """Converte uma string JSON em um objeto Python."""
        import json
        try:
            return json.loads(s)
        except Exception:
            return {}

    @app.template_filter('strftime')
    def strftime_filter(timestamp, format='%d/%m/%Y %H:%M'):
        """Formata um timestamp Unix para uma string de data legível."""
        from datetime import datetime
        try:
            return datetime.fromtimestamp(int(float(timestamp))).strftime(format)
        except Exception:
            return "-"

    @app.template_filter('basename')
    def basename_filter(path):
        """Retorna o nome base de um caminho de arquivo."""
        import os
        return os.path.basename(path)

    @app.template_filter('markdown')
    def markdown_filter(text):
        """Converte Markdown para HTML."""
        import markdown
        from markupsafe import Markup
        if not text:
            return ""
        return Markup(markdown.markdown(text, extensions=['extra', 'codehilite']))
    
    # Inicializa tabelas (pode ser movido para um comando CLI em produção para evitar overhead)
    # Mas como é SQLite local e leve, fazemos aqui para garantir funcionamento imediato.
    try:
        database.init_db()
    except Exception as e:
        logger.error(f"Erro ao inicializar banco de dados: {e}")

    # --- Registro de Blueprints ---
    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp, url_prefix='/api') 
    # Nota: api_routes já define prefixo?
    # O arquivo api_routes.py define api_bp = Blueprint('api', __name__)
    # Se usarmos url_prefix='/api', as rotas ficam /api/setup, /api/analyze/file, etc.
    # No arquivo api_routes.py as rotas são /setup, /analyze/file.
    # Portanto, url_prefix='/api' é o correto para agrupar.

    logger.info("Aplicação The Apex inicializada com sucesso.")
    return app
