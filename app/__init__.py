# -*- coding: utf-8 -*-
import webbrowser
from quart import Quart
from datetime import datetime
from .config import Config, settings

def create_app():
    """
    Cria e configura uma instância da aplicação Quart.
    Este padrão de fábrica (factory pattern) permite criar múltiplas instâncias da aplicação
    para testes ou configurações diferentes.
    """
    app = Quart(__name__, instance_relative_config=True)

    # Carrega a configuração a partir do objeto 'settings' em config.py,
    # que por sua vez carrega as variáveis do arquivo .env.
    app.config.from_object(settings)
    
    # --- Best Practice: Carrega a configuração a partir do objeto de config ---
    # O valor de MAX_FILE_SIZE já está no objeto 'settings', mas Quart usa
    # MAX_CONTENT_LENGTH para limitar o tamanho do request. Vamos garantir que ambos estejam alinhados.
    app.config['MAX_CONTENT_LENGTH'] = app.config['MAX_FILE_SIZE']

    # Inicializa o banco de dados
    from . import quart_db
    quart_db.init_app(app)
    
    # Registra tarefas a serem executadas antes do servidor começar a aceitar requisições.
    @app.before_serving
    async def startup_tasks():
        """Executa tarefas de inicialização, como a criação do BD e a abertura do navegador."""
        print("INFO: Database initialization...")
        quart_db.init_db()
        
        # Abre o navegador automaticamente, mas apenas quando em modo de debug
        # para evitar comportamento inesperado em produção.
        if app.debug:
            # O ideal seria usar o host/porta da configuração, mas como a app
            # está toda estruturada em torno de 127.0.0.1:5000, manteremos isso por simplicidade.
            print("INFO: Debug mode enabled, opening browser at http://127.0.0.1:5000")
            webbrowser.open("http://127.0.0.1:5000")

    # Adiciona um filtro Jinja para formatação de data/hora nos templates.
    def format_datetime_filter(timestamp: float, fmt: str = '%d/%m/%Y %H:%M') -> str:
        """Filtro Jinja para formatar um timestamp Unix em uma string legível."""
        if not timestamp:
            return ""
        return datetime.fromtimestamp(timestamp).strftime(fmt)
    app.jinja_env.filters['strftime'] = format_datetime_filter

    # Adiciona um filtro Jinja para renderizar Markdown de forma segura.
    @app.template_filter('markdown')
    def markdown_filter(s):
        """Filtro Jinja para converter texto Markdown em HTML."""
        from markupsafe import Markup
        import markdown
        if not s:
            return ""
        return Markup(markdown.markdown(s))
    
    # Injeta o objeto 'settings' no contexto de todos os templates para que possam
    # ser usados na UI (ex: para mostrar a versão do app).
    @app.context_processor
    def inject_settings():
        return dict(settings=settings)

    # Importa e registra os blueprints (conjuntos de rotas)
    from .main_routes import main_bp
    from .api_routes import api_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp, url_prefix='/api')

    return app