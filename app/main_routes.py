# -*- coding: utf-8 -*-
"""
Rotas principais da aplicação (páginas web).

Este arquivo centraliza as rotas de interface do usuário, utilizando o Blueprint 'main'.
As rotas são assíncronas para total compatibilidade com o servidor Quart.
"""
import logging
import json
import hashlib
from datetime import datetime
from quart import Blueprint, render_template, request, redirect, url_for, Markup
import markdown

from . import quart_db as database, services, utils
from .config import settings

logger = logging.getLogger(__name__)

main_bp = Blueprint('main', __name__)

# --- Processadores de Contexto e Filtros ---

@main_bp.app_context_processor
def inject_globals():
    """Injeta variáveis globais úteis para todos os templates."""
    try:
        latest = services.get_latest_news(limit=2)
    except Exception:
        latest = []
    
    return dict(
        latest_news=latest,
        now=datetime.now(),
        csrf_token=utils.generate_csrf_token
    )

@main_bp.app_template_filter('markdown')
def markdown_filter(text):
    """Filtro para renderizar Markdown nos templates."""
    if text:
        return Markup(markdown.markdown(text))
    return ""

# --- Rotas de Navegação ---

@main_bp.route('/')
async def root():
    """Redireciona a raiz para o dashboard."""
    return redirect(url_for('main.inicio'))

@main_bp.route('/inicio')
async def inicio():
    """Renderiza o Dashboard principal com estatísticas consolidadas."""
    logger.debug("Acessando Dashboard (/inicio)")
    
    key_status = {}
    stats = {
        'criticos': 0,
        'alertas': 0,
        'analises': 0,
        'resolvidos': 0,
        'recentes': [],
        'chart_data': [0] * 7
    }

    try:
        key_status = utils.get_key_status()
        all_analyses_raw = database.get_all_analyses()
        
        # Filtra 'audit' e 'vault' para que não apareçam nas estatísticas nem nos recentes
        all_analyses = [a for a in all_analyses_raw if a.get('item_type') not in ['audit', 'vault']]
        
        if all_analyses:
            stats['criticos'] = len([a for a in all_analyses if a.get('final_verdict') == 'malicious'])
            stats['alertas'] = len([a for a in all_analyses if a.get('final_verdict') in ['malicious', 'suspicious']])
            stats['analises'] = len(all_analyses)
            stats['resolvidos'] = len([a for a in all_analyses if a.get('final_verdict') == 'clean'])
            stats['recentes'] = all_analyses[:3]

            # Processamento de dados para o gráfico (últimos 7 dias)
            now = datetime.now()
            for analysis in all_analyses:
                created_at = analysis.get('created_at')
                if created_at:
                    try:
                        ts = float(created_at)
                        dt = datetime.fromtimestamp(ts)
                        days_ago = (now - dt).days
                        if 0 <= days_ago < 7:
                            stats['chart_data'][6 - days_ago] += 1
                    except (ValueError, TypeError):
                        continue

        return await render_template('inicio.html', key_status=key_status, stats=stats)

    except Exception as e:
        logger.error(f"Erro na rota /inicio: {e}", exc_info=True)
        return await render_template('inicio.html', key_status=key_status, stats=stats, error=str(e))

@main_bp.route('/modules')
async def index():
    """Renderiza a página de módulos (Malware, Network)."""
    try:
        key_status = utils.get_key_status()
        available_ai_providers = [
            {"value": "gemini", "name": "Google Gemini"},
            {"value": "groq", "name": "Groq Llama"},
            {"value": "grok", "name": "Grok"},
            {"value": "openai", "name": "OpenAI GPT-4"},
        ]
        selected_module = request.args.get('module', 'malware')

        return await render_template(
            'index.html',
            key_status=key_status,
            available_ai_providers=available_ai_providers,
            module=selected_module
        )
    except Exception as e:
        logger.error(f"Erro na rota /modules: {e}", exc_info=True)
        return "Erro interno ao carregar módulos.", 500

@main_bp.route('/history')
async def history():
    """Exibe o histórico de análises (filtrando auditoria por solicitação)."""
    analyses = database.get_all_analyses()
    # Filtra 'audit' e 'vault' do histórico conforme solicitado ("fora do histórico")
    filtered = [a for a in analyses if a.get('item_type') not in ['audit', 'vault']]
    return await render_template('history.html', analyses=filtered)

@main_bp.route('/history/clear', methods=['POST'])
async def history_clear():
    """Limpa o histórico de análises (protegido por CSRF)."""
    form = await request.form
    if utils.validate_csrf_token(form.get('csrf_token')):
        database.clear_all_analyses()
    return redirect(url_for('main.history'))

@main_bp.route('/results/<report_id>')
async def results(report_id):
    """Exibe detalhes de um relatório de análise específico."""
    analysis = database.get_analysis(report_id)
    if not analysis:
        return await render_template('base.html', content="<div class='glass-card'><h1>404</h1><p>Relatório não encontrado.</p></div>"), 404
    return await render_template('results.html', analysis=analysis, report_id=report_id)

@main_bp.route('/faq')
async def faq():
    """Exibe a página de Perguntas Frequentes."""
    return await render_template('faq.html')

@main_bp.route('/setup')
async def setup():
    """Exibe a página de configurações do sistema."""
    key_status = utils.get_key_status()
    return await render_template('settings.html', key_status=key_status)
