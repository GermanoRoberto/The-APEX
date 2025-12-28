# -*- coding: utf-8 -*-
"""
Rotas principais da aplicação (páginas web).

Este arquivo foi criado para corrigir o erro 'RuntimeError: Working outside of application context',
que ocorre ao usar funções síncronas do Flask (como render_template) em um ambiente assíncrono do Quart.
"""
from quart import Blueprint, render_template, current_app, request, redirect, url_for
from . import quart_db as database, services, utils
import logging
import markdown
from quart import Markup

from datetime import datetime

logger = logging.getLogger(__name__)

main_bp = Blueprint('main', __name__)

@main_bp.app_template_filter('strftime')
def strftime_filter(timestamp, format_str='%d/%m/%Y %H:%M'):
    """Filtro customizado para formatar timestamps Unix em datas legíveis."""
    if not timestamp:
        return ""
    try:
        # Tenta converter para float caso venha como string
        ts = float(timestamp)
        return datetime.fromtimestamp(ts).strftime(format_str)
    except (ValueError, TypeError):
        # Se falhar, retorna o valor original
        return str(timestamp)

@main_bp.app_template_filter('markdown')
def markdown_filter(text):
    if text:
        return Markup(markdown.markdown(text))
    return ""

@main_bp.app_context_processor
def inject_csrf_token():
    return dict(csrf_token=utils.generate_csrf_token)

@main_bp.route('/')
async def root():
    return redirect(url_for('main.inicio'))

@main_bp.route('/inicio')
async def inicio():
    try:
        key_status = utils.get_key_status()
        return await render_template('inicio.html', key_status=key_status)
    except Exception as e:
        logger.error(f"ERRO NA ROTA INICIO: {e}", exc_info=True)
        return "Ocorreu um erro ao renderizar a página inicial.", 500

@main_bp.route('/modules')
async def index():
    """
    Renderiza a página de módulos. Seleciona o módulo via querystring (?module=malware|network|audit)
    """
    logger.debug("Requisição recebida em '/modules'")
    try:
        key_status = utils.get_key_status()

        available_ai_providers = [
            {"value": "gemini", "name": "Google Gemini"},
            {"value": "groq", "name": "Groq Llama"},
            {"value": "grok", "name": "Grok"},
            {"value": "openai", "name": "OpenAI GPT-4"},
        ]

        selected_module = request.args.get('module', 'malware')

        response = await render_template(
            'index.html',
            key_status=key_status,
            available_ai_providers=available_ai_providers,
            module=selected_module
        )
        return response
    except Exception as e:
        logger.error(f"ERRO NA ROTA MODULES: {e}", exc_info=True)
        return "Ocorreu um erro interno ao renderizar a página.", 500

@main_bp.route('/history')
async def history():
    """Renderiza a página de histórico de análises."""
    # Executa de forma síncrona para manter o contexto da aplicação (necessário para o 'g' do banco de dados)
    analyses = database.get_all_analyses()
    return await render_template('history.html', analyses=analyses)

@main_bp.route('/history/clear', methods=['POST'])
async def history_clear():
    form = await request.form
    token = form.get('csrf_token')
    if not utils.validate_csrf_token(token):
        return redirect(url_for('main.history'))
    database.clear_all_analyses()
    return redirect(url_for('main.history'))

@main_bp.route('/results/<report_id>')
async def results(report_id):
    """Renderiza a página de resultados."""
    try:
        # Busca a análise no banco de dados
        analysis = database.get_analysis(report_id)
        
        if not analysis:
            logger.warning(f"Análise não encontrada para o ID: {report_id}")
            return await render_template('base.html', content="<div class='glass-card'><h1>404 - Análise não encontrada</h1><p>O relatório solicitado não existe ou foi removido.</p><a href='/' class='action-btn'>Voltar ao Início</a></div>"), 404

        # Passa o objeto 'analysis' para o template
        return await render_template('results.html', analysis=analysis, report_id=report_id)
    except Exception as e:
        logger.error(f"Erro ao renderizar resultados para ID {report_id}: {e}", exc_info=True)
        return "Erro interno ao processar resultados.", 500

@main_bp.route('/faq')
async def faq():
    """Renderiza a página de Perguntas Frequentes."""
    return await render_template('faq.html')

@main_bp.route('/setup')
async def setup():
    """Renderiza a página de configurações."""
    key_status = utils.get_key_status()
    return await render_template('settings.html', key_status=key_status)
