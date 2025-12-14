# -*- coding: utf-8 -*-
"""
Rotas principais da aplicação (páginas web).

Este arquivo foi criado para corrigir o erro 'RuntimeError: Working outside of application context',
que ocorre ao usar funções síncronas do Flask (como render_template) em um ambiente assíncrono do Quart.
"""
from quart import Blueprint, render_template, current_app
from . import quart_db as database, services, utils

main_bp = Blueprint('main', __name__)


@main_bp.route('/')
async def index():
    """
    Renderiza a página principal. Esta função agora é assíncrona.
    """
    print("--- DEBUG: Requisição recebida em '/' ---")
    try:
        print("DEBUG: Chamando utils.get_key_status()...")
        key_status = utils.get_key_status()
        print("DEBUG: ... utils.get_key_status() concluído.")

        available_ai_providers = [
            {"value": "gemini", "name": "Google Gemini"},
            {"value": "groq", "name": "Groq Llama"},
            {"value": "grok", "name": "Grok"},
            {"value": "openai", "name": "OpenAI GPT-4"},
        ]

        print("DEBUG: Chamando render_template('index.html')...")
        # O travamento provavelmente ocorre nesta chamada de I/O de arquivo.
        response = await render_template('index.html', key_status=key_status, available_ai_providers=available_ai_providers)
        print("DEBUG: ... render_template('index.html') concluído.")

        return response
    except Exception as e:
        print(f"!!!!!!!!!! ERRO NA ROTA INDEX: {e} !!!!!!!!!!!")
        # Em caso de erro, retorna um 500 para não travar.
        return "Ocorreu um erro interno ao renderizar a página.", 500

@main_bp.route('/history')
async def history():
    """Renderiza a página de histórico de análises."""
    # Executa de forma síncrona para manter o contexto da aplicação (necessário para o 'g' do banco de dados)
    analyses = database.get_all_analyses()
    return await render_template('history.html', analyses=analyses)

@main_bp.route('/results/<report_id>')
async def results(report_id):
    """Renderiza a página de resultados."""
    # Busca a análise no banco de dados
    analysis = database.get_analysis(report_id)
    # Passa o objeto 'analysis' para o template
    return await render_template('results.html', analysis=analysis, report_id=report_id)

@main_bp.route('/faq')
async def faq():
    """Renderiza a página de Perguntas Frequentes."""
    return await render_template('faq.html')

@main_bp.route('/setup')
async def setup():
    """Renderiza a página de configurações."""
    key_status = utils.get_key_status()
    return await render_template('settings.html', key_status=key_status)