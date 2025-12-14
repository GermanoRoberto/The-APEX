# -*- coding: utf-8 -*-
from quart import Blueprint, request, redirect, url_for, flash, jsonify, current_app
from . import services

api_bp = Blueprint('api', __name__)

@api_bp.route('/setup', methods=['POST'])
async def api_setup():
    """
    Recebe os dados do formulário de configuração, valida, salva no arquivo .env
    e recarrega as configurações da aplicação. Agora é assíncrono.
    """
    try:
        form_data = await request.form
        success, message, new_key_status = await services.update_settings(form_data)
        
        # Verifica se é uma requisição AJAX (vinda do settings.html)
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'ok': success, 'message': message, 'key_status': new_key_status, 'error': None if success else message})

        # Fallback para submissão de formulário padrão (setup.html)
        if success:
            await flash(message, 'success')
        else:
            await flash(message, 'danger')
    except Exception as e:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'ok': False, 'error': str(e)})
        await flash(f"Ocorreu um erro inesperado: {e}", "danger")

    return redirect(url_for('main.index'))

@api_bp.route('/analyze/file', methods=['POST'])
async def analyze_file():
    """Endpoint para analisar um arquivo."""
    files = await request.files
    if 'file' not in files:
        return jsonify({'error': 'Nenhum arquivo enviado'}), 400
    
    file = files['file']
    if file.filename == '':
        return jsonify({'error': 'Nome de arquivo vazio'}), 400

    if file:
        content = file.read()
        filename = file.filename
        
        # Validação de tamanho do arquivo
        if len(content) > current_app.config['MAX_FILE_SIZE']:
            return jsonify({'error': f'O arquivo excede o tamanho máximo de {current_app.config["MAX_FILE_SIZE"] / 1024 / 1024} MB'}), 413

        try:
            form = await request.form
            ai_provider = form.get('ai_provider')
            result_id = await services.run_file_analysis(content, filename, ai_provider)
            return jsonify({'result_id': result_id})
        except Exception as e:
            current_app.logger.error(f"Erro na análise de arquivo: {e}", exc_info=True)
            return jsonify({'error': 'Ocorreu um erro interno durante a análise do arquivo.'}), 500
            
    return jsonify({'error': 'Arquivo inválido'}), 400

@api_bp.route('/analyze/url', methods=['POST'])
async def analyze_url():
    """Endpoint para analisar uma URL."""
    data = await request.get_json()
    url = data.get('url')

    if not url:
        return jsonify({'error': 'URL não fornecida'}), 400

    try:
        ai_provider = data.get('ai_provider')
        result_id = await services.run_url_analysis(url, ai_provider)
        return jsonify({'result_id': result_id})
    except Exception as e:
        current_app.logger.error(f"Erro na análise de URL: {e}", exc_info=True)
        return jsonify({'error': 'Ocorreu um erro interno durante a análise da URL.'}), 500