# -*- coding: utf-8 -*-
from quart import Blueprint, request, redirect, url_for, flash, jsonify, current_app
from pydantic import ValidationError
from . import services, utils
from .schemas import FileAnalysisRequest, ScanRequest, SetupRequest, UrlAnalysisRequest, NetworkAnalysisRequest
import logging

logger = logging.getLogger(__name__)

api_bp = Blueprint('api', __name__)

async def check_csrf():
    """Verifica o token CSRF na requisição atual."""
    token = None
    # Tenta obter do header
    if 'X-CSRFToken' in request.headers:
        token = request.headers['X-CSRFToken']
    # Se não, tenta do form
    elif await request.form:
        form = await request.form
        token = form.get('csrf_token')
    
    if not utils.validate_csrf_token(token):
        logger.warning("Tentativa de CSRF detectada ou token ausente.")
        return False
    return True

@api_bp.route('/setup', methods=['POST'])
async def api_setup():
    """
    Recebe os dados do formulário de configuração.
    """
    if not await check_csrf():
        return jsonify({'ok': False, 'error': 'Token de segurança inválido (CSRF). Recarregue a página.'}), 403

    try:
        form_data = await request.form
        # Converte ImmutableMultiDict para dict padrão para validação Pydantic
        data_dict = form_data.to_dict()
        
        # Validação com Pydantic
        try:
            validated_data = SetupRequest(**data_dict)
        except ValidationError as e:
             error_msg = f"Erro de validação: {e.errors()}"
             logger.warning(error_msg)
             if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'ok': False, 'error': error_msg})
             await flash(error_msg, 'danger')
             return redirect(url_for('main.index'))

        # Passa os dados brutos (form_data) para services.update_settings pois ele espera o objeto form
        # Ou refatoramos update_settings para aceitar dict. 
        # Por hora, mantemos form_data mas sabendo que foi validado.
        success, message, new_key_status = await services.update_settings(form_data)
        
        # Verifica se é uma requisição AJAX
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'ok': success, 'message': message, 'key_status': new_key_status, 'error': None if success else message})

        if success:
            await flash(message, 'success')
        else:
            await flash(message, 'danger')
            
    except Exception as e:
        logger.error(f"Erro em api_setup: {e}", exc_info=True)
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'ok': False, 'error': str(e)})
        await flash(f"Ocorreu um erro inesperado: {e}", "danger")

    return redirect(url_for('main.index'))

@utils.log_execution
@api_bp.route('/analyze/file', methods=['POST'])
async def analyze_file():
    """
    Endpoint para análise de arquivos.
    Recebe um arquivo via upload e retorna o ID do resultado.
    """
    try:
        # Pydantic validation
        # form_data = await request.form
        # model = FileAnalysisRequest(**form_data)
        
        files = await request.files
        file = files.get('file')
        form = await request.form
        ai_provider = 'groq'

        if not file:
            return jsonify({'error': 'Nenhum arquivo enviado'}), 400

        filename = file.filename
        content = file.read()

        # Chama o serviço de análise
        result_id = await services.run_file_analysis(content, filename, ai_provider)
        return jsonify({'result_id': result_id})

    except ValidationError as e:
        return jsonify({'error': e.errors()}), 400
    except Exception as e:
        logger.error(f"Erro na análise de arquivo: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@utils.log_execution
@api_bp.route('/correlation/alerts', methods=['POST'])
async def correlation_alerts():
    return jsonify({'error': 'Módulo desabilitado'}), 403

@utils.log_execution
@api_bp.route('/analyze/url', methods=['POST'])
async def analyze_url():
    """
    Endpoint para análise de URLs.
    Recebe um JSON com a URL e retorna o ID do resultado.
    """
    try:
        data = await request.get_json()
        request_model = UrlAnalysisRequest(**data)
        ai_provider = 'groq'

        result_id = await services.run_url_analysis(request_model.url, ai_provider)
        return jsonify({'result_id': result_id})
    except ValidationError as e:
        logger.warning(f"Erro de validação em analyze_url: {e.errors()}")
        return jsonify({'error': 'Dados inválidos', 'details': e.errors()}), 400
    except Exception as e:
        logger.error(f"Erro na análise de URL: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@api_bp.route('/threats/brasil', methods=['GET'])
async def threats_brasil():
    try:
        trends = services.get_br_threat_trends(limit=5)
        # Adiciona interpretação por IA
        ai_analysis = services.get_ai_interpretation_for_threats(trends)
        return jsonify({
            'ok': True, 
            'items': trends,
            'ai_analysis': ai_analysis
        })
    except Exception as e:
        logger.error(f"Erro ao obter Alertas Brasil: {e}", exc_info=True)
        return jsonify({'ok': False, 'error': str(e)}), 500

@api_bp.route('/scan/<module_type>', methods=['POST'])
async def run_scan(module_type):
    """
    Endpoint da API para executar scans de sistema simulados e consultar a IA.
    """
    if not await check_csrf():
        return jsonify({'error': 'Token de segurança inválido (CSRF).'}), 403

    try:
        # Recupera o provider se enviado no JSON (opcional)
        data = await request.get_json() or {}
        
        ai_provider = data.get('ai_provider', 'groq')
        result = await services.run_system_scan(module_type, ai_provider)
        return jsonify(result)
        
    except ValidationError as e:
        logger.warning(f"Erro de validação em run_scan: {e.errors()}")
        return jsonify({'error': 'Dados inválidos', 'details': e.errors()}), 400
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        logger.error(f"Erro no endpoint scan/{module_type}: {e}", exc_info=True)
        return jsonify({"error": "Erro interno no servidor"}), 500

@api_bp.route('/network/local', methods=['GET'])
async def network_local():
    try:
        info = await services.get_local_network_info()
        return jsonify(info)
    except Exception as e:
        logger.error(f"Erro ao detectar rede local: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@api_bp.route('/analyze/vault', methods=['POST'])
async def analyze_vault():
    """Endpoint para análise do Windows Vault."""
    if not await check_csrf():
        return jsonify({'error': 'Token de segurança inválido (CSRF).'}), 403
    try:
        # Recupera o provider se enviado no JSON (opcional)
        data = await request.get_json() or {}
        ai_provider = data.get('ai_provider', 'groq')
        
        result_id = await services.run_vault_analysis(ai_provider)
        return jsonify({'result_id': result_id})
    except Exception as e:
        logger.error(f"Erro na análise do Vault: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@utils.log_execution
@api_bp.route('/analyze/network', methods=['POST'])
async def analyze_network():
    try:
        data = await request.get_json() or {}
        model = NetworkAnalysisRequest(**data)
        if not await check_csrf():
            return jsonify({'error': 'Token de segurança inválido (CSRF).'}), 403
        result_id = await services.run_network_analysis(mode=model.mode, cidr=model.cidr, ai_provider=model.ai_provider)
        return jsonify({'result_id': result_id})
    except ValidationError as e:
        return jsonify({'error': 'Dados inválidos', 'details': e.errors()}), 400
    except Exception as e:
        logger.error(f"Erro na análise de rede: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


