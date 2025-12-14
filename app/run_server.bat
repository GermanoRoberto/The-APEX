@echo off
title Analisador de Malware - Servidor de Producao (Hypercorn)

echo =================================================================
echo.
echo  Analisador de Malware - Servidor de Producao (Hypercorn/ASGI)
echo =================================================================
echo.

REM Navega para o diretório raiz do projeto (pasta acima de /app)
cd /d "%~dp0\.."

echo Ativando o ambiente virtual (venv)...
if not exist "venv\Scripts\activate" (
    echo.
    echo ============================== ERRO ==============================
    echo  Ambiente virtual 'venv' nao encontrado.
    echo  Execute o script 'iniciar.bat' primeiro para configurar o ambiente.
    echo ================================================================
    echo.
    pause
    exit /b
)
call venv\Scripts\activate

echo.
echo Iniciando o servidor Quart com Hypercorn em modo de producao...
echo O servidor estara disponivel em http://localhost:5000 ou http://SEU_IP_LOCAL:5000
echo Pressione Ctrl+C para parar o servidor.
echo.

REM O ponto de entrada para o Hypercorn e 'nome_arquivo:nome_app_asgi'.
hypercorn --bind 0.0.0.0:5000 wsgi:app

pause