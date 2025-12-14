@echo off
setlocal enabledelayedexpansion

:: ===================================================================================
:: Malware Analyzer - Inicializador Automatizado (v4.0 - com Opcao Docker)
:: ===================================================================================
::
:: Este script foi refatorado para incluir a opção de inicialização via Docker.
::
:: FUNCIONALIDADES:
:: 1. MENU DE ESCOLHA: Permite escolher entre ambiente local e ambiente Docker.
:: 2. AUTO-ELEVAÇÃO: Solicita privilégios de Administrador automaticamente (necessário para ambos os modos).
:: 3. ORQUESTRAÇÃO DOCKER: Automatiza os comandos `docker-compose` para construir e iniciar o ambiente.
:: 4. MODULARIDADE: Cada passo lógico é uma sub-rotina para clareza e manutenção.
::
:: ===================================================================================

:: --------------------------------------------------------------------------
:: BLOCO DE CONFIGURAÇÃO
:: --------------------------------------------------------------------------
set "PYTHON_CMD=python"
set "VENV_DIR=venv"
set "REQUIREMENTS_FILE=requirements.txt"
set "MAIN_SCRIPT=run.py"
set "SERVER_PORT=5000"


:: --------------------------------------------------------------------------
:: BLOCO DE AUTO-ELEVAÇÃO DE PRIVILÉGIOS
:: --------------------------------------------------------------------------
:check_admin
    echo [INFO] Verificando privilegios de execucao...
    net session >nul 2>&1
    if %errorlevel% == 0 (
        echo [SUCCESS] Privilegios de Administrador confirmados.
        goto :main_logic
    )

    echo [INFO] Privilegios de Administrador necessarios. Tentando elevar...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs" >nul 2>&1
    if !errorlevel! neq 0 (
        echo [ERRO] Falha ao tentar elevar privilegios. Por favor, execute manualmente como Administrador.
        pause
    )
    exit /b

:: --------------------------------------------------------------------------
:: BLOCO DE LÓGICA PRINCIPAL (MENU)
:: --------------------------------------------------------------------------
:main_logic
    title Malware Analyzer - Menu de Inicializacao
    cd /d "%~dp0"

    call :log "------ INICIALIZADOR MALWARE ANALYZER v4.0 ------"
    echo.
    echo    Escolha o modo de inicializacao:
    echo.
    echo      [1] Ambiente de Desenvolvimento Local (requer Python no PATH)
    echo      [2] Ambiente com Docker (requer Docker Desktop)
    echo      [3] Sair
    echo.
    
    choice /c 123 /n /m "Digite sua opcao (1, 2 ou 3): "
    
    if !errorlevel! == 1 goto :run_local_setup
    if !errorlevel! == 2 goto :run_docker_setup
    if !errorlevel! == 3 (
        call :log "Saindo..."
        exit /b 0
    )
    goto :main_logic


:: --------------------------------------------------------------------------
:: FLUXO DE EXECUÇÃO LOCAL
:: --------------------------------------------------------------------------
:run_local_setup
    cls
    call :log "--- INICIANDO AMBIENTE LOCAL ---"
    call :run_step kill_port "Limpando a porta da aplicacao (%SERVER_PORT%)"
    call :run_step check_python "Verificando instalacao do Python"
    call :run_step setup_venv "Configurando ambiente virtual '%VENV_DIR%'"
    call :run_step install_deps "Instalando dependencias de '%REQUIREMENTS_FILE%'"
    call :run_step run_server "Iniciando o servidor ('%MAIN_SCRIPT%')"
    call :log "--- AMBIENTE LOCAL CONFIGURADO ---"
    goto :end_script

:: --------------------------------------------------------------------------
:: FLUXO DE EXECUÇÃO DOCKER
:: --------------------------------------------------------------------------
:run_docker_setup
    cls
    call :log "--- INICIANDO AMBIENTE DOCKER ---"
    call :run_step check_docker "Verificando se o Docker esta em execucao"
    call :run_step stop_docker_containers "Parando containers existentes (se houver)"
    call :run_step build_docker_images "Construindo/atualizando imagens Docker"
    call :run_step start_docker_containers "Iniciando containers"
    call :log "--- AMBIENTE DOCKER INICIADO ---"
    call :log "Logs dos containers serao exibidos abaixo. Pressione CTRL+C para parar."
    goto :end_script

:end_script
    echo.
    call :log "------ Script de inicializacao finalizado. ------"
    pause
    goto :eof

:: ==========================================================================
:: SUB-ROTINAS DE EXECUÇÃO
:: ==========================================================================

:run_step
    call :log "[PASSO] %~2"
    call :%1
    if !errorlevel! neq 0 (
        call :log "[ERRO FATAL] O passo '%~2' falhou. Abortando."
        pause
        exit /b !errorlevel!
    )
    call :log "[SUCCESS] Passo '%~2' concluido."
    echo.
    goto :eof

:log
    echo [%date% %time:~0,8%] %*
    goto :eof

:: --- Sub-rotinas Locais ---
:kill_port
    for /f "tokens=5" %%a in ('netstat -aon ^| findstr /i ":%SERVER_PORT%"') do (
        if "%%a" neq "0" (
            call :log "[INFO] Encerrando processo (PID: %%a) na porta %SERVER_PORT%."
            taskkill /F /PID %%a >nul
        )
    )
    exit /b 0

:check_python
    %PYTHON_CMD% --version >nul 2>&1
    exit /b %errorlevel%

:setup_venv
    if not exist "%VENV_DIR%\Scripts\activate" (
        call :log "[INFO] Criando ambiente virtual..."
        %PYTHON_CMD% -m venv %VENV_DIR%
        if !errorlevel! neq 0 exit /b !errorlevel!
    )
    call :log "[INFO] Ativando ambiente virtual..."
    call "%VENV_DIR%\Scripts\activate"
    exit /b %errorlevel%

:install_deps
    if not exist "%REQUIREMENTS_FILE%" (
        call :log "[ERRO] Arquivo '%REQUIREMENTS_FILE%' nao encontrado."
        exit /b 1
    )
    call :log "[INFO] Instalando dependencias..."
    %PYTHON_CMD% -m pip install -r %REQUIREMENTS_FILE% >nul
    exit /b %errorlevel%

:run_server
    if not exist "%MAIN_SCRIPT%" (
        call :log "[ERRO] Script principal '%MAIN_SCRIPT%' nao encontrado."
        exit /b 1
    )
    call :log "[INFO] Iniciando o servidor em uma nova janela..."
    start "Malware Analyzer Server" cmd /k "%PYTHON_CMD% %MAIN_SCRIPT%"
    exit /b 0

:: --- Sub-rotinas Docker ---
:check_docker
    docker ps >nul 2>&1
    if !errorlevel! neq 0 (
        call :log "[ERRO] O Docker nao parece estar em execucao."
        call :log "        Por favor, inicie o Docker Desktop e tente novamente."
        exit /b 1
    )
    exit /b 0

:stop_docker_containers
    call :log "[INFO] Executando 'docker-compose down' para limpar containers antigos..."
    docker-compose down --remove-orphans
    exit /b 0

:build_docker_images
    call :log "[INFO] Executando 'docker-compose build'. Isso pode levar alguns minutos..."
    docker-compose build
    exit /b %errorlevel%

:start_docker_containers
    call :log "[INFO] Executando 'docker-compose up'. Pressione CTRL+C aqui para parar os containers."
    docker-compose up --remove-orphans
    exit /b %errorlevel%
