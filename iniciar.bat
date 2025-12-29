@echo off
setlocal enabledelayedexpansion
title THE APEX - System Launcher

:menu
cls
echo ======================================================
echo           THE APEX - CYBERSECURITY PLATFORM
echo ======================================================
echo [1] Executar Local (Apenas App - Requer Python)
echo [2] Executar via Docker (Sistema Completo + SOC Stack)
echo [3] Executar via Docker (Apenas SOC Stack: Elastic Stack)
echo [4] Rebuild Containers (Build do Zero)
echo [5] Parar Tudo e Limpar Containers
echo [6] Ver Logs do Sistema
echo [7] Abrir Dashboards (App, Kibana)
echo [8] Modo Diagnostico (Passo a Passo)
echo [Q] Sair
echo ======================================================
set /p choice="Selecione uma opcao: "

if "%choice%"=="1" goto local
if "%choice%"=="2" goto dockertotal
if "%choice%"=="3" goto dockerstack
if "%choice%"=="4" goto dockerbuild
if "%choice%"=="5" goto dockerstop
if "%choice%"=="6" goto dockerlogs
if "%choice%"=="7" goto open
if "%choice%"=="8" goto diagnosis
if /I "%choice%"=="Q" goto end
goto menu

:local
echo [+] Configurando variaveis de ambiente locais...
:: Altere aqui se o seu Elasticsearch estiver em outro endereço/porta
if not defined ELASTIC_API_URL set ELASTIC_API_URL=http://localhost:9200

echo [+] Iniciando ambiente local...
where python >nul 2>&1 || (echo [!] Python nao encontrado no PATH & pause & goto menu)
echo [+] Instalando/Atualizando dependencias...
python -m pip install -r requirements.txt
echo [+] Iniciando The APEX...
python initializer.py
pause
goto menu

:check_docker
where docker >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [!] ERRO: Comando 'docker' nao encontrado no PATH.
    echo [!] Certifique-se de que o Docker Desktop esta instalado e rodando.
    pause
    goto menu
)
where docker-compose >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [!] AVISO: Comando 'docker-compose' antigo nao encontrado. 
    echo [+] Tentando usar 'docker compose' (V2)...
    set DOCKER_CMD=docker compose
) else (
    set DOCKER_CMD=docker-compose
)
goto :eof

:dockertotal
echo [+] Iniciando ambiente Docker...
call :check_docker
echo [+] Executando: %DOCKER_CMD% up -d
%DOCKER_CMD% up -d
if %ERRORLEVEL% neq 0 (
    echo [!] Erro ao subir containers. Verifique o Docker Desktop.
    pause
    goto menu
)
echo [+] Aguardando inicializacao dos servicos...
timeout /t 5
start "" http://localhost:5000
echo [+] App: http://localhost:5000
echo [+] Kibana: http://localhost:5601
pause
goto menu

:dockerstack
call :check_docker
echo [+] Iniciando apenas SOC Stack (Elastic Stack)...
%DOCKER_CMD% up -d elasticsearch kibana
if %ERRORLEVEL% neq 0 (
    echo [!] Erro ao subir SOC Stack.
    pause
    goto menu
)
echo [+] SOC Stack iniciado.
pause
goto menu

:dockerbuild
call :check_docker
echo [+] Remontando containers...
%DOCKER_CMD% down
%DOCKER_CMD% build --no-cache
if %ERRORLEVEL% neq 0 (
    echo [!] Erro durante o build dos containers.
    pause
    goto menu
)
echo [+] Build concluido.
pause
goto menu

:dockerstop
call :check_docker
echo [+] Parando e removendo containers...
%DOCKER_CMD% down
echo [+] Sistema parado.
pause
goto menu

:dockerlogs
call :check_docker
echo [+] Exibindo logs (Pressione CTRL+C para sair dos logs)...
%DOCKER_CMD% logs -f
goto menu

:diagnosis
cls
echo ======================================================
echo           THE APEX - MODO DIAGNOSTICO
echo ======================================================
echo [Step 1] Verificando Python...
where python
if %ERRORLEVEL% == 0 (python --version) else (echo [!] Python NAO encontrado)
pause

echo.
echo [Step 2] Verificando Docker...
where docker
if %ERRORLEVEL% == 0 (docker --version) else (echo [!] Docker NAO encontrado)
pause

echo.
echo [Step 3] Verificando Docker Compose...
where docker-compose
if %ERRORLEVEL% == 0 (docker-compose --version) else (
    docker compose version >nul 2>&1
    if %ERRORLEVEL% == 0 (echo [+] Docker Compose V2 detectado) else (echo [!] Docker Compose NAO encontrado)
)
pause

echo.
echo [Step 4] Verificando status do Daemon Docker...
docker ps >nul 2>&1
if %ERRORLEVEL% == 0 (echo [+] Docker Daemon esta rodando.) else (echo [!] Docker Daemon NAO esta respondendo! Abra o Docker Desktop.)
pause

echo.
echo [Step 5] Validando arquivo docker-compose.yml...
if exist docker-compose.yml (
    echo [+] Arquivo encontrado. Validando sintaxe...
    docker compose config -q
    if %ERRORLEVEL% == 0 (echo [+] Sintaxe OK.) else (echo [!] Erro de sintaxe no docker-compose.yml)
) else (
    echo [!] Erro: docker-compose.yml nao encontrado na pasta atual.
)
pause

echo [+] Diagnostico concluido.
goto menu

:open
echo [+] Abrindo dashboards no navegador...
start "" http://localhost:5000
start "" http://localhost:5601
goto menu

:end
echo [+] Saindo...
endlocal
exit /b 0
