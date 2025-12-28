@echo off
setlocal
if "%~1"=="" goto menu
if /I "%~1"=="local" goto local
if /I "%~1"=="build" goto dockerbuild
if /I "%~1"=="run" goto dockerrun
if /I "%~1"=="stop" goto dockerstop
if /I "%~1"=="logs" goto dockerlogs
if /I "%~1"=="open" goto open
goto menu

:local
where python >nul 2>&1 || (echo Python nao encontrado & exit /b 1)
python -m pip install -r requirements.txt
python initializer.py
goto end

:dockerbuild
docker --version >nul 2>&1 || (echo Docker nao encontrado & exit /b 1)
docker build -t the-apex .
goto end

:dockerrun
docker --version >nul 2>&1 || (echo Docker nao encontrado & exit /b 1)
docker rm -f the-apex >nul 2>&1
docker run -d -p 5000:5000 --name the-apex the-apex
start "" http://localhost:5000
goto end

:dockerstop
docker rm -f the-apex
goto end

:dockerlogs
docker logs -f the-apex
goto end

:open
start "" http://127.0.0.1:5000
goto end

:menu
echo 1) Executar local
echo 2) Build Docker
echo 3) Run Docker
echo 4) Stop Docker
echo 5) Abrir no navegador
echo Q) Sair
choice /c:12345Q /n /m "Selecione uma opcao: "
if errorlevel 6 goto end
if errorlevel 5 goto open
if errorlevel 4 goto dockerstop
if errorlevel 3 goto dockerrun
if errorlevel 2 goto dockerbuild
if errorlevel 1 goto local
goto end

:end
endlocal
exit /b 0
