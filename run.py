import asyncio
import os
import webbrowser
from hypercorn.config import Config
from hypercorn.asyncio import serve

from app import create_app

async def main():
    """
    Ponto de entrada assíncrono para configurar e iniciar o servidor Hypercorn.
    Carrega a configuração de um arquivo externo para maior clareza e flexibilidade.
    """
    app = create_app()

    # Carrega a configuração do Hypercorn a partir do arquivo hypercorn_config.py
    config = Config().from_pyfile("hypercorn_config.py")
    
    # Informa ao Quart se está em modo de depuração, o que é usado no __init__.py
    # para acionar a abertura automática do navegador.
    app.debug = config.use_reloader

    print("\n🛡️  THE APEX ARCHITECT // MALWARE ANALYZER 🛡️")
    print(f"👉 Access: http://{config.bind[0]}")
    
    if config.use_reloader:
        print(f"ℹ️  Reloader Active. Ignoring: {config.reload_exclude_patterns}")
    print("👉 CTRL+C to shutdown\n")

    # Inicia o servidor com a configuração carregada.
    await serve(app, config)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n🛑 System shutdown initiated by user.")