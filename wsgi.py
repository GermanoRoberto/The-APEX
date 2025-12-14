from app import create_app

# Cria a instância da aplicação que será usada pelo servidor ASGI (Hypercorn).
app = create_app()