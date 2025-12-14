# --- Estágio 1: Builder ---
# Este estágio instala as dependências e as compila em "wheels",
# que são um formato de pacote otimizado.
FROM python:3.11-slim AS builder

# Define o diretório de trabalho
WORKDIR /wheels

# Instala procps para usar nproc e atualiza o pip e instala a ferramenta 'wheel'
RUN apt-get update && apt-get install -y procps && \
    pip install --upgrade pip wheel

# Copia o arquivo de dependências para o diretório de trabalho
# O arquivo requirements.txt foi movido para a raiz do projeto.
COPY requirements.txt /wheels/

# Baixa e compila todas as dependências como wheels.
# Isso acelera a instalação no estágio final e mantém o estágio de build separado.
RUN pip wheel --no-cache-dir -r requirements.txt && rm requirements.txt

# --- Estágio 2: Final ---
# Este é o estágio final que irá gerar a imagem da aplicação.
# Ele é baseado na mesma imagem slim, mas será muito menor porque
# não contém as ferramentas de build do estágio anterior.
FROM python:3.11-slim AS final

# Define o diretório de trabalho
WORKDIR /app

# Cria um usuário não-root para executar a aplicação.
# Isso é uma prática de segurança importante para evitar que a aplicação
# rode com privilégios de administrador dentro do contêiner.
RUN useradd --create-home --shell /bin/bash appuser && chown -R appuser:appuser /app

# Copia as dependências pré-compiladas (wheels) do estágio 'builder'
COPY --from=builder /wheels /wheels

# Instala as dependências a partir dos wheels locais, sem acessar a internet.
RUN pip install --no-cache --no-index --find-links=/wheels /wheels/* && \
    rm -rf /wheels /root/.cache

# Copia o código da aplicação para o diretório de trabalho
COPY --chown=appuser:appuser ./app ./app
# O arquivo wsgi.py é o ponto de entrada para servidores WSGI como Gunicorn.
COPY --chown=appuser:appuser ./wsgi.py .
# Copia o script de execução principal para garantir que ele exista mesmo se o volume falhar
COPY --chown=appuser:appuser ./run.py .

# Muda para o usuário não-root
USER appuser

# Expõe a porta em que a aplicação irá rodar
EXPOSE 5000

# Adiciona um healthcheck para verificar a saúde da aplicação
HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=20s \
    CMD curl --fail http://localhost:5000/ || exit 1

# Define variáveis de ambiente para o Flask (opcional, pode ser gerenciado por .env)
# Manter FLASK_ENV para que a aplicação possa se comportar de forma diferente em produção.
ENV FLASK_ENV=production

# Comando para iniciar o servidor de produção com Hypercorn (ASGI)
CMD ["hypercorn", "--bind", "0.0.0.0:5000", "wsgi:app"]
