FROM python:3.12-slim

# Evita a criação de arquivos .pyc e garante logs em tempo real
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Instala dependências de sistema necessárias (ex: curl para healthchecks)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Cria um usuário não-root para maior segurança
RUN adduser --disabled-password --gecos "" apexuser

WORKDIR /app

# Copia e instala dependências separadamente para aproveitar o cache do Docker
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copia o código da aplicação
COPY app ./app
COPY run.py .
COPY initializer.py .
COPY hypercorn_config.toml .

# Cria o diretório instance para o banco de dados e define as permissões
RUN mkdir -p /app/instance && chown -R apexuser:apexuser /app

# Alterna para o usuário não-root
USER apexuser

# Expõe a porta da aplicação
EXPOSE 5000

# Comando de inicialização
CMD ["python", "initializer.py"]
