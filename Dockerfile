FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY app /app/app
COPY run.py /app/run.py
COPY initializer.py /app/initializer.py
COPY hypercorn_config.toml /app/hypercorn_config.toml
EXPOSE 5000
CMD ["python","/app/initializer.py"]
