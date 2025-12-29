import os
import asyncio
from pathlib import Path
from hypercorn.config import Config
from hypercorn.asyncio import serve
from app import create_app
from app import quart_db

def prepare_environment():
    base_dir = Path(__file__).parent
    instance_dir = base_dir / "instance"
    instance_dir.mkdir(parents=True, exist_ok=True)
    quart_db.init_db()

def build_config() -> Config:
    host = os.environ.get("APP_HOST", "127.0.0.1")
    port = os.environ.get("APP_PORT", "5000")
    reload_flag = os.environ.get("APP_RELOAD", "false").lower() in ("true", "1", "t", "yes")
    workers = int(os.environ.get("APP_WORKERS", "2"))
    cfg = Config()
    cfg.bind = [f"{host}:{port}"]
    cfg.use_reloader = reload_flag
    cfg.workers = workers
    return cfg

async def main():
    prepare_environment()
    app = create_app()
    cfg = build_config()
    bind = cfg.bind[0] if cfg.bind else "127.0.0.1:5000"
    host, port = bind.split(":")
    display_host = "127.0.0.1" if host in ("0.0.0.0", "0:0:0:0") else host
    print(f"Access: http://{display_host}:{port}/")
    await serve(app, cfg)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
