from app import create_app
import asyncio

async def check_routes():
    app = create_app()
    print("--- REGISTERED ROUTES ---")
    for rule in app.url_map.iter_rules():
        print(f"Endpoint: {rule.endpoint}, Methods: {rule.methods}, Rule: {rule.rule}")
    print("-------------------------")

if __name__ == "__main__":
    asyncio.run(check_routes())
