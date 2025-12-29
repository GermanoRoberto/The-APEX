
import asyncio
import os
import sys

# Adiciona o diretório raiz ao path
sys.path.append(os.getcwd())

from app import create_app
from app import quart_db as database
from app import utils
from datetime import datetime

async def test_inicio_logic():
    print("Iniciando teste da lógica do Dashboard...")
    
    # Mock do app context
    app = create_app()
    
    async with app.app_context():
        try:
            print("1. Testando utils.get_key_status()...")
            key_status = utils.get_key_status()
            print(f"   Status das chaves: {list(key_status.keys())}")
            
            print("2. Testando database.get_all_analyses()...")
            all_analyses_raw = database.get_all_analyses()
            print(f"   Total de análises brutas encontradas: {len(all_analyses_raw)}")
            
            # Filtra 'audit' e 'vault' conforme a lógica da rota /inicio
            all_analyses = [a for a in all_analyses_raw if a.get('item_type') not in ['audit', 'vault']]
            print(f"   Total de análises após filtragem: {len(all_analyses)}")
            
            stats = {
                'criticos': 0,
                'alertas': 0,
                'analises': 0,
                'resolvidos': 0,
                'recentes': [],
                'chart_data': [0] * 7
            }
            
            if all_analyses:
                print("3. Processando estatísticas...")
                stats['criticos'] = len([a for a in all_analyses if a.get('final_verdict') == 'malicious'])
                stats['alertas'] = len([a for a in all_analyses if a.get('final_verdict') in ['malicious', 'suspicious']])
                stats['analises'] = len(all_analyses)
                stats['resolvidos'] = len([a for a in all_analyses if a.get('final_verdict') == 'clean'])
                stats['recentes'] = all_analyses[:3]

                now = datetime.now()
                for analysis in all_analyses:
                    created_at = analysis.get('created_at')
                    if created_at:
                        try:
                            ts = float(created_at)
                            dt = datetime.fromtimestamp(ts)
                            delta = now - dt
                            days_ago = delta.days
                            
                            if 0 <= days_ago < 7:
                                stats['chart_data'][6 - days_ago] += 1
                        except Exception as e:
                            print(f"   Erro ao processar data da análise: {e}")
                            continue
                print(f"   Estatísticas calculadas: {stats}")

            print("4. Testando renderização (simulada)...")
            # Aqui não podemos renderizar o template facilmente sem um request context completo,
            # mas a lógica acima é o que costuma falhar.
            
            print("TESTE CONCLUÍDO COM SUCESSO!")
            
        except Exception as e:
            print(f"ERRO IDENTIFICADO: {e}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_inicio_logic())
