
import subprocess
import time
import os
import signal

def test_server():
    print("Iniciando servidor para teste...")
    # Inicia o servidor em background
    process = subprocess.Popen(['python', 'run.py'], 
                             stdout=subprocess.PIPE, 
                             stderr=subprocess.STDOUT,
                             text=True,
                             encoding='utf-8')
    
    try:
        # Aguarda o servidor subir
        time.sleep(5)
        
        print("Enviando requisição para /inicio...")
        # Usa curl.exe para testar
        result = subprocess.run(['curl.exe', '-i', 'http://127.0.0.1:5000/inicio'], 
                              capture_output=True, text=True, encoding='utf-8')
        
        print("\n--- RESPOSTA DO CURL ---")
        print(result.stdout)
        print("------------------------\n")
        
        # Lê o que o servidor cuspiu até agora
        print("--- LOGS DO SERVIDOR ---")
        # Como o processo ainda está rodando, pegamos o que foi gerado
        try:
            out, _ = process.communicate(timeout=2)
            print(out)
        except subprocess.TimeoutExpired:
            # Se der timeout, matamos e pegamos o que der
            process.kill()
            out, _ = process.communicate()
            print(out)
        print("------------------------")
        
    finally:
        if process.poll() is None:
            process.kill()

if __name__ == "__main__":
    test_server()
