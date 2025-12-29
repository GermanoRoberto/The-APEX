# -*- coding: utf-8 -*-
"""
Módulo de Utilidades para Auditoria Windows.
Responsável por coletar informações de hardware, rede e gerenciar criptografia.
"""
import os
import subprocess
import platform
import uuid
import socket
import json
import logging
import base64
from datetime import datetime
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

def get_machine_info() -> Dict[str, Any]:
    """
    Coleta informações básicas e identificadores únicos da máquina.
    """
    info = {
        "hostname": platform.node(),
        "os": f"{platform.system()} {platform.release()}",
        "architecture": platform.machine(),
        "ip_primary": _get_primary_ip(),
        "mac_address": _get_mac_address(),
        "hardware_id": _get_hardware_id(),
        "timestamp": datetime.now().isoformat()
    }
    return info

def _get_primary_ip() -> str:
    """Obtém o endereço IP primário da máquina."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Não precisa conectar de verdade, apenas para pegar a interface de saída
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def _get_mac_address() -> str:
    """Obtém o endereço MAC da interface principal."""
    try:
        mac = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff)
                        for ele in range(0, 8*6, 8)][::-1])
        return mac
    except Exception:
        return "00:00:00:00:00:00"

def _get_hardware_id() -> str:
    """
    Gera um identificador único baseado no hardware (UUID do Windows).
    """
    try:
        if platform.system() == "Windows":
            cmd = "wmic csproduct get uuid"
            output = subprocess.check_output(cmd, shell=True).decode().split()
            if len(output) >= 2:
                return output[1]
    except Exception as e:
        logger.error(f"Erro ao obter Hardware ID: {e}")
    
    # Fallback para um ID persistente baseado no MAC se o wmic falhar
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, _get_mac_address() + platform.node()))

# Gerenciamento de Criptografia
def encrypt_data(data: str, key: str) -> str:
    """
    Criptografa uma string usando a chave fornecida.
    Se a biblioteca cryptography não estiver disponível, usa base64 (fallback inseguro).
    """
    try:
        from cryptography.fernet import Fernet
        f = Fernet(key.encode())
        return f.encrypt(data.encode()).decode()
    except ImportError:
        logger.warning("cryptography não instalada. Usando fallback base64 para 'criptografia'.")
        return base64.b64encode(data.encode()).decode()
    except Exception as e:
        logger.error(f"Erro na criptografia: {e}")
        return data

def decrypt_data(token: str, key: str) -> str:
    """
    Descriptografa uma string usando a chave fornecida.
    """
    try:
        from cryptography.fernet import Fernet
        f = Fernet(key.encode())
        return f.decrypt(token.encode()).decode()
    except ImportError:
        return base64.b64decode(token.encode()).decode()
    except Exception as e:
        logger.error(f"Erro na descriptografia: {e}")
        return token

def generate_audit_key() -> str:
    """Gera uma chave compatível com Fernet."""
    try:
        from cryptography.fernet import Fernet
        return Fernet.generate_key().decode()
    except ImportError:
        return base64.b64encode(os.urandom(32)).decode()

def validate_audit_data(data: Dict[str, Any]) -> bool:
    """
    Valida se os dados de auditoria são estruturalmente corretos.
    """
    try:
        # Tenta extrair machine_info com fallback para dict vazio
        m_info = data.get('machine_info', {})
        if not m_info:
             logger.error("Validação falhou: machine_info está vazio ou ausente.")
             return False

        # Campos obrigatórios da máquina
        required_machine = ["hostname", "ip_primary", "mac_address", "hardware_id"]
        missing_m = [k for k in required_machine if k not in m_info or not m_info[k]]
        
        if missing_m:
            logger.error(f"Validação falhou: Campos de máquina ausentes ou vazios: {missing_m}. Data: {m_info}")
            return False
            
        # Campos obrigatórios do evento
        if not data.get('event_type'):
            logger.error("Validação falhou: Tipo de evento ausente.")
            return False
        
        if not data.get('status'):
            logger.error("Validação falhou: Status ausente.")
            return False
            
        return True
    except Exception as e:
        logger.error(f"Erro crítico durante validação de dados: {e}")
        return False

def get_vault_credentials() -> list:
    """
    Coleta credenciais do Windows Vault usando o comando cmdkey.
    Retorna uma lista de dicionários com target, type e user.
    """
    try:
        # Executa cmdkey /list
        output = subprocess.check_output("cmdkey /list", shell=True).decode(errors="ignore")
        
        entries = []
        current = {}
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
                
            # Suporta inglês (Target, Type, User) e português (Destino, Tipo, Usuário)
            if ":" in line:
                key, val = line.split(":", 1)
                key = key.strip().lower()
                val = val.strip()
                
                if key in ["target", "destino"]:
                    if current:
                        entries.append(current)
                    current = {"target": val}
                elif key in ["type", "tipo"]:
                    current["type"] = val
                elif key in ["user", "usuário", "usuario"]:
                    current["user"] = val
                
        if current:
            entries.append(current)
            
        return entries
    except Exception as e:
        logger.error(f"Erro ao coletar credenciais do Vault: {e}")
        return []
