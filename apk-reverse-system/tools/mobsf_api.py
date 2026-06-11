import requests
import json
import time
import os
import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)

class MobSFWrapper:
    """Wrapper para comunicarse con la API REST de MobSF"""
    
    def __init__(self, server_url: str = "http://localhost:8000", api_key: str = None):
        """
        Args:
            server_url: URL base de MobSF
            api_key: API Key de MobSF (necesaria para interactuar)
        """
        self.server_url = server_url.rstrip('/')
        self.api_key = api_key or os.environ.get('MOBSF_API_KEY', '')
        self.headers = {'Authorization': self.api_key}
        
    def upload_and_analyze(self, file_path: str, wait: bool = True) -> Dict:
        """
        Sube un archivo a MobSF y comienza el análisis
        
        Args:
            file_path: Ruta al archivo APK/IPA
            wait: Esperar a que termine el análisis
            
        Returns:
            Dict con los resultados (o status)
        """
        if not self.api_key:
            return {'success': False, 'error': 'No se configuró MOBSF_API_KEY'}
            
        if not os.path.exists(file_path):
            return {'success': False, 'error': f'Archivo no encontrado: {file_path}'}
            
        upload_url = f"{self.server_url}/api/v1/upload"
        
        logger.info(f"Subiendo archivo {file_path} a MobSF...")
        
        try:
            with open(file_path, 'rb') as f:
                files = {'file': (os.path.basename(file_path), f, 'application/octet-stream')}
                response = requests.post(upload_url, headers=self.headers, files=files)
                
            if response.status_code != 200:
                return {'success': False, 'error': f'Error al subir a MobSF: {response.text}'}
                
            upload_data = response.json()
            file_hash = upload_data.get('hash')
            scan_type = upload_data.get('scan_type')
            file_name = upload_data.get('file_name')
            
            if not wait:
                return {'success': True, 'hash': file_hash, 'status': 'uploaded'}
                
            logger.info(f"Archivo subido exitosamente. Hash: {file_hash}. Iniciando análisis...")
            
            scan_url = f"{self.server_url}/api/v1/scan"
            scan_data = {'hash': file_hash, 'scan_type': scan_type, 'file_name': file_name}
            scan_response = requests.post(scan_url, headers=self.headers, data=scan_data)
            
            if scan_response.status_code != 200:
                return {'success': False, 'error': f'Error en escaneo de MobSF: {scan_response.text}'}
            
            scan_result = scan_response.json()
            return {
                'success': True,
                'hash': file_hash,
                'scan_type': scan_type,
                'report': scan_result
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def get_report_json(self, file_hash: str) -> Dict:
        """Obtiene el reporte en JSON para un hash dado"""
        report_url = f"{self.server_url}/api/v1/report_json"
        
        try:
            response = requests.post(report_url, headers=self.headers, data={'hash': file_hash})
            if response.status_code != 200:
                return {'success': False, 'error': f'Error al obtener reporte: {response.text}'}
            
            return {'success': True, 'report': response.json()}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def delete_scan(self, file_hash: str) -> Dict:
        """Elimina el escaneo de MobSF"""
        delete_url = f"{self.server_url}/api/v1/delete_scan"
        
        try:
            response = requests.post(delete_url, headers=self.headers, data={'hash': file_hash})
            return {'success': response.status_code == 200}
        except Exception as e:
            return {'success': False, 'error': str(e)}
