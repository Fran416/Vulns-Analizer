"""
    Miner de repositorios de PrefectHQ. Este script se encarga de:
    1. Obtener los repositorios activos de la organización PrefectHQ en GitHub.
    2. Clonar cada repositorio y generar su SBOM utilizando Syft.
    3. Analizar el SBOM con Grype para identificar vulnerabilidades.
    4. Guardar los resultados en formato JSON en un directorio específico.
"""


import os
import subprocess
import requests
from datetime import datetime, timedelta

ORG = "PrefectHQ"
RESULTS_DIR = "../results"


def obtener_repos():
    """
    Filtra los reopositorios para obtener solo los que han tenido actividad en el último mes. 
    Además, se limita a los 50 repositorios más activos para optimizar el proceso.

    @return: Lista de nombres de repositorios activos.
    
    """
    print(f"Obteniendo repositorios activos de {ORG}...")
    url = f"https://api.github.com/orgs/{ORG}/repos?per_page=100&sort=pushed"
    
    fecha_limite = datetime.now() - timedelta(days=30)
    
    response = requests.get(url).json()
    
    repos_validos = []
    for r in response:
        if r['fork']: continue
        
        fecha_push = datetime.strptime(r['pushed_at'], '%Y-%m-%dT%H:%M:%SZ')
        
        if fecha_push > fecha_limite:
            repos_validos.append(r['name'])
        
        if len(repos_validos) >= 50:
            break
            
    print(f"Se encontraron {len(repos_validos)} repositorios activos.")
    return repos_validos


def ejecutar_herramientas(repo_name):
    """
    Clona el repositorio, genera su SBOM con Syft y luego busca vulnerabilidades con Grype.

    @param repo_name: Nombre del repositorio a analizar.
    @return: None
    """
    repo_url = f"https://github.com/{ORG}/{repo_name}.git"
    destino = f"./temp_{repo_name}"

    print(f"Analizando: {repo_name}")

    subprocess.run(["git", "clone", "--depth", "1", repo_url, destino], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Syft (Genera SBOM)
    print("   Generando SBOM...")
    subprocess.run(["syft", destino, "-o", "json", "--file", f"{RESULTS_DIR}/{repo_name}_sbom.json"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # 3. Grype (Busca vulnerabilidades)
    print("   Buscando vulnerabilidades...")
    subprocess.run(["grype", f"sbom:{RESULTS_DIR}/{repo_name}_sbom.json", "-o", "json", "--file",
                    f"{RESULTS_DIR}/{repo_name}_vulns.json"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    buscar_secretos(repo_name, destino)

     # Limpieza: Eliminamos la carpeta temporal del repositorio clonado para ahorrar espacio.   

    subprocess.run(["rm", "-rf", destino])


def buscar_secretos(repo_name, destino):
    """
    Ejecuta Gitleaks sobre el repositorio clonado para identificar exposición de secretos.
    """
    print("   Buscando exposición de secretos (Gitleaks)...")
    output_file = f"{RESULTS_DIR}/{repo_name}_secrets.json"

    # Ejecutamos gitleaks detect sobre la carpeta temporal
    subprocess.run([
        "gitleaks", "detect",
        "--source", destino,
        "--report-format", "json",
        "--report-path", output_file,
        "--exit-code", "0"  # Para que el script no se detenga si encuentra secretos
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)