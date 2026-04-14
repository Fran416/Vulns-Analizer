import os
import subprocess
import requests
from datetime import datetime, timedelta

ORG = "PrefectHQ"
RESULTS_DIR = "../results"


def obtener_repos():
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
    repo_url = f"https://github.com/{ORG}/{repo_name}.git"
    destino = f"./temp_{repo_name}"

    print(f"\nAnalizando: {repo_name}\n")

    subprocess.run(["git", "clone", "--depth", "1", repo_url, destino])

    # Syft (Genera SBOM)
    print("   Generando SBOM...")
    subprocess.run(["syft", destino, "-o", "json", "--file", f"{RESULTS_DIR}/{repo_name}_sbom.json"])

    # 3. Grype (Busca vulnerabilidades)
    print("   Buscando vulnerabilidades...")
    subprocess.run(["grype", f"sbom:{RESULTS_DIR}/{repo_name}_sbom.json", "-o", "json", "--file",
                    f"{RESULTS_DIR}/{repo_name}_vulns.json"])

    
    subprocess.run(["rm", "-rf", destino])


if __name__ == "__main__":
    os.makedirs(RESULTS_DIR, exist_ok=True)
    lista = obtener_repos()
    for repo in lista:
        ejecutar_herramientas(repo)
    print("\nProceso finalizado.")