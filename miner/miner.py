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
from dataset import generar_dataset_final

ORG = "PrefectHQ"
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RESULTS_DIR = os.path.join(BASE_DIR, "results")


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
    Clona el repositorio, genera su SBOM con Syft, busca vulnerabilidades con Grype
    y luego ejecuta CodeQL.

    @param repo_name: Nombre del repositorio a analizar.
    @return: None
    """
    repo_url = f"https://github.com/{ORG}/{repo_name}.git"
    destino = f"./temp_{repo_name}"
    db_path = f"./db_{repo_name}" 

    print(f"Analizando: {repo_name}")

    clone_result = subprocess.run(
        ["git", "clone", "--depth", "1", repo_url, destino],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if clone_result.returncode != 0:
        print(f" Git clone failed for {repo_name}: {clone_result.stderr.strip()}")
        return

    sbom_file = generar_sbom(repo_name, destino)
    if sbom_file is None:
        subprocess.run(["rm", "-rf", destino])
        return

    vuln_file = buscar_vulnerabilidades(repo_name, destino)
    if vuln_file is None:
        subprocess.run(["rm", "-rf", destino])
        return

    analizar_con_codeql(repo_name, destino, db_path)

    subprocess.run(["rm", "-rf", destino])
    if os.path.exists(db_path):
        subprocess.run(["rm", "-rf", db_path])


def generar_sbom(repo_name, fuente):
    print("   Generando SBOM...")
    os.makedirs(RESULTS_DIR, exist_ok=True)
    sbom_file = os.path.join(RESULTS_DIR, f"{repo_name}_sbom.json")
    try:
        with open(sbom_file, "w", encoding="utf-8") as out:
            subprocess.run(
                ["syft", fuente, "-o", "json"],
                check=True,
                stdout=out,
                stderr=subprocess.PIPE,
                text=True,
            )
        print(f"   SBOM escrito en: {sbom_file}")
        return sbom_file
    except subprocess.CalledProcessError as e:
        print(f" Syft error para {repo_name}: {e}")
        if e.stderr:
            print(f"   stderr:\n{e.stderr}")
        return None


def buscar_vulnerabilidades(repo_name, fuente):
    print("   Buscando vulnerabilidades...")
    os.makedirs(RESULTS_DIR, exist_ok=True)
    vuln_file = os.path.join(RESULTS_DIR, f"{repo_name}_vulns.json")
    try:
        with open(vuln_file, "w", encoding="utf-8") as out:
            subprocess.run(
                ["grype", fuente, "-o", "json"],
                check=True,
                stdout=out,
                stderr=subprocess.PIPE,
                text=True,
            )
        print(f"   Vulnerabilidades escrito en: {vuln_file}")
        return vuln_file
    except subprocess.CalledProcessError as e:
        print(f" Grype error para {repo_name}: {e}")
        if e.stderr:
            print(f"   stderr:\n{e.stderr}")
        return None


def analizar_con_codeql(repo_name, fuente, db_path):
    """
    Intenta crear una base de datos y analizar el código fuente
    probando primero con Python y luego con JavaScript/TypeScript.
    """
    output_file = f"{RESULTS_DIR}/{repo_name}_codeql.sarif"

    lenguajes_a_probar = ["python", "javascript"]
    
    for lang in lenguajes_a_probar:
        print(f"   Intentando CodeQL con lenguaje: {lang}...")
        try:
            subprocess.run([
                "codeql", "database", "create", db_path,
                f"--language={lang}",
                "--source-root", fuente,
                "--overwrite"
            ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            query_suite = f"{lang}-code-scanning.qls" if lang == "python" else "javascript-code-scanning.qls"
            
            subprocess.run([
                "codeql", "database", "analyze", db_path,
                query_suite, 
                "--format=sarif-latest", 
                f"--output={output_file}"
            ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            print(f"   [+] CodeQL finalizado con éxito ({lang}). Reporte: {output_file}")
            return True

        except subprocess.CalledProcessError:

            if os.path.exists(db_path):
                subprocess.run(["rm", "-rf", db_path])
            continue

    print(f" No se pudo generar reporte de CodeQL para {repo_name} (No se detectó código Py/JS)")
    return False