import os
import subprocess
import requests
import json
from datetime import datetime, timedelta

ORG = "PrefectHQ"
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RESULTS_DIR = os.path.join(BASE_DIR, "results")

def obtener_repos():
    """
    Filtra los repositorios activos y retorna solo la lista de nombres.
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


def obtener_lenguajes_desde_sbom(ruta_sbom):
    """
    Lee el SBOM y devuelve un set de TODOS los lenguajes detectados,
    listos para ser usados por CodeQL (Repositorios políglotas).
    """
    if not os.path.exists(ruta_sbom) or os.path.getsize(ruta_sbom) == 0:
        return []
        
    try:
        with open(ruta_sbom, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        artifacts = data.get('artifacts', [])
        
        # 1. Recopilamos todos los ecosistemas únicos que encontró Syft
        syft_types = set()
        for artifact in artifacts:
            tipo = artifact.get('type')
            if tipo:
                syft_types.add(tipo.lower())
                
        # 2. Mapeamos lo que encontró Syft a los lenguajes de CodeQL
        codeql_lang_map = {
            "python": "python",
            "npm": "javascript",
            "yarn": "javascript",
            "go-module": "go",
            "java-archive": "java",
            "gem": "ruby",
            "cargo": "cpp"
        }

        # 3. Creamos la lista final
        lenguajes_a_escanear = set()
        for t in syft_types:
            if t in codeql_lang_map:
                lenguajes_a_escanear.add(codeql_lang_map[t])
                
        return list(lenguajes_a_escanear)
        
    except Exception as e:
        print(f"   [!] Error al leer ecosistemas del SBOM: {e}")
        return []


def ejecutar_herramientas(repo_name):
    """
    Ejecuta el pipeline: Clona -> SBOM -> Grype -> Lee Ecosistemas -> CodeQL (Multi-lang)
    """
    repo_url = f"https://github.com/{ORG}/{repo_name}.git"
    destino = f"./temp_{repo_name}"
    db_path_base = f"./db_{repo_name}" 

    print(f"\n[{repo_name}] Iniciando extracción de seguridad...")

    clone_result = subprocess.run(
        ["git", "clone", "--depth", "1", repo_url, destino],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if clone_result.returncode != 0:
        print(f" [!] Git clone falló para {repo_name}: {clone_result.stderr.strip()}")
        return

    # 1. Generar SBOM
    sbom_file = generar_sbom(repo_name, destino)
    if sbom_file is None:
        subprocess.run(["rm", "-rf", destino])
        return

    # 2. Buscar Vulnerabilidades (SCA)
    vuln_file = buscar_vulnerabilidades(repo_name, destino)
    if vuln_file is None:
        subprocess.run(["rm", "-rf", destino])
        return

    # 3. Extraer TODOS los lenguajes del SBOM
    lenguajes = obtener_lenguajes_desde_sbom(sbom_file)
    
    # 4. Analizar con CodeQL iterando sobre lenguajes detectados (SAST)
    if lenguajes:
        print(f"   [+] Repositorio políglota. Lenguajes detectados: {lenguajes}")
        for lang in lenguajes:
            db_path_lang = f"{db_path_base}_{lang}"
            analizar_con_codeql(repo_name, destino, db_path_lang, lang)
    else:
        print("   [!] No se detectaron lenguajes soportados por CodeQL en el SBOM.")

    # 5. Limpieza del entorno
    subprocess.run(["rm", "-rf", destino])
    if lenguajes:
        for lang in lenguajes:
            db_path_lang = f"{db_path_base}_{lang}"
            if os.path.exists(db_path_lang):
                subprocess.run(["rm", "-rf", db_path_lang])


def generar_sbom(repo_name, fuente):
    print("   Generando SBOM con Syft...")
    os.makedirs(RESULTS_DIR, exist_ok=True)
    sbom_file = os.path.join(RESULTS_DIR, f"{repo_name}_sbom.json")
    try:
        with open(sbom_file, "w", encoding="utf-8") as out:
            subprocess.run(["syft", fuente, "-o", "json"], check=True, stdout=out, stderr=subprocess.PIPE, text=True)
        return sbom_file
    except subprocess.CalledProcessError:
        print(f" [!] Syft error para {repo_name}")
        return None


def buscar_vulnerabilidades(repo_name, fuente):
    print("   Buscando vulnerabilidades con Grype...")
    os.makedirs(RESULTS_DIR, exist_ok=True)
    vuln_file = os.path.join(RESULTS_DIR, f"{repo_name}_vulns.json")
    try:
        with open(vuln_file, "w", encoding="utf-8") as out:
            subprocess.run(["grype", fuente, "-o", "json"], check=True, stdout=out, stderr=subprocess.PIPE, text=True)
        return vuln_file
    except subprocess.CalledProcessError:
        print(f" [!] Grype error para {repo_name}")
        return None


def analizar_con_codeql(repo_name, fuente, db_path, lang):
    """
    Ejecuta el escaneo CodeQL para un lenguaje específico.
    """
    output_file = f"{RESULTS_DIR}/{repo_name}_{lang}_codeql.sarif"
    print(f"   Ejecutando CodeQL para: {lang}...")

    try:
        # 1. Crear Base de Datos
        subprocess.run([
            "codeql", "database", "create", db_path,
            f"--language={lang}",
            "--source-root", fuente,
            "--overwrite"
        ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # 2. Analizar Base de Datos
        query_suite = f"{lang}-code-scanning.qls"
        subprocess.run([
            "codeql", "database", "analyze", db_path,
            query_suite, 
            "--format=sarif-latest", 
            f"--output={output_file}"
        ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        print(f"   [+] SAST completado con éxito ({lang}).")
        return True

    except subprocess.CalledProcessError:
        print(f"   [!] CodeQL falló para {lang} (Sin código ejecutable o entorno no compatible). Saltando...")
        return False


if __name__ == "__main__":
    repositorios = obtener_repos()
    for repo_name in repositorios:
        ejecutar_herramientas(repo_name)