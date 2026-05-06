import json
import os
import glob
from datetime import datetime

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RESULTS_DIR = os.path.join(BASE_DIR, "results")
OUTPUT_FILE = os.path.join(RESULTS_DIR, "summary_prefect.json")


def extraer_metricas_grype(ruta_json):
    """Extrae conteo de vulnerabilidades por severidad desde Grype."""
    if not os.path.exists(ruta_json) or os.path.getsize(ruta_json) == 0:
        return {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        
    try:
        with open(ruta_json, 'r', encoding='utf-8') as f:
            data = json.load(f)

        conteo = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for match in data.get('matches', []):
            sev = match.get('vulnerability', {}).get('severity', 'Unknown')
            if sev in conteo:
                conteo[sev] += 1
        return conteo
    except Exception:
        return {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}


def extraer_metricas_codeql(ruta_sarif):
    """Cuenta el total de alertas en el archivo SARIF de CodeQL."""
    if not os.path.exists(ruta_sarif) or os.path.getsize(ruta_sarif) == 0:
        return 0
        
    try:
        with open(ruta_sarif, 'r', encoding='utf-8') as f:
            data = json.load(f)

        total = 0
        for run in data.get('runs', []):
            total += len(run.get('results', []))
        return total
    except Exception:
        return 0


def obtener_ecosistema_desde_sbom(ruta_sbom):
    """
    Basado en el Notebook 02_analisis_dependencias.ipynb:
    Lee el SBOM, cuenta los tipos de componentes ('python', 'npm', etc.)
    y devuelve el ecosistema predominante.
    """
    if not os.path.exists(ruta_sbom) or os.path.getsize(ruta_sbom) == 0:
        return "Desconocido"
        
    try:
        with open(ruta_sbom, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        artifacts = data.get('artifacts', [])
        if not artifacts:
            return "Desconocido"
            
        # Contar la cantidad de componentes por ecosistema (type)
        conteo_tipos = {}
        for artifact in artifacts:
            tipo = artifact.get('type', 'Desconocido')
            conteo_tipos[tipo] = conteo_tipos.get(tipo, 0) + 1
            
        # Retornar el tipo con más dependencias (ej. 'python' o 'npm')
        ecosistema_principal = max(conteo_tipos, key=conteo_tipos.get)
        return ecosistema_principal
        
    except Exception:
        return "Desconocido"


def generar_dataset_final():
    """Genera el summary.json unificado."""
    print("\nGenerando dataset estructurado consolidado...")
    resumen = []

    archivos_vulns = glob.glob(os.path.join(RESULTS_DIR, "*_vulns.json"))

    if not archivos_vulns:
        print(f" [!] No se encontraron archivos en {RESULTS_DIR}.")
        return

    for archivo in archivos_vulns:
        repo_name = os.path.basename(archivo).replace("_vulns.json", "")

        # 1. Datos de Grype
        metrics_grype = extraer_metricas_grype(archivo)

        # 2. Datos de CodeQL
        sarif_path = os.path.join(RESULTS_DIR, f"{repo_name}_codeql.sarif")
        metrics_codeql = extraer_metricas_codeql(sarif_path)
        
        # 3. Datos del Ecosistema desde el SBOM (Lógica del Notebook)
        sbom_path = os.path.join(RESULTS_DIR, f"{repo_name}_sbom.json")
        ecosistema = obtener_ecosistema_desde_sbom(sbom_path)

        resumen.append({
            "repository": repo_name,
            "ecosystem": ecosistema,  # <--- Agregamos el ecosistema aquí
            "sca_metrics": metrics_grype,
            "sast_alerts": metrics_codeql,
            "timestamp": datetime.now().isoformat()
        })

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(resumen, f, indent=4)

    print(f"Dataset estructurado creado en: {OUTPUT_FILE}")

if __name__ == "__main__":
    generar_dataset_final()