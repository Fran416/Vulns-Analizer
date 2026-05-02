import json
import os
import glob
from datetime import datetime

# Configuramos la ruta hacia atrás para encontrar la carpeta results
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RESULTS_DIR = os.path.join(BASE_DIR, "results")
OUTPUT_FILE = os.path.join(RESULTS_DIR, "summary_prefect.json")


def extraer_metricas_grype(ruta_json):
    """Extrae conteo de vulnerabilidades por severidad desde Grype."""
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
    try:
        with open(ruta_sarif, 'r', encoding='utf-8') as f:
            data = json.load(f)

        total = 0
        for run in data.get('runs', []):
            total += len(run.get('results', []))
        return total
    except Exception:
        return 0


def generar_dataset_final():
    """Genera el summary.json unificado para el Visualizer y Analyzer."""
    print("\nGenerando dataset estructurado consolidado...")
    resumen = []

    # Buscamos todos los archivos de vulnerabilidades generados
    archivos_vulns = glob.glob(os.path.join(RESULTS_DIR, "*_vulns.json"))

    if not archivos_vulns:
        print(f" [!] No se encontraron archivos en {RESULTS_DIR}. Revisa la ruta.")
        return

    for archivo in archivos_vulns:
        # Extraemos el nombre del repo del nombre del archivo
        repo_name = os.path.basename(archivo).replace("_vulns.json", "")

        # 1. Datos de Grype (SCA)
        metrics_grype = extraer_metricas_grype(archivo)

        # 2. Datos de CodeQL (SAST)
        sarif_path = os.path.join(RESULTS_DIR, f"{repo_name}_codeql.sarif")
        metrics_codeql = extraer_metricas_codeql(sarif_path)

        resumen.append({
            "repository": repo_name,
            "sca_metrics": metrics_grype,
            "sast_alerts": metrics_codeql,
            "timestamp": datetime.now().isoformat()
        })

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(resumen, f, indent=4)

    print(f"Dataset estructurado creado en: {OUTPUT_FILE}")


if __name__ == "__main__":
    generar_dataset_final()