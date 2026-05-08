import json
import os
import glob
from datetime import datetime

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RESULTS_DIR = os.path.join(BASE_DIR, "results")
OUTPUT_FILE = os.path.join(RESULTS_DIR, "summary_prefect.json")


def extraer_metricas_grype(ruta_json):
    """Extrae el conteo de vulnerabilidades por severidad desde la salida JSON de Grype.

    :param ruta_json: Ruta al archivo JSON generado por Grype.
    :type ruta_json: str
    :return: Diccionario con conteo por severidad (Critical, High, Medium, Low).
    :rtype: dict
    :raises: Ninguna; las excepciones se capturan internamente y se devuelve un conteo a cero en caso de error.
    """
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
    """Cuenta el total de alertas reportadas en un archivo SARIF de CodeQL.

    :param ruta_sarif: Ruta al archivo SARIF generado por CodeQL.
    :type ruta_sarif: str
    :return: Número total de resultados/alertas en el SARIF.
    :rtype: int
    :raises: Ninguna; en caso de error retorna 0.
    """
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


def obtener_ecosistemas_desde_sbom(ruta_sbom):
    """Analiza un SBOM (Syft JSON) y devuelve el ecosistema principal y el desglose de tipos.

    :param ruta_sbom: Ruta al SBOM en formato JSON generado por Syft.
    :type ruta_sbom: str
    :return: Diccionario con claves 'primary' (ecosistema predominante) y 'breakdown' (conteo por tipo).
    :rtype: dict
    :raises: Ninguna; en caso de error retorna valores por defecto indicando desconocido.
    """
    if not os.path.exists(ruta_sbom) or os.path.getsize(ruta_sbom) == 0:
        return {"primary": "Desconocido", "breakdown": {}}

    try:
        with open(ruta_sbom, 'r', encoding='utf-8') as f:
            data = json.load(f)

        artifacts = data.get('artifacts', [])
        if not artifacts:
            return {"primary": "Desconocido", "breakdown": {}}

        conteo_tipos = {}
        for artifact in artifacts:
            tipo = artifact.get('type', 'Desconocido')
            conteo_tipos[tipo] = conteo_tipos.get(tipo, 0) + 1

        ecosistema_principal = max(conteo_tipos, key=conteo_tipos.get)

        return {
            "primary": ecosistema_principal,
            "breakdown": conteo_tipos
        }

    except Exception:
        return {"primary": "Desconocido", "breakdown": {}}


def generar_dataset_final():
    """Consolida resultados de Grype, CodeQL y SBOM en un JSON resumen en results/.

    :return: None
    :rtype: None
    :raises: Ninguna; los errores se imprimen y la función retorna sin excepción.
    """
    print("\nGenerando dataset estructurado consolidado...")
    resumen = []

    archivos_vulns = glob.glob(os.path.join(RESULTS_DIR, "*_vulns.json"))

    if not archivos_vulns:
        print(f" [!] No se encontraron archivos en {RESULTS_DIR}.")
        return

    for archivo in archivos_vulns:
        repo_name = os.path.basename(archivo).replace("_vulns.json", "")

        metrics_grype = extraer_metricas_grype(archivo)

        total_sast_alerts = 0
        archivos_sarif = glob.glob(os.path.join(RESULTS_DIR, f"{repo_name}_*_codeql.sarif"))

        for sarif_path in archivos_sarif:
            total_sast_alerts += extraer_metricas_codeql(sarif_path)

        sbom_path = os.path.join(RESULTS_DIR, f"{repo_name}_sbom.json")
        ecosistema = obtener_ecosistemas_desde_sbom(sbom_path)

        resumen.append({
            "repository": repo_name,
            "ecosystem": ecosistema,
            "sca_metrics": metrics_grype,
            "sast_alerts": total_sast_alerts,
            "timestamp": datetime.now().isoformat()
        })

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(resumen, f, indent=4)

    print(f"Dataset estructurado creado en: {OUTPUT_FILE}")


if __name__ == "__main__":
    generar_dataset_final()
