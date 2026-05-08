import json
import os
from datetime import datetime

# Configuramos las rutas
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RESULTS_DIR = os.path.join(BASE_DIR, "results")
INPUT_FILE = os.path.join(RESULTS_DIR, "summary_prefect.json")
OUTPUT_FILE = os.path.join(RESULTS_DIR, "detailed_analysis.json")

# Pesos matemáticos base (El Daño)
PESOS = {"Critical": 10, "High": 5, "Medium": 2, "Low": 1, "SAST": 3}

# Multiplicadores según tecnología dominante (El Terreno)
MULTIPLICADORES_ECOSISTEMA = {
    "npm": 1.2,
    "javascript": 1.2,
    "python": 1.1,
    "go-module": 0.9,
    "go": 0.9,
    "github-actions": 1.0,
}


def evaluar_arquitectura(ecosistema_principal, desglose):
    """Calcula multiplicador de riesgo y contexto de amenaza según el desglose de dependencias.

    :param ecosistema_principal: Nombre del ecosistema predominante desde el SBOM.
    :type ecosistema_principal: str
    :param desglose: Diccionario con conteo por tipo/artefacto.
    :type desglose: dict
    :return: Diccionario con 'multiplier', 'threat_landscape' y 'breakdown' (porcentajes).
    :rtype: dict
    """
    desglose_norm = {str(k).lower(): v for k, v in desglose.items()}
    total_deps = sum(desglose_norm.values())

    if total_deps == 0:
        return {"multiplier": 1.0, "threat_landscape": "Sin dependencias detectadas.", "breakdown": {}}

    porcentajes = {k: (v / total_deps) * 100 for k, v in desglose_norm.items()}

    multiplicador = 1.0

    tiene_js = "npm" in porcentajes or "javascript" in porcentajes or "yarn" in porcentajes
    tiene_python = "python" in porcentajes

    if tiene_js and tiene_python:
        multiplicador = 1.3
        contexto = "Proyecto Full-Stack detectado. Alto riesgo arquitectónico: Vulnerabilidades en el frontend (JS) podrían ser usadas para escalar privilegios hacia el backend (Python)."

    elif porcentajes.get("python", 0) > 85:
        multiplicador = 1.1
        contexto = "Monolito o Microservicio Python. El riesgo se concentra en dependencias de PyPI y potencial ejecución remota de código (RCE) en el servidor."

    elif porcentajes.get("npm", 0) > 85 or porcentajes.get("javascript", 0) > 85:
        multiplicador = 1.2
        contexto = "Aplicación fuertemente basada en JavaScript/Node. Alta exposición a ataques de Supply Chain, Prototype Pollution o XSS si está expuesto a web."

    else:
        eco_limpio = str(ecosistema_principal).lower()
        multiplicador = MULTIPLICADORES_ECOSISTEMA.get(eco_limpio, 1.0)
        contexto = f"Ecosistema principal: {ecosistema_principal}. Análisis estándar de superficie de ataque."

    return {
        "multiplier": multiplicador,
        "threat_landscape": contexto,
        "breakdown": porcentajes
    }


def calcular_nivel(score):
    """Devuelve una etiqueta de nivel de riesgo para un puntaje numérico.

    :param score: Puntaje de riesgo calculado.
    :type score: float
    :return: Cadena con el nivel de riesgo: SEGURO, BAJO, MEDIO, ALTO, CRITICO.
    :rtype: str
    """
    if score == 0:
        return "SEGURO"
    elif score <= 15:
        return "BAJO"
    elif score <= 40:
        return "MEDIO"
    elif score <= 90:
        return "ALTO"
    return "CRITICO"


def realizar_analisis_contextual():
    """Lee el resumen generado por el miner y produce un análisis detallado en JSON.

    El resultado se guarda en results/detailed_analysis.json e incluye metadatos,
    análisis por repositorio y puntajes normalizados.
    :return: None
    :rtype: None
    """
    print(f"\n[Analizador] Leyendo dataset de: {INPUT_FILE}")

    if not os.path.exists(INPUT_FILE) or os.path.getsize(INPUT_FILE) == 0:
        print(" [!] Error: El archivo summary_prefect.json no existe o está vacío.")
        return

    try:
        with open(INPUT_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except json.JSONDecodeError:
        print(" [!] Error: summary_prefect.json está corrupto o mal formado.")
        return

    analisis_repositorios = []
    total_ecosystem_score = 0

    for repo in data:
        sca = repo.get("sca_metrics", {})
        sast = repo.get("sast_alerts", 0)
        repo_name = repo.get("repository", "Desconocido")

        ecosystem_data = repo.get("ecosystem", {})
        eco_principal = ecosystem_data.get("primary", "Desconocido")
        eco_desglose = ecosystem_data.get("breakdown", {})

        score_base = (
            (sca.get("Critical", 0) * PESOS["Critical"]) +
            (sca.get("High", 0) * PESOS["High"]) +
            (sca.get("Medium", 0) * PESOS["Medium"]) +
            (sca.get("Low", 0) * PESOS["Low"]) +
            (sast * PESOS["SAST"]) 
        )

        analisis_arq = evaluar_arquitectura(eco_principal, eco_desglose)

        score_final = score_base * analisis_arq["multiplier"]
        total_ecosystem_score += score_final

        analisis_repositorios.append({
            "repository": repo_name,
            "architecture_context": {
                "primary_ecosystem": eco_principal,
                "stack_breakdown": analisis_arq["breakdown"],
                "threat_landscape_note": analisis_arq["threat_landscape"]
            },
            "mathematical_analysis": {
                "base_score": score_base,
                "contextual_multiplier": analisis_arq["multiplier"],
                "risk_score": round(score_final, 2),
                "risk_level": calcular_nivel(score_final)
            },
            "raw_metrics": {"sca": sca, "sast": sast}
        })

    for repo in analisis_repositorios:
        score_repo = repo["mathematical_analysis"]["risk_score"]
        porcentaje = (score_repo / total_ecosystem_score * 100) if total_ecosystem_score > 0 else 0
        repo["mathematical_analysis"]["ecosystem_risk_share_percentage"] = round(porcentaje, 2)

    analisis_repositorios.sort(key=lambda x: x["mathematical_analysis"]["risk_score"], reverse=True)

    analisis_final = {
        "metadata": {
            "analysis_timestamp": datetime.now().isoformat(),
            "repositories_analyzed": len(data),
            "total_ecosystem_risk_score": round(total_ecosystem_score, 2)
        },
        "detailed_repository_analysis": analisis_repositorios
    }

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(analisis_final, f, indent=4)

    print(f" [✓] Análisis RBVM (Risk-Based Vulnerability Management) completado.")
    print(f" [✓] Resultados detallados en: {OUTPUT_FILE}\n")


if __name__ == "__main__":
    realizar_analisis_contextual()
