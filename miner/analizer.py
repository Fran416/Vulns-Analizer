import json
import os
from datetime import datetime

# Configuramos las rutas
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RESULTS_DIR = os.path.join(BASE_DIR, "results")
INPUT_FILE = os.path.join(RESULTS_DIR, "summary_prefect.json")
OUTPUT_FILE = os.path.join(RESULTS_DIR, "detailed_analysis.json")

# Pesos matemáticos
PESOS = {"Critical": 10, "High": 5, "Medium": 2, "Low": 1, "SAST": 3}


def generar_contexto_dinamico(ecosistema):
    """Genera inteligencia de amenazas evaluando el ecosistema real del SBOM."""
    ecosistema = str(ecosistema).lower().strip()
    
    if ecosistema == "python":
        return {
            "primary_language": "Python",
            "known_threat_landscape": "Vulnerabilidades críticas concentradas en el ecosistema pip/PyPI. Riesgos de Supply Chain y ejecución arbitraria por dependencias."
        }
    elif ecosistema == "npm" or ecosistema == "javascript":
        return {
            "primary_language": "JavaScript / npm",
            "known_threat_landscape": "Alta densidad de alertas SCA debido a dependencias transitivas. Riesgos comunes: Prototype Pollution y XSS."
        }
    elif ecosistema == "go-module":
        return {
            "primary_language": "Go",
            "known_threat_landscape": "Ecosistema compilado estáticamente. Prestar atención a fallos de red, concurrencia o módulos indirectos."
        }
    elif "github-action" in ecosistema:
        return {
            "primary_language": "CI/CD (GitHub Actions)",
            "known_threat_landscape": "Riesgo operativo en la cadena de construcción (Pipeline). Posibilidad de robo de secretos o tokens."
        }
    else:
        # Si el SBOM no supo qué era o es otro lenguaje
        nombre_limpio = ecosistema.capitalize() if ecosistema not in ["", "none", "desconocido"] else "Desconocido"
        return {
            "primary_language": nombre_limpio,
            "known_threat_landscape": "Analizar la matriz de riesgo genérica basada en métricas SCA/SAST."
        }


def calcular_nivel(score):
    """Asigna una etiqueta visual según el puntaje de riesgo."""
    if score == 0: return "SEGURO"
    elif score <= 10: return "BAJO"
    elif score <= 30: return "MEDIO"
    elif score <= 80: return "ALTO"
    return "CRITICO"


def realizar_analisis_contextual():
    print(f"\n[Analizador] Leyendo dataset de: {INPUT_FILE}")
    
    # 1. Protección contra archivo vacío o inexistente
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

    # 2. Iterar sobre los datos y calcular
    for repo in data:
        sca = repo.get("sca_metrics", {})
        sast = repo.get("sast_alerts", 0)
        repo_name = repo.get("repository", "Desconocido")
        
        # Leemos el ecosistema que 'dataset.py' incrustó desde el SBOM
        repo_ecosistema = repo.get("ecosystem", "Desconocido")

        # Fórmula matemática
        score = (
            (sca.get("Critical", 0) * PESOS["Critical"]) +
            (sca.get("High", 0) * PESOS["High"]) +
            (sca.get("Medium", 0) * PESOS["Medium"]) +
            (sca.get("Low", 0) * PESOS["Low"]) +
            (sast * PESOS["SAST"])
        )
        
        total_ecosystem_score += score
        
        # Generar el contexto dinámicamente
        contexto = generar_contexto_dinamico(repo_ecosistema)

        analisis_repositorios.append({
            "repository": repo_name,
            "ecosystem_context": contexto,
            "mathematical_analysis": {
                "risk_score": score,
                "risk_level": calcular_nivel(score)
            },
            "raw_metrics": {"sca": sca, "sast": sast}
        })

    # 3. Calcular porcentajes de impacto y ordenar
    for repo in analisis_repositorios:
        score_repo = repo["mathematical_analysis"]["risk_score"]
        porcentaje = (score_repo / total_ecosystem_score * 100) if total_ecosystem_score > 0 else 0
        repo["mathematical_analysis"]["ecosystem_risk_share_percentage"] = round(porcentaje, 2)

    # Ordenar del más peligroso al más seguro
    analisis_repositorios.sort(key=lambda x: x["mathematical_analysis"]["risk_score"], reverse=True)

    # 4. Guardar archivo final
    analisis_final = {
        "metadata": {
            "analysis_timestamp": datetime.now().isoformat(),
            "repositories_analyzed": len(data),
            "total_ecosystem_risk_score": total_ecosystem_score
        },
        "detailed_repository_analysis": analisis_repositorios
    }

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(analisis_final, f, indent=4)

    print(f" [✓] Análisis contextual y matemático completado.")
    print(f" [✓] Resultados detallados en: {OUTPUT_FILE}\n")


if __name__ == "__main__":
    realizar_analisis_contextual()