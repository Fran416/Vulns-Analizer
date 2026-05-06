// Ruta al archivo de análisis generado por analizer.py
const DATA_URL = "../results/detailed_analysis.json";

// Colores por severidad
const COLORES_SEVERIDAD = {
    Critical: "#f85149",
    High:     "#e3b341",
    Medium:   "#58a6ff",
    Low:      "#3fb950",
    Unknown:  "#8b949e"
};

async function cargarDatos() {
    try {
        const response = await fetch(DATA_URL);
        const data = await response.json();
        return data;
    } catch (error) {
        console.error("Error al cargar datos:", error);
        return null;
    }
}

function actualizarTarjetas(data) {
    const repos = data.detailed_repository_analysis;
    const metadata = data.metadata;

    // Total repositorios
    document.getElementById("total-repos").textContent = 
        metadata.repositories_analyzed;

    // Risk score total
    document.getElementById("total-score").textContent = 
        metadata.total_ecosystem_risk_score;

    // Total vulnerabilidades y críticas
    let totalVulns = 0;
    let totalCritical = 0;

    repos.forEach(repo => {
        const sca = repo.raw_metrics.sca;
        totalVulns += (sca.Critical || 0) + (sca.High || 0) + 
                      (sca.Medium || 0) + (sca.Low || 0);
        totalCritical += sca.Critical || 0;
    });

    document.getElementById("total-vulns").textContent = totalVulns;
    document.getElementById("total-critical").textContent = totalCritical;
}

function graficarSeveridades(data) {
    const repos = data.detailed_repository_analysis;

    // Sumar severidades de todos los repos
    const totales = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    repos.forEach(repo => {
        const sca = repo.raw_metrics.sca;
        totales.Critical += sca.Critical || 0;
        totales.High     += sca.High || 0;
        totales.Medium   += sca.Medium || 0;
        totales.Low      += sca.Low || 0;
    });

    new Chart(document.getElementById("chartSeveridad"), {
        type: "doughnut",
        data: {
            labels: Object.keys(totales),
            datasets: [{
                data: Object.values(totales),
                backgroundColor: Object.keys(totales).map(k => COLORES_SEVERIDAD[k])
            }]
        },
        options: {
            plugins: {
                legend: { labels: { color: "#c9d1d9" } }
            }
        }
    });
}

function graficarRiskScore(data) {
    const repos = data.detailed_repository_analysis.slice(0, 10);
    const labels = repos.map(r => r.repository);
    const scores = repos.map(r => r.mathematical_analysis.risk_score);

    new Chart(document.getElementById("chartRiskScore"), {
        type: "bar",
        data: {
            labels,
            datasets: [{
                label: "Risk Score",
                data: scores,
                backgroundColor: "#58a6ff"
            }]
        },
        options: {
            indexAxis: "y",
            plugins: {
                legend: { display: false }
            },
            scales: {
                x: { ticks: { color: "#c9d1d9" } },
                y: { ticks: { color: "#c9d1d9" } }
            }
        }
    });
}

function graficarVulnsPorRepo(data) {
    const repos = data.detailed_repository_analysis.slice(0, 10);
    const labels = repos.map(r => r.repository);

    const critical = repos.map(r => r.raw_metrics.sca.Critical || 0);
    const high     = repos.map(r => r.raw_metrics.sca.High || 0);
    const medium   = repos.map(r => r.raw_metrics.sca.Medium || 0);
    const low      = repos.map(r => r.raw_metrics.sca.Low || 0);

    new Chart(document.getElementById("chartVulnsPorRepo"), {
        type: "bar",
        data: {
            labels,
            datasets: [
                { label: "Critical", data: critical, backgroundColor: COLORES_SEVERIDAD.Critical },
                { label: "High",     data: high,     backgroundColor: COLORES_SEVERIDAD.High },
                { label: "Medium",   data: medium,   backgroundColor: COLORES_SEVERIDAD.Medium },
                { label: "Low",      data: low,      backgroundColor: COLORES_SEVERIDAD.Low }
            ]
        },
        options: {
            scales: {
                x: { stacked: true, ticks: { color: "#c9d1d9" } },
                y: { stacked: true, ticks: { color: "#c9d1d9" } }
            },
            plugins: {
                legend: { labels: { color: "#c9d1d9" } }
            }
        }
    });
}

function graficarEcosistema(data) {
    const repos = data.detailed_repository_analysis;

    // Contar ecosistemas
    const ecosistemas = {};
    repos.forEach(repo => {
        const eco = repo.ecosystem_context.primary_language || "Desconocido";
        ecosistemas[eco] = (ecosistemas[eco] || 0) + 1;
    });

    new Chart(document.getElementById("chartEcosistema"), {
        type: "pie",
        data: {
            labels: Object.keys(ecosistemas),
            datasets: [{
                data: Object.values(ecosistemas),
                backgroundColor: [
                    "#58a6ff", "#3fb950", "#e3b341", 
                    "#f85149", "#bc8cff", "#8b949e"
                ]
            }]
        },
        options: {
            plugins: {
                legend: { labels: { color: "#c9d1d9" } }
            }
        }
    });
}

// Función principal
async function main() {
    const data = await cargarDatos();
    if (!data) return;

    actualizarTarjetas(data);
    graficarSeveridades(data);
    graficarRiskScore(data);
    graficarVulnsPorRepo(data);
    graficarEcosistema(data);
}

main();
