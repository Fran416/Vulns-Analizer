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

// Colores consistentes para los lenguajes/ecosistemas
const COLORES_ECO = {
    "python": "#58a6ff",
    "npm": "#3fb950",
    "javascript": "#3fb950",
    "go-module": "#e3b341",
    "go": "#e3b341",
    "github-action": "#f85149",
    "github-action-workflow": "#bc8cff",
    "Desconocido": "#8b949e"
};

async function cargarDatos() {
    try {
        // Agregamos un timestamp a la URL para evitar el caché agresivo del navegador
        const response = await fetch(`${DATA_URL}?t=${new Date().getTime()}`);
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

    document.getElementById("total-repos").textContent = metadata.repositories_analyzed;
    document.getElementById("total-score").textContent = metadata.total_ecosystem_risk_score;

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
            plugins: { legend: { labels: { color: "#c9d1d9" } } }
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
            plugins: { legend: { display: false } },
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
            plugins: { legend: { labels: { color: "#c9d1d9" } } }
        }
    });
}

function graficarEcosistema(data) {
    const repos = data.detailed_repository_analysis;
    const ecosistemas = {};
    
    repos.forEach(repo => {
        // Corrección aplicada: architecture_context
        const eco = repo.architecture_context?.primary_ecosystem || "Desconocido";
        ecosistemas[eco] = (ecosistemas[eco] || 0) + 1;
    });

    new Chart(document.getElementById("chartEcosistema"), {
        type: "pie",
        data: {
            labels: Object.keys(ecosistemas),
            datasets: [{
                data: Object.values(ecosistemas),
                backgroundColor: Object.keys(ecosistemas).map(eco => COLORES_ECO[eco] || COLORES_ECO["Desconocido"])
            }]
        },
        options: {
            plugins: { legend: { labels: { color: "#c9d1d9" } } }
        }
    });
}

function graficarDistribucionEcosistemas(data) {
    const repos = data.detailed_repository_analysis.slice(0, 10);
    const labels = repos.map(r => r.repository);

    const uniqueEcosystems = new Set();
    repos.forEach(repo => {
        Object.keys(repo.architecture_context?.stack_breakdown || {}).forEach(eco => {
            uniqueEcosystems.add(eco);
        });
    });

    const datasets = Array.from(uniqueEcosystems).map(eco => {
        return {
            label: eco,
            data: repos.map(r => r.architecture_context?.stack_breakdown?.[eco] || 0),
            backgroundColor: COLORES_ECO[eco] || COLORES_ECO["Desconocido"]
        };
    });

    new Chart(document.getElementById("chartDistribucionEco"), {
        type: "bar",
        data: { labels, datasets },
        options: {
            scales: {
                x: { stacked: true, ticks: { color: "#c9d1d9" } },
                y: { 
                    stacked: true, 
                    max: 100,
                    ticks: { 
                        color: "#c9d1d9",
                        callback: function(value) { return value + "%"; }
                    } 
                }
            },
            plugins: { legend: { labels: { color: "#c9d1d9" } } }
        }
    });
}

function graficarRiesgoPorEcosistema(data) {
    const repos = data.detailed_repository_analysis;
    const ecosistemas = {};

    repos.forEach(repo => {
        const eco = repo.architecture_context?.primary_ecosystem || "Desconocido";
        
        if (!ecosistemas[eco]) {
            ecosistemas[eco] = { Critical: 0, High: 0, Medium: 0, Low: 0 };
        }

        const sca = repo.raw_metrics.sca;
        ecosistemas[eco].Critical += (sca.Critical || 0);
        ecosistemas[eco].High += (sca.High || 0);
        ecosistemas[eco].Medium += (sca.Medium || 0);
        ecosistemas[eco].Low += (sca.Low || 0);
    });

    const labels = Object.keys(ecosistemas);
    
    const datasets = [
        { label: "Critical", data: labels.map(l => ecosistemas[l].Critical), backgroundColor: COLORES_SEVERIDAD.Critical },
        { label: "High", data: labels.map(l => ecosistemas[l].High), backgroundColor: COLORES_SEVERIDAD.High },
        { label: "Medium", data: labels.map(l => ecosistemas[l].Medium), backgroundColor: COLORES_SEVERIDAD.Medium },
        { label: "Low", data: labels.map(l => ecosistemas[l].Low), backgroundColor: COLORES_SEVERIDAD.Low }
    ];

    new Chart(document.getElementById("chartRiesgoPorEcosistema"), {
        type: "bar",
        data: { labels, datasets },
        options: {
            indexAxis: "y", 
            scales: {
                x: { stacked: true, ticks: { color: "#c9d1d9" } },
                y: { stacked: true, ticks: { color: "#c9d1d9" } }
            },
            plugins: { legend: { labels: { color: "#c9d1d9" } } }
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
    graficarDistribucionEcosistemas(data);
    graficarRiesgoPorEcosistema(data);
}

main();