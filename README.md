# SBOM Analyzer

Herramienta para detectar, analizar y visualizar vulnerabilidades en repositorios
de software open source. Desarrollada para analizar la organizacion **PrefectHQ**.

## Arquitectura

El sistema se divide en tres componentes con responsabilidades bien definidas:

    miner/        -> Extraccion de vulnerabilidades (Syft + Grype + CodeQL)
    notebooks/    -> Analisis exploratorio y cuantitativo
    visualizer/   -> Dashboard interactivo de resultados

### Decisiones de diseno

**1. Pipeline secuencial en el Miner**
El miner ejecuta Syft primero para generar el SBOM, luego Grype para analizar
dependencias y finalmente CodeQL para analisis estatico. Este orden es intencional:
CodeQL usa el SBOM para detectar los lenguajes presentes en el repositorio.

**2. JSON como formato de intercambio**
Los tres componentes se comunican mediante archivos JSON en results/.
Esto permite desacoplar los componentes: el miner produce datos,
el analyzer los consume y el visualizer los presenta.

**3. Risk Score ponderado**
El analyzer calcula un puntaje de riesgo por repositorio usando pesos matematicos:
- Critical: 10 puntos
- High: 5 puntos
- Medium: 2 puntos
- Low: 1 punto
- SAST (CodeQL): 3 puntos

**4. Dev Containers para reproducibilidad**
Todo el entorno esta definido en Docker, incluyendo Syft, Grype, CodeQL,
Node.js y Python. Cualquier persona puede reproducir el analisis sin
configuraciones adicionales.

## Prerrequisitos

- Docker
- VSCode
- Extension Dev Containers de VSCode

## Como ejecutar

### 1. Clonar el repositorio

git clone https://github.com/Fran416/SBOM-Analyzer.git
cd SBOM-Analyzer

### 2. Abrir en Dev Container

code .

Presiona Ctrl+Shift+P y selecciona:
Dev Containers: Rebuild and Reopen in Container

### 3. Configurar el Kernel

Al abrir cualquier notebook .ipynb selecciona:
- Select Another Environment
- Python Environments
- Python 3.11.15

### 4. Ejecutar los notebooks en orden

Notebook                              | Descripcion
01_ejecutar_miner.ipynb               | Ejecuta el pipeline completo (Syft + Grype + CodeQL)
02_analisis_dependencias.ipynb        | Analisis de dependencias y vulnerabilidades
03_ejecutar_dataset_analyzer.ipynb    | Genera dataset consolidado y risk scores

NOTA: El notebook 01 puede tardar hasta 2 horas por el analisis de CodeQL.

### 5. Ejecutar el Visualizer

python3 -m http.server 8080

Abre en el navegador: http://localhost:8080/visualizer/

## Componentes

### Miner (miner/)

- miner.py -> Pipeline principal: clona repos, ejecuta Syft, Grype y CodeQL
- dataset.py -> Consolida resultados en summary_prefect.json
- analizer.py -> Calcula risk scores y genera detailed_analysis.json

### Analyzer (notebooks/)

- Analisis cuantitativo de dependencias por ecosistema
- Distribucion de vulnerabilidades por severidad
- Identificacion de repositorios mas riesgosos

### Visualizer (visualizer/)

- Dashboard interactivo con Chart.js
- Distribucion de severidades
- Risk score por repositorio
- Comparacion de vulnerabilidades entre repositorios

## Resultados generados

Archivo                | Descripcion
*_sbom.json            | SBOM generado por Syft
*_vulns.json           | Vulnerabilidades detectadas por Grype
*_codeql.sarif         | Alertas de analisis estatico de CodeQL
summary_prefect.json   | Dataset consolidado
detailed_analysis.json | Analisis con risk scores

## Estudiantes

- Benjamin Garces -> BenjaG123
- Francisco Lizama -> Fran416
- Nicolas Sandoval -> NicolasSandovalll
