# SBOM Analyzer
Proyecto centrado en analizar repositorios activos de una organizacion, PerfectHQ para este caso.

## Como ejecutar

### Prerrequisitos

- Docker
- VSCode
- Extension Dev Containers de "Docker" en VSCode

### Clonar

- Para ejecutar el proyecto debes clonar el repositorio:
`
git clone https://github.com/Fran416/SBOM-Analyzer.git
cd SBOM-Analyzer 
`

- Abrir el repositorio en VSCode:
`code .`

### Reconstruir en un contenedor:
- En VSCode presiona `ctrl + shitft + p` (para Mac: `Cmd + shitft + p`)

- Escribe y selecciona: `Dev Containers: Rebuild and Reopen in Container` abrir como Dev

- Container

Con esto VSCode ejecutara el proyecto en un contenedor Docker donde tendras todas las librerias y dependencias necesarias para este proyecto

### Configurar el Kernel

- Abrir cualquier Notebook (archivos terminados en `.ipynb`)

-Al tratar de ejecutra por primera vez selecciona:
`Select Another Enviroment`
`Python Enviroments`
`Python 3.11.15`

### Ejecutar

Para replicar el projecto, utiliza los notebooks presentes en la carpeta `notebooks`, siendo el `00_ejecutar_proyecto.ipynb` la base para crear lo antes dicho en el README.md, por ende la ejecucion de codigo comienza desde el `01_ejecutar_miner.ipynb`.


## Estudiantes 

- Benjamín Garcés -> BenjaG123
- Francisco Lizama -> Fran416
- Nicolás Sandoval -> NicolasSandovalll
