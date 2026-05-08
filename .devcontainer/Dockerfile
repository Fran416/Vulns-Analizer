FROM mcr.microsoft.com/vscode/devcontainers/python:3.11

# --- Instalación de Syft y Grype  ---
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin && \
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# --- Instalación de Node.js y npm  ---
RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash - && \
    apt-get install -y nodejs

# --- Instalación de CodeQL CLI ---
RUN wget https://github.com/github/codeql-action/releases/latest/download/codeql-bundle-linux64.tar.gz && \
    tar -xvzf codeql-bundle-linux64.tar.gz && \
    mv codeql /usr/local/codeql-home && \
    rm codeql-bundle-linux64.tar.gz

# --- Configuración del PATH ---
ENV PATH="/usr/local/codeql-home:$PATH"

# --- Instalación de dependencias de Python ---
RUN pip install requests pandas matplotlib seaborn tqdm jupyter

# Limpieza de caché de apt para reducir el tamaño de la imagen
RUN apt-get clean && rm -rf /var/lib/apt/lists/*