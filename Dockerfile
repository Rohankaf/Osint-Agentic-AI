
FROM golang:1.24-bullseye AS go-builder

WORKDIR /go/src/tools
ENV CGO_ENABLED=0
ENV GO111MODULE=on

RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.8.0 && \
    GO111MODULE=on go install github.com/projectdiscovery/dnsx/cmd/dnsx@v1.1.3


FROM python:3.12-slim AS osint-final

ENV DEBIAN_FRONTEND=noninteractive

# System packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl wget git whois dnsutils jq ca-certificates build-essential && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy Go tools from builder
COPY --from=go-builder /go/bin/subfinder /usr/local/bin/subfinder
COPY --from=go-builder /go/bin/dnsx /usr/local/bin/dnsx

# Clone and install theHarvester
RUN git clone https://github.com/laramies/theHarvester.git /opt/theHarvester && \
    pip install --no-cache-dir /opt/theHarvester

# Copy code
WORKDIR /app
COPY . /app

# Install Python deps
RUN pip install --no-cache-dir -r requirements.txt

# Expose FastAPI port
EXPOSE 8000

# Start FastAPI
CMD ["uvicorn", "mcp_server:app", "--host=0.0.0.0", "--port=8000"]
