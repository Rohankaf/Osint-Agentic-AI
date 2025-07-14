## OSINT Agentic AI Pipeline

A powerful OSINT automation framework using Claude (Anthropic), FastAPI, and CLI tools. It supports multi-loop planning, tool reflection, memory tracking, and modular execution of recon tools.


# Features

- LLM-driven tool planning with Claude
- Multi-loop execution with self-reflection
- Short-term memory to track goals, plans, results
- FastAPI backend to run supported tools:
  - `theHarvester`
  - `subfinder`
  - `whois`
  - `dnsx`
  - `shodan`

# Architecture

User Prompt → Claude Preprocessing → Tool Plan → Tool Execution (MCP) → Claude Reflection → Repeat if needed → Final Summary

# Tools Used

| Tool         | Purpose                     |
|--------------|-----------------------------|
| Claude       | LLM for reasoning + planning|
| FastAPI      | MCP (Multi-tool control point) |
| Subfinder    | Subdomain enumeration       |
| theHarvester | Email + subdomain OSINT     |
| dnsx         | DNS probing (resolves IPs)  |
| Shodan       | IP-based device fingerprinting |
| whois        | WHOIS data extraction       |

# Project Structure
.
├── llm_client.py # LLM loop: planning, reflection, control
├── mcp_server.py # FastAPI backend that runs OSINT tools
├── tools_used.md # Optional: docs for tool functions
├── logs/ # Transcript and results from each run
└── .env # Claude API key (not committed)

# Setup

```bash
git clone https://github.com/codex500/Osint-Agentic-AI
cd Osint-Agentic-AI
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

# Create a .env file in the root directory:

CLAUDE_API_KEY=sk-your-api-key-here

# Start the FastAPI server:

uvicorn mcp_server:app --reload

# How to Run

python3 llm_client.py

# Enter a prompt like:

Run full recon on tesla.com


 
