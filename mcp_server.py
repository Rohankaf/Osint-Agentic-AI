import os
import subprocess
import shodan
import whois
import datetime
import json
from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.responses import JSONResponse
from dotenv import load_dotenv


load_dotenv()


SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
MAX_SUBFINDER_RESULTS = int(os.getenv("MAX_SUBFINDER_RESULTS", 20))
MAX_HARVESTER_EMAILS = int(os.getenv("MAX_HARVESTER_EMAILS", 10))
MAX_HARVESTER_HOSTS = int(os.getenv("MAX_HARVESTER_HOSTS", 10))
MAX_RESULTS = 5                                                                                                             
MAX_LINE_LENGTH = 1000


app = FastAPI()


class ToolRequest(BaseModel):
    tool: str
    inputs: dict


@app.post("/run_tool")
async def run_tool(req: ToolRequest):
    tool = req.tool.lower()
    inputs = req.inputs

    try:
        if tool == "theharvester":
            return run_theharvester(inputs)
        elif tool == "subfinder":
            return run_subfinder(inputs)
        elif tool == "shodan":
            return run_shodan(inputs)
        elif tool == "whois":
            return run_whois(inputs)
        elif tool == "dnsx":
            return run_dnsx(inputs)
        else:
            return JSONResponse(status_code=400, content={"error": f"Unknown tool: {tool}"})
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


def run_theharvester(inputs):
    domain = inputs.get("domain", "")
    if not domain:
        return JSONResponse(status_code=400, content={"error": "Domain is required for theHarvester."})

    output_file = f"{domain}_results.json"
    sources = "crtsh,hackertarget,otx"
    cmd = f"theHarvester -d {domain} -b {sources} -l 10 -f {output_file}"

    try:
        subprocess.run(cmd, shell=True, check=True, timeout=60)

        if not os.path.exists(output_file):
            return JSONResponse(status_code=500, content={"error": "Output file not found."})

        with open(output_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        emails = data.get("emails", [])[:MAX_HARVESTER_EMAILS]
        hosts = data.get("hosts", [])[:MAX_HARVESTER_HOSTS]

        return {
            "tool": "theHarvester",
            "domain": domain,
            "emails": emails,
            "hosts": hosts
        }

    except subprocess.TimeoutExpired:
        return JSONResponse(status_code=500, content={"error": "theHarvester timed out."})
    except subprocess.CalledProcessError as e:
        return JSONResponse(status_code=500, content={"error": f"theHarvester failed: {str(e)}"})
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": f"Error reading output: {str(e)}"})

def run_subfinder(inputs):
    domain = inputs.get("domain", "")
    if not domain:
        return JSONResponse(status_code=400, content={"error": "Domain is required for Subfinder."})

    output_file = f"subfinder_{domain}.json"
    subfinder_path = "/Users/rohahahan/go/bin/subfinder" 
    cmd = f"{subfinder_path} -d {domain} -o {output_file} -silent -json"

    try:
        subprocess.run(cmd, shell=True, check=True, timeout=60)

        with open(output_file, "r", encoding="utf-8") as f:
            subdomains = [json.loads(line) for line in f if line.strip()]

        limited_subs = [entry.get("host", "") for entry in subdomains[:MAX_SUBFINDER_RESULTS]]

        return {
            "tool": "subfinder",
            "domain": domain,
            "subdomains": limited_subs
        }

    except subprocess.TimeoutExpired:
        return JSONResponse(status_code=500, content={"error": "Subfinder timed out."})
    except subprocess.CalledProcessError as e:
        return JSONResponse(status_code=500, content={"error": f"Subfinder failed: {str(e)}"})
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": f"Parsing subfinder output failed: {str(e)}"})

def run_shodan(inputs):
    ip = inputs.get("ip", "")
    if not ip:
        return JSONResponse(status_code=400, content={"error": "IP is required for Shodan."})

    api = shodan.Shodan(SHODAN_API_KEY)
    try:
        host = api.host(ip)
        banners = [item.get("data", "")[:MAX_LINE_LENGTH] for item in host.get("data", [])[:MAX_RESULTS]]
        return {
            "tool": "shodan",
            "ip": ip,
            "organization": host.get("org"),
            "os": host.get("os"),
            "ports": host.get("ports", []),
            "banners": banners,
            "country": host.get("country_name"),
            "hostnames": host.get("hostnames"),
            "matches_count": len(host.get("data", []))
        }
    except shodan.APIError as e:
        if "Access Denied" in str(e):
            return {"tool": "shodan", "ip": ip, "note": "This data requires Shodan premium tier."}
        return JSONResponse(status_code=500, content={"error": f"Shodan error: {str(e)}"})

def clean_whois_value(value):
    if isinstance(value, (datetime.date, datetime.datetime)):
        return value.isoformat()
    elif isinstance(value, set):
        return list(value)
    elif isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore")
    return value

def run_whois(inputs):
    target = inputs.get("target")
    if not target:
        return {"tool": "whois", "error": "Target is required"}

    try:
        raw_result = whois.whois(target)
        cleaned = {key: clean_whois_value(value) for key, value in raw_result.items()}
        return {"tool": "whois", "target": target, "results": cleaned}
    except Exception as e:
        return {"tool": "whois", "target": target, "error": str(e)}

def run_dnsx(inputs):
    domains = inputs.get("domains", [])
    if not domains or not isinstance(domains, list):
        return JSONResponse(status_code=400, content={"error": "A list of domains is required for dnsx."})

    input_file = "dnsx_input.txt"
    output_file = "dnsx_output.txt"
    dnsx_path = "/Users/rohahahan/go/bin/dnsx"  

    with open(input_file, "w") as f:
        f.write("\n".join(domains))

    cmd = f"{dnsx_path} -l {input_file} -o {output_file} -silent -resp"

    try:
        subprocess.run(cmd, shell=True, check=True, timeout=60)

        if not os.path.exists(output_file):
            return JSONResponse(status_code=500, content={"error": "dnsx output file not found."})

        with open(output_file, "r", encoding="utf-8") as f:
            raw_lines = [line.strip() for line in f if line.strip()]

        def strip_ansi(text):
            result = ""
            skip = False
            for char in text:
                if char == "\x1b":
                    skip = True
                    continue
                if skip:
                    if char == "m":
                        skip = False
                    continue
                result += char
            return result

        parsed_results = []
        for line in raw_lines[:50]:  
            line = strip_ansi(line).strip()

            if "[" not in line or "]" not in line:
                continue

            parts = line.split("[")
            if len(parts) < 3:
                continue

            domain = parts[0].strip()
            ip = parts[2].replace("]", "").strip()

            if domain and ip:
                parsed_results.append({"domain": domain, "ip": ip})

        input_domains = set(d.lstrip("*.").lower() for d in domains)

        def is_subdomain(domain, input_set):
            domain = domain.lower()
            return any(domain == base or domain.endswith("." + base) for base in input_set)

        filtered_results = []
        seen = set()
        for r in parsed_results:
            d = r.get("domain")
            ip = r.get("ip")
            if not d or not ip:
                continue
            if is_subdomain(d, input_domains):
                key = (d, ip)
                if key not in seen:
                    seen.add(key)
                    filtered_results.append(r)

        return {
            "tool": "dnsx",
            "domains": domains,
            "results": filtered_results
        }

    except subprocess.TimeoutExpired:
        return JSONResponse(status_code=500, content={"error": "dnsx timed out."})
    except subprocess.CalledProcessError as e:
        return JSONResponse(status_code=500, content={"error": f"dnsx failed: {str(e)}"})
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": f"Unexpected error: {str(e)}"})
    