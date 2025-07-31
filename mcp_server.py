import os
import subprocess
import json
import ipaddress
from dotenv import load_dotenv
from shodan import Shodan, APIError
from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.responses import JSONResponse

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

class MultiToolRequest(BaseModel):
    tool_steps: list[ToolRequest]

def normalize_shodan_inputs(tool_steps):
    for step in tool_steps:
        if step["tool"] == "shodan":
            if "query" in step["inputs"]:
                step["inputs"]["ip"] = step["inputs"].pop("query")
    return tool_steps

@app.post("/run_tool")
async def run_tool(req: ToolRequest):
    step = normalize_shodan_inputs([req.dict()])[0]
    tool = step["tool"].lower()
    inputs = step["inputs"]

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

@app.post("/run_tools")
async def run_multiple_tools(req: MultiToolRequest):
    normalized_steps = normalize_shodan_inputs([step.dict() for step in req.tool_steps])
    results = []

    for step in normalized_steps:
        tool = step["tool"].lower()
        inputs = step["inputs"]
        try:
            if tool == "theharvester":
                result = run_theharvester(inputs)
            elif tool == "subfinder":
                result = run_subfinder(inputs)
            elif tool == "shodan":
                result = run_shodan(inputs)
            elif tool == "whois":
                result = run_whois(inputs)
            elif tool == "dnsx":
                result = run_dnsx(inputs)
            else:
                result = {"error": f"Unknown tool: {tool}"}
        except Exception as e:
            result = {"error": str(e), "tool": tool}

        results.append(result)

    return results

def is_valid_public_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not (ip_obj.is_private or ip_obj.is_reserved or ip_obj.is_loopback or ip_obj.is_multicast)
    except ValueError:
        return False

def is_valid_ip_for_shodan(ip):
    return ip not in {"1.2.3.4", "0.0.0.0"} and not ip.startswith("127.") and not ip.startswith("169.254.")

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
    cmd = f"subfinder -d {domain} -o {output_file} -silent -json"

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

    if not is_valid_public_ip(ip) or not is_valid_ip_for_shodan(ip):
        return {
            "tool": "shodan",
            "ip": ip,
            "note": "Skipping private, reserved, or dummy IP — Shodan only supports public, meaningful IPs."
        }

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return JSONResponse(status_code=400, content={"error": f"Invalid IP format: {ip}"})

    api = Shodan(SHODAN_API_KEY)

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

    except APIError as e:
        error_msg = str(e).lower()
        plan_issue_terms = ["upgrade your api plan", "requires api plan", "access denied", "not allowed", "403", "not permitted"]

        if any(term in error_msg for term in plan_issue_terms):
            try:
                results = api.search(f"ip:{ip}")
                matches = results.get("matches", [])
                banners = [match.get("data", "")[:MAX_LINE_LENGTH] for match in matches[:MAX_RESULTS]] 

                if not matches:
                    return {
                        "tool": "shodan",
                        "ip": ip,
                        "note": "Fallback search returned no results — API limit or IP not indexed."
                    }

                return {
                    "tool": "shodan",
                    "ip": ip,
                    "banners": banners,
                    "matches_count": len(matches),
                    "note": "Used fallback search() due to limited API plan"
                }

            except APIError as fallback_error:
                return JSONResponse(
                    status_code=500,
                    content={
                        "error": f"Fallback search also failed: {str(fallback_error)}",
                        "hint": "Upgrade Shodan API plan or ensure the IP is indexed"
                    }
                )

        return JSONResponse(status_code=500, content={"error": f"Shodan host() error: {str(e)}"})

def run_whois(inputs):
    target = inputs.get("target")
    if not target:
        return {"tool": "whois", "error": "Target is required"}

    try:
        result = subprocess.run(["whois", target], capture_output=True, text=True, timeout=15)
        return {
            "tool": "whois",
            "target": target,
            "output": result.stdout.strip()
        }
    except Exception as e:
        return {"tool": "whois", "target": target, "error": str(e)}

def run_dnsx(inputs):
    domains = inputs.get("domains", [])
    if not domains or not isinstance(domains, list):
        return JSONResponse(status_code=400, content={"error": "A list of domains is required for dnsx."})

    input_file = "dnsx_input.txt"
    output_file = "dnsx_output.txt"
    dnsx_path = "/usr/local/bin/dnsx"

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

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
