import os
import json
import time
from datetime import datetime
import requests
from dotenv import load_dotenv
import anthropic
import ipaddress
import argparse
from llm_gpt import ask_gpt
from llm_gemini import ask_gemini

# Config and Constants
model = None
COST_PER_1K_TOKENS = {"claude": 0.25, "gpt": 0.0015, "gemini": 0.00025}
llm_token_usage = {"claude": 0, "gpt": 0, "gemini": 0}
llm_cost_usage = {"claude": 0.0, "gpt": 0.0, "gemini": 0.0}
total_cost_limit = 1.0

load_dotenv()
CLAUDE_API_KEY = os.getenv("CLAUDE_API_KEY")
MCP_URL = "http://127.0.0.1:8000/run_tool"
TRANSCRIPT_DIR = "logs"
os.makedirs(TRANSCRIPT_DIR, exist_ok=True)
client = anthropic.Anthropic(api_key=CLAUDE_API_KEY)
ALLOWED_TOOLS = {"theHarvester", "subfinder", "dnsx", "whois", "shodan"}

PRE_PROCESSING_PROMPT = """You are an OSINT task planner.

Your job is to turn a user's recon goal into a step-by-step JSON tool plan using only the tools listed below.

 Supported tools (use only these — do not invent others):
- theHarvester (input: domain)
- subfinder (input: domain)
- shodan (input: IP only — accepts {"ip"}, {"query"}, {"domain"}, or {"target"} 
# but extracts and validates only IPv4/IPv6 addresses, skips domains or hostnames)
- whois (input: domain or IP as 'target')
- dnsx (input: list of domains)

 Rules:
- ONLY use the tools listed above.
- DO NOT use tools like amass, crtsh, censys, zoomeye, dnsdumpster, or github-search.
- Prefer minimal tool use unless multiple are justified.
- Use dnsx to check if subdomains are alive.
- If input is vague like "scan everything" or "full recon", plan a reasonable recon workflow using only the above tools.
- Do not ask for more input — infer what makes sense from what's given.
- Always limit scope to reduce Claude API usage (no large loops or overkill).

 Return ONLY a raw JSON list of tool steps in the format:
[
  {"tool": "theHarvester", "inputs": {"domain": "example.com"}},
  {"tool": "subfinder", "inputs": {"domain": "example.com"}},
  {"tool": "shodan", "inputs": {"ip": "8.8.8.8"}},
  {"tool": "whois", "inputs": {"target": "example.com"}}
  {"tool": "dnsx", "inputs": {"domains": ["sub1.example.com", "sub2.example.com"]}}
]
"""

POST_PROCESSING_PROMPT = """You are an skilled OSINT analyst. Given raw JSON results from tools like theHarvester, Subfinder, Shodan, and Whois, summarize the findings.

Extract and highlight:
- Open ports, service info, emails, hostnames, orgs, locations, subdomains
- Mention anything juicy or security-relevant

Skip HTML or long raw data. Return a clean markdown-style summary.
"""

REFLECT_PLAN_PROMPT = """You are a reflective OSINT planner. Given the initial plan and user goal, decide if the plan:

- Is missing any useful steps using ONLY the allowed tools listed.
- Has redundant tools or can be simplified.
- Could improve in accuracy or coverage using ONLY the allowed tools.
- Only use Shodan with valid IP addresses. Never use domain names like "example.com" or "1234.example.com".

Tools you may use:
- theHarvester (input: domain)
- subfinder (input: domain)
- dnsx (input: domains list)
- whois (input: target)
- shodan (input: ip)

Very strict output rules:
- If the plan is already solid, return only: {"status": "good"}
- If you suggest changes, return a valid JSON list: [ {...}, {...} ]
- NEVER return separate JSON objects outside a list.
- NEVER use a domain name in a Shodan query — only use IP addresses like "1.2.3.4".

Example of correct output:
[
  {"tool": "dnsx", "inputs": {"domains": ["sub1.example.com"]}},
  {"tool": "shodan", "inputs": {"ip": "1.2.3.4"}}
]

Return ONLY valid JSON.
"""

REFLECT_RESULTS_PROMPT = """You are a reflective OSINT agent. Given the tool outputs and user goal, decide:
- Did we learn enough to answer the user’s request?
- Is more data needed?
- Should we rerun with additional tools?

If subdomains are found but not verified (e.g., not checked for liveness), consider adding a dnsx step — but only using real subdomains extracted from previous tool output.

IMPORTANT INPUT RULES:
- For dnsx: only use known, verified subdomains in the form of ["sub1.example.com", "sub2.example.com"] — avoid fake/generated or wildcard subdomains.
- For shodan: only use IPs like {"query": "1.2.3.4"} — never use domains or org names.
- Do NOT generate random subdomains. Only use those found in previous tool output.
- Use only tools from this list: theHarvester, subfinder, dnsx, whois, shodan
- If subdomains of the original domain are found but not verified, consider adding a dnsx step.
ONLY add DNSX steps for subdomains of the original user domain (do not invent new domains).

Respond strictly with one of the following formats:
- {"status": "goal_met"}
- {"status": "needs_more", "reason": "...", "next_plan": [ ... ]}

Where next_plan is a raw JSON list of tool steps like:
[
  {"tool": "shodan", "inputs": {"query": "1.2.3.4"}},
  {"tool": "dnsx", "inputs": {"domains": ["sub1.example.com"]},
  {"tool": "whois", "inputs": {"target": "example.com"}}
]
Do not use natural language strings. Use only these tools:
- theHarvester
- subfinder
- dnsx
- whois
- shodan
"""

def ask_llm(system_prompt, user_prompt):
    global model
    prompt_tokens = len(system_prompt.split()) + len(user_prompt.split())

    if model == "gpt":
        output = ask_gpt(system_prompt, user_prompt)
    elif model == "gemini":
        output = ask_gemini(f"{system_prompt}\n\n{user_prompt}")
    else:
        response = client.messages.create(
            model="claude-3-haiku-20240307",
            system=system_prompt,
            max_tokens=1024,
            temperature=0.2,
            messages=[{"role": "user", "content": user_prompt}]
        )
        output = response.content[0].text.strip()

    llm_token_usage[model] += prompt_tokens
    cost = (prompt_tokens / 1000.0) * COST_PER_1K_TOKENS[model]
    llm_cost_usage[model] += cost

    print(f"\n💬 [LLM Used: {model}]")
    print(f"Tokens used: {prompt_tokens}")
    print(f"Estimated cost: ${round(cost, 6)}")

    return output


def safe_parse_json(text):
    try:
        return json.loads(text.strip())
    except:
        start = min((text.find(c) for c in ('[', '{') if text.find(c) != -1), default=0)
        for end in range(len(text), start, -1):
            try:
                return json.loads(text[start:end])
            except:
                continue
    return None


def run_tool(tool, inputs):
    try:
        if tool == "shodan":
            query = inputs.get("ip") or inputs.get("query")
            if query:
                try:
                    ip_obj = ipaddress.ip_address(query.strip())
                    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_multicast:
                        return {"error": f"Shodan cannot scan private/reserved IPs ({query})."}
                except ValueError:
                    return {"error": f"Invalid IP address for Shodan: {query}"}

        response = requests.post(MCP_URL, json={"tool": tool, "inputs": inputs}, timeout=60)
        return response.json()
    except Exception as e:
        return {"error": f"Tool call failed: {str(e)}"}


def filter_supported_tools(tool_plan, original_domain=None):
    cleaned = []
    for step in tool_plan:
        if not isinstance(step, dict):
            continue
        tool = step.get("tool")
        inputs = step.get("inputs", {})
        if tool not in ALLOWED_TOOLS:
            continue

        if tool in {"theHarvester", "subfinder"}:
            domain = inputs.get("domain")
            if isinstance(domain, str) and domain.strip():
                cleaned.append({"tool": tool, "inputs": {"domain": domain.strip()}})

        elif tool == "dnsx":
            domains = inputs.get("domains")
            if isinstance(domains, list):
                valid = []
                for d in domains:
                    if isinstance(d, str):
                        d = d.lstrip("*.").strip()
                        if "*" in d:
                            continue
                        if original_domain and d.endswith("." + original_domain):
                            valid.append(d)
                if valid:
                    cleaned.append({"tool": "dnsx", "inputs": {"domains": valid}})

        elif tool == "shodan":
            query = inputs.get("query") or inputs.get("ip") or inputs.get("domain") or inputs.get("target")
            if isinstance(query, str) and query.strip():
                query = query.strip()
                try:
                    ip = str(ipaddress.ip_address(query))
                    cleaned.append({"tool": "shodan", "inputs": {"ip": ip}})
                except ValueError:
                    cleaned.append({"tool": "shodan", "inputs": {"query": query}})

        elif tool == "whois":
            target = None
            for key in ("target", "domain", "ip", "domains"):
                val = inputs.get(key)
                if isinstance(val, str):
                    target = val.strip()
                    break
                elif isinstance(val, list):
                    targets = [v.strip() for v in val if isinstance(v, str)]
                    if targets:
                        target = targets[0]
                        break
            if target:
                cleaned.append({"tool": "whois", "inputs": {"target": target}})

    return cleaned


def reflect_on_plan(user_prompt, plan, memory):
    payload = {
        "goal": user_prompt,
        "current_plan": plan,
        "plan_history": memory.get("tool_plan_history", []),
        "results_so_far": memory.get("tool_results_history", []),
        "reflections_so_far": memory.get("reflections", [])
    }
    output = ask_llm(REFLECT_PLAN_PROMPT, json.dumps(payload, indent=2))
    print("\n[DEBUG] Claude raw reflection output:\n", output)
    parsed = safe_parse_json(output)
    if isinstance(parsed, list):
        return parsed
    elif isinstance(parsed, dict):
        if parsed.get("status") == "good":
            return parsed
        elif isinstance(parsed.get("plan"), list):
            return parsed["plan"]
    return {"status": "fallback", "raw": output}


def reflect_on_results(user_prompt, results, memory):
    payload = {
        "goal": user_prompt,
        "results": results,
        "plan_history": memory.get("tool_plan_history", []),
        "reflections_so_far": memory.get("reflections", [])
    }
    output = ask_llm(REFLECT_RESULTS_PROMPT, json.dumps(payload, indent=2))
    parsed = safe_parse_json(output)

    if isinstance(parsed, dict) and parsed.get("status") in ["goal_met", "needs_more"]:
        if parsed["status"] == "needs_more":
            parsed.setdefault("next_plan", [])

            dnsx_ips = []
            for r in results:
                if r["tool"] != "dnsx":
                    continue
                for entry in r.get("result", {}).get("results", []):
                    ip_raw = entry.get("ip", "")
                    try:
                        ip_obj = ipaddress.ip_address(ip_raw.strip())
                        dnsx_ips.append(str(ip_obj))
                    except ValueError:
                        continue

            for ip in sorted(set(dnsx_ips)):
                parsed["next_plan"].append({"tool": "shodan", "inputs": {"query": ip}})

            original_domain = extract_original_domain_from_tool_plan(
                memory.get("tool_plan_history", [])[-1] if memory.get("tool_plan_history") else []
            )
            subdomains = extract_subdomains(results, original_domain)
            if subdomains:
                parsed["next_plan"].append({
                    "tool": "dnsx",
                    "inputs": {"domains": sorted(set(subdomains))}
                })
        return parsed

    return {"status": "fallback", "raw": output}


def extract_original_domain_from_tool_plan(plan):
    if not isinstance(plan, list):
        return ""
    for step in plan:
        inputs = step.get("inputs", {})
        for key in ["domain", "target", "query", "ip"]:
            value = inputs.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip().lower()
    return ""


def extract_subdomains(results, original_domain):
    subdomains = set()
    for r in results:
        if r["tool"] in {"subfinder", "theHarvester"}:
            for sub in r.get("result", {}).get("subdomains", []):
                if isinstance(sub, str):
                    sub_clean = sub.lstrip("*.").strip()
                    if sub_clean == original_domain or sub_clean.endswith("." + original_domain):
                        subdomains.add(sub_clean)
    return list(subdomains)


def parse_next_plan(plan):
    return safe_parse_json(plan) if isinstance(plan, str) else plan


def save_final_llm_cost_log():
    if all(cost == 0 for cost in llm_cost_usage.values()):
        return  

    os.makedirs("logs", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = f"logs/llm_cost_log_{timestamp}.json"

    with open(log_path, "w") as f:
        json.dump({
            "timestamp": timestamp,
            "llm_cost_usage": llm_cost_usage,
            "llm_token_usage": llm_token_usage
        }, f, indent=2)

    print(f"\n Final LLM cost log saved to {log_path}")

def main():
    global model

    parser = argparse.ArgumentParser()
    parser.add_argument("prompt", help="User prompt for OSINT")
    parser.add_argument("--model", choices=["claude", "gpt", "gemini"], default="claude", help="Choose LLM model")
    args = parser.parse_args()

    model = args.model
    user_prompt = args.prompt.strip()
    if not user_prompt:
        print("⚠️ Please enter a valid OSINT prompt.")
        return

    start_time = datetime.now()
    timestamp = start_time.strftime('%Y%m%d_%H%M%S')

    transcript = {
        "user_prompt": user_prompt,
        "start_time": str(start_time),
        "steps": [],
        "loops": [],
        "llm_usage": {},
        "final_summary": "",
        "end_time": "",
        "duration_total_sec": 0,
        "timestamp": timestamp
    }

    short_term_memory = {
        "user_prompt": user_prompt,
        "tool_plan_history": [],
        "tool_results_history": [],
        "reflections": []
    }

    loops = 0
    max_loops = 3
    already_run = set()

    try:
        tool_plan_raw = ask_llm(PRE_PROCESSING_PROMPT, user_prompt)
        parsed_plan = safe_parse_json(tool_plan_raw)
        if not parsed_plan:
            print("❌ LLM returned invalid tool plan.")
            return
        original_domain = extract_original_domain_from_tool_plan(parsed_plan)
        tool_plan = filter_supported_tools(parsed_plan, original_domain=original_domain)
    except Exception as e:
        print(f"❌ LLM preprocessing failed: {e}")
        return

    if not tool_plan:
        print("❌ No valid tools in LLM plan.")
        return

    while loops < max_loops:
        loops += 1
        print(f"\n🔁 Loop {loops} - Executing tool plan...")
        print("\nCurrent Tool Plan:\n", json.dumps(tool_plan, indent=2))

        loop_result = {"loop": loops, "tools": []}
        all_results = []

        for step in tool_plan:
            tool = step["tool"]
            inputs = step["inputs"]
            key = (tool, json.dumps(inputs, sort_keys=True))
            if key in already_run:
                print(f"Skipping already run: {tool} with {inputs}")
                continue

            already_run.add(key)
            print(f"\n⚙️ Running {tool} with inputs: {inputs}")
            t0 = time.time()
            result = run_tool(tool, inputs)
            t1 = time.time()

            print(f"Result:\n{json.dumps(result, indent=2)}")
            all_results.append({"tool": tool, "inputs": inputs, "result": result})

            loop_result["tools"].append({
                "tool": tool,
                "inputs": inputs,
                "output": result,
                "duration_sec": round(t1 - t0, 2)
            })

        transcript["loops"].append(loop_result)
        short_term_memory["tool_plan_history"].append(tool_plan)
        short_term_memory["tool_results_history"].append(all_results)

        result_review = reflect_on_results(user_prompt, all_results, short_term_memory)
        short_term_memory["reflections"].append({
            "type": "result",
            "loop": loops,
            "reflection": result_review
        })

        if result_review.get("status") == "goal_met":
            print("\n✅ Goal Met. Exiting loop.")
            break
        elif result_review.get("status") == "needs_more":
            next_plan = parse_next_plan(result_review.get("next_plan", []))
            tool_plan = filter_supported_tools(next_plan, original_domain=original_domain)
            if not tool_plan:
                print("⚠️ No valid tools left after reflection.")
                break
        else:
            print("⚠️ Invalid result reflection. Exiting.")
            break

    all_results_flat = [r for loop in short_term_memory["tool_results_history"] for r in loop]
    try:
        post_output = ask_llm(POST_PROCESSING_PROMPT, json.dumps(all_results_flat, indent=2))
    except Exception as e:
        post_output = f"LLM summary failed: {e}"

    # Final summary and save
    print("\n📝 Final Summary:\n", post_output)
    transcript["final_summary"] = post_output
    transcript["end_time"] = str(datetime.now())
    transcript["duration_total_sec"] = round((datetime.now() - start_time).total_seconds(), 2)
    transcript["llm_usage"] = {
        m: {
            "tokens_used": llm_token_usage[m],
            "estimated_cost_usd": round(llm_cost_usage[m], 6)
        } for m in llm_token_usage if llm_token_usage[m] > 0
    }

    # File save paths
    transcript_file = f"{TRANSCRIPT_DIR}/transcript_{timestamp}.json"
    memory_file = f"{TRANSCRIPT_DIR}/memory_{timestamp}.json"
    summary_file = f"{TRANSCRIPT_DIR}/summary_{timestamp}.txt"

    # Save files
    with open(transcript_file, "w") as f:
        json.dump(transcript, f, indent=2)
    with open(memory_file, "w") as f:
        json.dump(short_term_memory, f, indent=2)
    with open(summary_file, "w") as f:
        f.write(post_output)

    save_final_llm_cost_log()

    print("\n✅ Saved the following files:")
    print(f" Transcript: {transcript_file}")
    print(f" Memory    : {memory_file}")
    print(f" Summary   : {summary_file}")

if __name__ == "__main__":
    main()
