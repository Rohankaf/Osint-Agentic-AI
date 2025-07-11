import os 
import json
import time
from datetime import datetime
import requests
from dotenv import load_dotenv
import anthropic

load_dotenv()
CLAUDE_API_KEY = os.getenv("CLAUDE_API_KEY")
MCP_URL = "http://127.0.0.1:8000/run_tool"
TRANSCRIPT_DIR = "logs"
os.makedirs(TRANSCRIPT_DIR, exist_ok=True)

client = anthropic.Anthropic(api_key=CLAUDE_API_KEY)

ALLOWED_TOOLS = {"theHarvester", "subfinder", "dnsx", "whois", "shodan"}

# --- Prompts ---
PRE_PROCESSING_PROMPT = """You are an OSINT task planner.

Your job is to turn a user's recon goal into a step-by-step JSON tool plan using only the tools listed below.

📌 Supported tools (use only these — do not invent others):
- theHarvester (input: domain)
- subfinder (input: domain)
- shodan (input: IP only — use only {"query": "IP"} format, never "host" or domain names)
- whois (input: domain or IP as 'target')
- dnsx (input: list of domains)

🔐 Rules:
- ONLY use the tools listed above.
- DO NOT use tools like amass, crtsh, censys, zoomeye, dnsdumpster, or github-search.
- Prefer minimal tool use unless multiple are justified.
- Use dnsx to check if subdomains are alive.
- If input is vague like "scan everything" or "full recon", plan a reasonable recon workflow using only the above tools.
- Do not ask for more input — infer what makes sense from what's given.
- Always limit scope to reduce Claude API usage (no large loops or overkill).

✅ Return ONLY a raw JSON list of tool steps in the format:
[
  {"tool": "theHarvester", "inputs": {"domain": "example.com"}},
  {"tool": "subfinder", "inputs": {"domain": "example.com"}},
  {"tool": "dnsx", "inputs": {"domains": ["a.example.com", "b.example.com"]}},
  {"tool": "whois", "inputs": {"target": "example.com"}},
  {"tool": "shodan", "inputs": {"query": "1.2.3.4"}}
]"""
POST_PROCESSING_PROMPT = """You are an skilled OSINT analyst. Given raw JSON results from tools like theHarvester, Subfinder, Shodan, and Whois, summarize the findings.

Extract and highlight:
- Open ports, service info, emails, hostnames, orgs, locations, subdomains
- Mention anything juicy or security-relevant

Skip HTML or long raw data. Return a clean markdown-style summary."""
REFLECT_PLAN_PROMPT = """You are a reflective OSINT planner. Given the initial plan and user goal, decide if the plan:

- Is missing any useful steps using ONLY the allowed tools listed.
- Has redundant tools or can be simplified.
- Could improve in accuracy or coverage using ONLY the allowed tools.

 VERY IMPORTANT:
Use ONLY the following tools (never suggest anything else):
- theHarvester
- subfinder
- dnsx
- whois
- shodan

Return:
- A new plan (as a JSON list) if improvement is needed
- Or {"status": "good"} if the plan is already solid"""
REFLECT_RESULTS_PROMPT = """You are a reflective OSINT agent. Given the tool outputs and user goal, decide:
- Did we learn enough to answer the user’s request?
- Is more data needed?
- Should we rerun with additional tools?

Respond with one of:
- {"status": "goal_met"}
- {"status": "needs_more", "reason": "...", "next_plan": [ ... ]}

✅ next_plan MUST be a list of tool steps like:
[
  {"tool": "shodan", "inputs": {"query": "example.com"}},
  {"tool": "whois", "inputs": {"target": "example.com"}}
]

Do not use natural language strings. Use only these tools:
- theHarvester
- subfinder
- dnsx
- whois
- shodan"""

# --- Utility Functions ---

def filter_supported_tools(tool_plan):
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
                domains = [d for d in domains if isinstance(d, str) and "*" not in d]
                if domains:
                    cleaned.append({"tool": tool, "inputs": {"domains": domains}})
        elif tool == "shodan":
            query = inputs.get("query") or inputs.get("ip") or inputs.get("domain") or inputs.get("target")
            if isinstance(query, str) and query.strip():
                cleaned.append({"tool": tool, "inputs": {"query": query.strip()}})
        elif tool == "whois":
            for key in ("target", "domain", "ip"):
                if key in inputs and isinstance(inputs[key], str):
                    cleaned.append({"tool": tool, "inputs": {"target": inputs[key].strip()}})
                    break
    return cleaned

def ask_claude(system_prompt, user_prompt):
    response = client.messages.create(
        model="claude-3-haiku-20240307",
        system=system_prompt,
        max_tokens=1024,
        temperature=0.2,
        messages=[{"role": "user", "content": user_prompt}]
    )
    return response.content[0].text.strip()

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
        response = requests.post(MCP_URL, json={"tool": tool, "inputs": inputs}, timeout=60)
        return response.json()
    except Exception as e:
        return {"error": f"Tool call failed: {str(e)}"}

def reflect_on_plan(user_prompt, plan):
    output = ask_claude(REFLECT_PLAN_PROMPT, json.dumps({"goal": user_prompt, "plan": plan}, indent=2))
    parsed = safe_parse_json(output)
    if isinstance(parsed, list):
        return parsed
    elif isinstance(parsed, dict):
        if parsed.get("status") == "good":
            return parsed
        elif isinstance(parsed.get("plan"), list):
            return parsed["plan"]
    return {"status": "fallback", "raw": output}

def reflect_on_results(user_prompt, results):
    output = ask_claude(REFLECT_RESULTS_PROMPT, json.dumps({"goal": user_prompt, "results": results}, indent=2))
    parsed = safe_parse_json(output)
    if isinstance(parsed, dict) and parsed.get("status") in ["goal_met", "needs_more"]:
        return parsed
    return {"status": "fallback", "raw": output}

def parse_next_plan(plan):
    return safe_parse_json(plan) if isinstance(plan, str) else plan

# --- Main Loop ---
def main():
    user_prompt = input("Enter your OSINT prompt: ").strip()
    start_time = datetime.now()

    transcript = {"user_prompt": user_prompt, "start_time": str(start_time), "steps": []}
    short_term_memory = {"user_prompt": user_prompt, "tool_plan_history": [], "tool_results_history": [], "reflections": []}
    loops = 0
    max_loops = 3

    tool_plan = filter_supported_tools(safe_parse_json(ask_claude(PRE_PROCESSING_PROMPT, user_prompt)))
    if not tool_plan:
        print("❌ Claude returned invalid JSON.")
        return

    while loops < max_loops:
        loops += 1
        print(f"\n🔄 Loop {loops} - Executing tool plan...")

        # Reflect on plan
        plan_review = reflect_on_plan(user_prompt, tool_plan)
        short_term_memory["tool_plan_history"].append(tool_plan)
        short_term_memory["reflections"].append({"type": "plan", "reflection": plan_review})

        if isinstance(plan_review, list):
            tool_plan = filter_supported_tools(plan_review)
        elif isinstance(plan_review, dict) and plan_review.get("status") == "good":
            pass
        else:
            print("⚠️ Invalid plan reflection.")

        all_results = []
        for step in tool_plan:
            tool = step["tool"]
            inputs = step["inputs"]
            print(f"\n⚙️ Running {tool} with inputs: {inputs}")
            t0 = time.time()
            result = run_tool(tool, inputs)
            t1 = time.time()
            print(f"✅ Result:\n{json.dumps(result, indent=2)}")
            all_results.append({"tool": tool, "inputs": inputs, "result": result})
            transcript["steps"].append({"step": f"run_{tool}", "inputs": inputs, "output": result, "duration_sec": round(t1 - t0, 2)})

        result_review = reflect_on_results(user_prompt, all_results)
        short_term_memory["tool_results_history"].append(all_results)
        short_term_memory["reflections"].append({"type": "result", "loop": loops, "reflection": result_review})

        if result_review.get("status") == "goal_met":
            print("\n✅ Goal Met. Exiting loop.")
            break
        elif result_review.get("status") == "needs_more":
            tool_plan = filter_supported_tools(parse_next_plan(result_review.get("next_plan", [])))
            if not tool_plan:
                print("⚠️ No valid tools left after reflection. Stopping.")
                break
        elif not isinstance(result_review, dict) or "raw" not in result_review:
            print("⚠️ Invalid result reflection. Exiting.")
            break
        else:
            print("⚠️ Claude said:\n", result_review.get("raw", "No raw output found."))
            break

    all_results_flat = [r for loop in short_term_memory["tool_results_history"] for r in loop]
    post_output = ask_claude(POST_PROCESSING_PROMPT, json.dumps(all_results_flat, indent=2))
    print("\n🧠 Final Summary:\n")
    print(post_output)

    transcript["steps"].append({"step": "summary", "summary": post_output})
    transcript["end_time"] = str(datetime.now())
    transcript["duration_total_sec"] = round((datetime.now() - start_time).total_seconds(), 2)

    timestamp = start_time.strftime('%Y-%m-%d_%H-%M-%S')
    with open(f"{TRANSCRIPT_DIR}/transcript_{timestamp}.json", "w") as f:
        json.dump(transcript, f, indent=2)
    with open(f"{TRANSCRIPT_DIR}/memory_{timestamp}.json", "w") as f:
        json.dump(short_term_memory, f, indent=2)
    print(f"\n📄 Saved transcript and memory to logs/")

if __name__ == "__main__":
    main()
