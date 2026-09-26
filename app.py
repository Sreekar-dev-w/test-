import streamlit as st
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel
import concurrent.futures
import json
import sys

st.set_page_config(
    page_title="AgentX Security Swarm",
    page_icon="⚡",
    layout="wide",
)

st.markdown("""
    <style>
    .stApp { background-color: #0a0a0a; color: #ededed; }
    .stTextArea textarea { background-color: #171717; color: #34d399; border: 1px solid #262626; font-family: monospace; }
    .stButton button { background-color: #059669; color: #0a0a0a; font-weight: bold; width: 100%; border-radius: 8px; border: none; padding: 10px; }
    .stButton button:hover { background-color: #10b981; color: #0a0a0a; }
    </style>
""", unsafe_allow_html=True)

st.title(" AgentX Local Security Swarm")
st.caption("Autonomous Multi-Agent System powered by your fine-tuned CrossVul LoRA adapter")

@st.cache_resource
def load_agentx_engine():
    BASE_MODEL = "Qwen/Qwen2.5-Coder-1.5B-Instruct"
    ADAPTER_PATH = "./agentx_crossvul_adapter" 
    
    print("⏳ [Terminal Log] Loading tokenizer...", flush=True)
    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)
    
    print("⏳ [Terminal Log] Loading base model into VRAM (this may take a minute on first run)...", flush=True)
    base_model = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL,
        torch_dtype=torch.float16,
        device_map="auto"
    )
    
    print(" [Terminal Log] Merging custom CrossVul LoRA adapter weights...", flush=True)
    model = PeftModel.from_pretrained(base_model, ADAPTER_PATH)
    print(" [Terminal Log] Model and adapter fully loaded into VRAM!", flush=True)
    return tokenizer, model

with st.spinner(" Loading base model & custom security weights into VRAM (Check terminal for live progress)..."):
    tokenizer, model = load_agentx_engine()
st.success(" AgentX Custom Security Engine Ready!")

def local_model_generate(prompt):
    inputs = tokenizer(prompt, return_tensors="pt").to("cuda" if torch.cuda.is_available() else "cpu")
    with torch.no_grad():
        outputs = model.generate(
            **inputs, 
            max_new_tokens=300, 
            temperature=0.1, 
            do_sample=True,
            pad_token_id=tokenizer.eos_token_id
        )
    return tokenizer.decode(outputs[0][inputs['input_ids'].shape[1]:], skip_special_tokens=True)


def parallel_fixer_1(code):
    prompt = f"You are a Defensive Architect. Fix this code securely:\n{code}\nProvide patch and notes."
    return {"agent": "DefensiveArchitect", "response": local_model_generate(prompt)}

def parallel_fixer_2(code):
    prompt = f"You are a Performance Coder. Fix this code efficiently:\n{code}\nProvide patch and notes."
    return {"agent": "PerformanceCoder", "response": local_model_generate(prompt)}

def parallel_fixer_3(code):
    prompt = f"You are a Minimalist Specialist. Fix this code with minimal lines changed:\n{code}\nProvide patch and notes."
    return {"agent": "MinimalistSpecialist", "response": local_model_generate(prompt)}

def parallel_fixer_4(code):
    prompt = f"You are a Compliance Expert. Fix this code adhering to CWE standards:\n{code}\nProvide patch and notes."
    return {"agent": "ComplianceExpert", "response": local_model_generate(prompt)}

def consensus_judge(original, proposals):
    prompt = f"You are the Consensus Judge. Review original:\n{original}\nProposals:\n{json.dumps(proposals)}\nSelect the absolute best secure patch."
    return local_model_generate(prompt)

def formatter_agent(consensus_data):
    prompt = f"Format this decision into a clean Markdown developer report card:\n{consensus_data}"
    return local_model_generate(prompt)

def run_agentx_swarm(vulnerable_code):
    with st.status(" Running AgentX Swarm Pipeline...", expanded=True) as status:
        st.write(" Agents 1-4: Running parallel expert fixer personas...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = [
                executor.submit(parallel_fixer_1, vulnerable_code),
                executor.submit(parallel_fixer_2, vulnerable_code),
                executor.submit(parallel_fixer_3, vulnerable_code),
                executor.submit(parallel_fixer_4, vulnerable_code)
            ]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]
        
        st.write(" Agent 5: Reconciling consensus & verifying security...")
        consensus = consensus_judge(vulnerable_code, results)
        
        st.write("Agent 6: Generating final developer markdown card...")
        final_report = formatter_agent(consensus)
        
        status.update(label=" Swarm Analysis Complete!", state="complete", expanded=False)
        
    return results, final_report


default_snippet = 'cursor.execute(f"SELECT * FROM users WHERE name = {user_input}")'
code_input = st.text_area("Vulnerable Code Snippet", value=default_snippet, height=120)

if st.button(" Run AgentX Swarm Analysis"):
    if not code_input.strip():
        st.warning(" Please provide a valid code snippet.")
    else:
        raw_results, report = run_agentx_swarm(code_input)
        
        st.markdown("###  Individual Expert Fixer Proposals")
        tabs = st.tabs(["Defensive Architect", "Performance Coder", "Minimalist Specialist", "Compliance Expert"])
        for idx, tab in enumerate(tabs):
            with tab:
                st.code(raw_results[idx]['response'], language="python")

        st.markdown("### 🛡️ Final Consensus Security Report (Agent 6)")
        st.markdown(report)