"""
core/ai_lora.py
---------------
LoRA fine-tuning data preparation for local models.

This module:
  - Collects training data from your reports and findings
  - Formats it as instruction-response pairs
  - Saves a JSONL training file ready for LoRA training

Actual training is done outside the framework (via unsloth/peft tools).
"""

import json
import os
import re
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

from core.logger import get_logger, info, ok, warn, skip
from core.utils import load_json, save_json, ensure_dir, read_lines
from core.database import get_db

log = get_logger("ai_lora")


# ─────────────────────────────────────────
# Paths
# ─────────────────────────────────────────
TRAINING_DIR = Path(".cache/lora")
TRAINING_FILE = TRAINING_DIR / "training_data.jsonl"
CONFIG_FILE = TRAINING_DIR / "lora_config.json"


# ─────────────────────────────────────────
# Data collectors
# ─────────────────────────────────────────
def collect_from_database(db_path: str = "bug_bounty.db") -> List[Dict]:
    """
    Extract confirmed findings from DB to use as training data.
    """
    samples: List[Dict] = []
    try:
        db = get_db(db_path)
        conn = db._conn()
        rows = conn.execute("""
            SELECT vuln_type, severity, url, param, payload, evidence, status
            FROM findings
            WHERE status IN ('confirmed', 'reported')
            LIMIT 1000
        """).fetchall()
        conn.close()
    except Exception as e:
        log.debug(f"DB read failed: {e}")
        return samples

    for r in rows:
        finding = dict(r)
        instruction = (
            f"Analyze this finding from a bug bounty scan and classify it:\n\n"
            f"Type: {finding.get('vuln_type', 'unknown')}\n"
            f"Severity: {finding.get('severity', 'unknown')}\n"
            f"URL: {finding.get('url', '')}\n"
            f"Parameter: {finding.get('param', '')}\n"
            f"Payload: {finding.get('payload', '')}\n"
        )
        response = json.dumps({
            "verdict": "true_positive",
            "severity": finding.get("severity", "medium"),
            "reasoning": finding.get("evidence", "")[:300],
            "next_step": "Manual verification recommended.",
        }, ensure_ascii=False)
        samples.append({"instruction": instruction, "response": response})

    return samples


def collect_from_reports(reports_dir: str = "results") -> List[Dict]:
    """
    Extract from markdown reports.
    """
    samples: List[Dict] = []
    root = Path(reports_dir)
    if not root.exists():
        return samples

    for md in root.rglob("*.md"):
        try:
            text = md.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        if len(text) < 100:
            continue

        # Extract title + severity from the report
        title = ""
        for line in text.splitlines():
            if line.startswith("# "):
                title = line[2:].strip()
                break

        instruction = f"Write a HackerOne report for this vulnerability:\nTitle: {title}"
        response = text[:3000]
        samples.append({"instruction": instruction, "response": response})

    return samples


def collect_from_rag() -> List[Dict]:
    """
    Get documents from the RAG store.
    """
    samples: List[Dict] = []
    try:
        from core.ai_rag import get_rag
        rag = get_rag()
        for doc in rag.docs:
            text = doc.get("text", "")
            if len(text) < 80:
                continue
            meta = doc.get("metadata", {})
            dtype = meta.get("type", "doc")
            instruction = f"Explain or analyze this {dtype}:"
            samples.append({
                "instruction": instruction,
                "response": text[:1500],
            })
    except Exception as e:
        log.debug(f"RAG read failed: {e}")
    return samples


# ─────────────────────────────────────────
# Augmentation
# ─────────────────────────────────────────
def augment_sample(sample: Dict) -> List[Dict]:
    """
    Create 2-3 variations of each sample to enrich training set.
    """
    variants = [sample]

    inst = sample.get("instruction", "")
    resp = sample.get("response", "")

    # Variant: shorter phrasing
    variants.append({
        "instruction": inst.replace("Analyze", "Review").replace("Classify", "Judge"),
        "response": resp,
    })

    # Variant: task-focused
    variants.append({
        "instruction": "Bug bounty triage assistant task: " + inst[:200],
        "response": resp,
    })

    return variants


# ─────────────────────────────────────────
# Deduplication
# ─────────────────────────────────────────
def dedupe_samples(samples: List[Dict]) -> List[Dict]:
    seen = set()
    out = []
    for s in samples:
        key = (s.get("instruction", "")[:150], s.get("response", "")[:150])
        if key in seen:
            continue
        seen.add(key)
        out.append(s)
    return out


# ─────────────────────────────────────────
# Main builder
# ─────────────────────────────────────────
def build_training_data(db_path: str = "bug_bounty.db",
                        output_file: Path = TRAINING_FILE,
                        augment: bool = True) -> Dict:
    """
    Build a JSONL training file from all sources.
    """
    ensure_dir(output_file.parent)

    info("Collecting training samples...")
    samples = []
    samples += collect_from_database(db_path)
    samples += collect_from_reports()
    samples += collect_from_rag()

    info(f"Collected {len(samples)} raw samples")

    if augment:
        expanded = []
        for s in samples:
            expanded.extend(augment_sample(s))
        samples = expanded
        info(f"Augmented to {len(samples)} samples")

    samples = dedupe_samples(samples)
    info(f"Deduped to {len(samples)} samples")

    # Write JSONL
    written = 0
    with open(output_file, "w", encoding="utf-8") as f:
        for s in samples:
            try:
                f.write(json.dumps(s, ensure_ascii=False) + "\n")
                written += 1
            except Exception:
                continue

    # Write config
    config = {
        "created_at": datetime.utcnow().isoformat(),
        "samples": written,
        "output_file": str(output_file),
        "recommended_base_models": [
            "meta-llama/Llama-3.1-8B-Instruct",
            "mistralai/Mistral-7B-Instruct-v0.3",
            "Qwen/Qwen2.5-7B-Instruct",
        ],
        "recommended_tools": ["unsloth", "peft", "transformers", "trl"],
        "lora_rank": 16,
        "lora_alpha": 32,
        "lora_dropout": 0.05,
        "learning_rate": 2e-4,
        "epochs": 3,
        "batch_size": 4,
        "note": (
            "This config is for reference. Actual training requires a GPU. "
            "Use unsloth or peft to load the base model and apply LoRA."
        ),
    }
    save_json(CONFIG_FILE, config)

    ok(f"Training data: {written} samples → {output_file}")
    return {"samples": written, "output": str(output_file), "config": str(CONFIG_FILE)}


# ─────────────────────────────────────────
# Quick fine-tune runner (optional)
# ─────────────────────────────────────────
def generate_training_script(base_model: str = "unsloth/llama-3.1-8b-instruct",
                             output_dir: str = ".cache/lora/out") -> str:
    """
    Generate a Python training script for manual use.
    """
    ensure_dir(output_dir)
    script = f'''"""
LoRA Fine-Tuning Script (Generated by Dream Framework)
Requires: pip install unsloth transformers trl datasets peft
Recommended: Run on a GPU with 16+ GB VRAM.
"""

import json
from datasets import Dataset
from unsloth import FastLanguageModel
from trl import SFTTrainer

BASE_MODEL = "{base_model}"
TRAINING_DATA = "{TRAINING_FILE}"
OUTPUT_DIR = "{output_dir}"
MAX_SEQ_LEN = 2048

# Load data
samples = []
with open(TRAINING_DATA, encoding="utf-8") as f:
    for line in f:
        try:
            samples.append(json.loads(line))
        except Exception:
            continue

def fmt(sample):
    return {{
        "text": (
            "### Instruction:\\n" + sample["instruction"]
            + "\\n\\n### Response:\\n" + sample["response"]
        )
    }}

dataset = Dataset.from_list([fmt(s) for s in samples])

# Load model
model, tokenizer = FastLanguageModel.from_pretrained(
    model_name=BASE_MODEL,
    max_seq_length=MAX_SEQ_LEN,
    load_in_4bit=True,
)

model = FastLanguageModel.get_peft_model(
    model,
    r=16,
    lora_alpha=32,
    lora_dropout=0.05,
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj"],
    bias="none",
    use_gradient_checkpointing=True,
    random_state=42,
)

# Trainer
trainer = SFTTrainer(
    model=model,
    tokenizer=tokenizer,
    train_dataset=dataset,
    dataset_text_field="text",
    max_seq_length=MAX_SEQ_LEN,
    args={{
        "per_device_train_batch_size": 4,
        "gradient_accumulation_steps": 4,
        "warmup_steps": 10,
        "num_train_epochs": 3,
        "learning_rate": 2e-4,
        "fp16": True,
        "logging_steps": 10,
        "output_dir": OUTPUT_DIR,
        "save_strategy": "epoch",
    }},
)

trainer.train()
model.save_pretrained(OUTPUT_DIR + "/final")
tokenizer.save_pretrained(OUTPUT_DIR + "/final")
print("Training complete:", OUTPUT_DIR)
'''
    script_path = Path(output_dir) / "train_lora.py"
    script_path.write_text(script, encoding="utf-8")
    ok(f"Training script: {script_path}")
    return str(script_path)


# ─────────────────────────────────────────
# CLI
# ─────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="LoRA fine-tuning data prep")
    p.add_argument("--build", action="store_true", help="Build training data")
    p.add_argument("--generate-script", action="store_true",
                   help="Generate training script")
    p.add_argument("--stats", action="store_true")
    args = p.parse_args()

    if args.build:
        r = build_training_data()
        print(json.dumps(r, indent=2))
    elif args.generate_script:
        s = generate_training_script()
        print(f"Script: {s}")
    else:
        if TRAINING_FILE.exists():
            count = sum(1 for _ in open(TRAINING_FILE))
            print(f"Training file: {TRAINING_FILE} ({count} samples)")
        else:
            print("No training data yet. Run --build")