# Dream Framework

AI-powered bug bounty hunting framework — built for serious hunters.

![Status](https://img.shields.io/badge/status-production--ready-brightgreen)
![Python](https://img.shields.io/badge/python-3.10+-blue)
![License](https://img.shields.io/badge/license-MIT-yellow)

---

## 🎯 Overview

Dream Framework is a modular, AI-powered bug bounty hunting framework.
It chains reconnaissance, scanning, exploitation, and reporting into
a single automated pipeline while keeping human-in-the-loop for
critical decisions.

**Key Stats:**
- 139 Python files
- 48 vulnerability modules
- 4 AI providers supported (CommandCode, DeepSeek, OpenAI, Anthropic)
- Multi-layer caching for 60-80% token savings
- Parallel AI calls for 5-10x speedup

---

## 🚀 Quick Start

### 1. Install dependencies

```bash
pip3 install -r requirements.txt --break-system-packages
pip3 install aiohttp --break-system-packages