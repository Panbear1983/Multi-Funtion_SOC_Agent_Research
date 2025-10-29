# 🛡️ Multi-Function SOC Agent Research

**Comprehensive Security Operations Center Research & Implementation Repository**

A holistic research repository exploring multiple facets of modern Security Operations Center (SOC) capabilities, from AI-powered threat hunting and anomaly detection to vulnerability management, threat hunting exercises, and security compliance automation.

---

## 📋 Table of Contents

- [Repository Overview](#repository-overview)
- [Project Structure](#project-structure)
- [Components](#components)
- [Getting Started](#getting-started)
- [Use Cases](#use-cases)
- [Architecture & Design Philosophy](#architecture--design-philosophy)
- [Contributing](#contributing)
- [License](#license)

---

## 🎯 Repository Overview

This repository serves as a comprehensive research and implementation platform for SOC operations, encompassing four critical domains:

1. **🤖 AI-Powered Threat Detection** - Automated threat hunting and anomaly detection using Large Language Models
2. **🔍 Vulnerability Management** - End-to-end vulnerability lifecycle management from policy to remediation
3. **📊 Threat Hunting Exercises** - Real-world CTF scenarios and threat hunting case studies
4. **⚙️ Security Compliance** - STIG implementation and security hardening automation

Together, these components form a complete SOC research and development ecosystem, demonstrating how modern security operations can leverage AI, automation, and best practices to enhance detection, response, and remediation capabilities.

---

## 🏗️ Project Structure

```
Multi-Funtion_SOC_Agent_Research/
│
├── openAI_Agentic_SOC_Analyst/         # AI-powered SOC analyst
│   ├── README.md                       # Comprehensive documentation
│   ├── _main.py                        # Main entry point
│   ├── THREAT_HUNT_PIPELINE.py         # Targeted threat hunting
│   ├── ANOMALY_DETECTION_PIPELINE.py   # Automated anomaly detection
│   ├── CORRELATION_ENGINE.py           # Attack chain correlation
│   ├── LEARNING_ENGINE.py             # Self-learning system
│   └── ... (30+ modules)
│
├── Vulnerability_Management_Program _Implementation/
│   ├── README.md                       # Program documentation
│   └── ... (vulnerability management artifacts)
│
├── Threat_Hunting_Projects/
│   ├── (CTF) RDP Password Spray.md     # Password spray case study
│   ├── (CTF) Lurker.md                 # Advanced persistent threat
│   └── (CTF) Papertrail.md             # Log analysis challenge
│
└── STIGS/
    └── (demo-project)WN10-AU-000500.ps1 # Security compliance scripts
```

---

## 🔧 Components

### 1. 🤖 OpenAI Agentic SOC Analyst

**Location:** `openAI_Agentic_SOC_Analyst/`

**Purpose:** AI-powered threat hunting and anomaly detection system that uses Large Language Models (LLMs) to analyze security logs and detect threats.

**Key Features:**
- ✅ **3-Tier Severity System** - Relaxed/Balanced/Strict detection modes
- ✅ **Active Learning** - Self-improving from user feedback (1-5 ratings)
- ✅ **Hybrid Detection** - 165+ rule-based patterns + LLM analysis
- ✅ **Attack Chain Correlation** - Cross-table event linking
- ✅ **Behavioral Baseline** - Learns normal patterns and detects deviations
- ✅ **MITRE ATT&CK Mapping** - 610+ technique mappings
- ✅ **Offline Operation** - Local models for privacy-preserving analysis
- ✅ **CTF Mode** - Interactive flag hunting for competitions

**Use Cases:**
- Incident response and alert triage
- Proactive threat hunting
- Anomaly detection across multiple data sources
- CTF competition flag hunting

**Documentation:** See [`openAI_Agentic_SOC_Analyst/README.md`](openAI_Agentic_SOC_Analyst/README.md) for complete documentation.

---

### 2. 🔍 Vulnerability Management Program Implementation

**Location:** `Vulnerability_Management_Program _Implementation/`

**Purpose:** Complete vulnerability management program lifecycle from policy creation to remediation execution.

**Key Features:**
- ✅ **Policy Development** - Draft and finalize vulnerability management policies
- ✅ **Stakeholder Engagement** - Simulated meetings and buy-in processes
- ✅ **Scan Execution** - Tenable integration for vulnerability scanning
- ✅ **Prioritization** - Risk-based vulnerability assessment
- ✅ **Remediation Automation** - PowerShell scripts for automated fixes
- ✅ **Change Management** - CAB meeting simulations and approval workflows
- ✅ **Metrics & Reporting** - Vulnerability reduction tracking

**Program Flow:**
1. Policy Draft Creation
2. Stakeholder Buy-In Meetings
3. Senior Leadership Sign-Off
4. Initial Discovery Scans
5. Vulnerability Assessment & Prioritization
6. Remediation Distribution
7. Change Control Board Approval
8. Remediation Execution (4 rounds)
9. Verification Scans
10. Maintenance Mode Transition

**Use Cases:**
- Establishing a new vulnerability management program
- Training teams on vulnerability lifecycle
- Demonstrating end-to-end remediation workflows
- Reference implementation for policy development

**Documentation:** See [`Vulnerability_Management_Program _Implementation/README.md`](Vulnerability_Management_Program%20_Implementation/README.md) for detailed workflow.

---

### 3. 📊 Threat Hunting Projects

**Location:** `Threat_Hunting_Projects/`

**Purpose:** Real-world threat hunting case studies and CTF scenarios demonstrating MITRE ATT&CK framework application.

**Current Projects:**

#### 🚨 Hide Your RDP: Password Spray Leads to Full Compromise
- **Date Completed:** 2025-09-08
- **Techniques:** T1110.001 (Password Spraying), T1078 (Valid Accounts), T1053.005 (Scheduled Tasks), T1562.001 (Defense Evasion)
- **Frameworks:** MITRE ATT&CK, NIST 800-61
- **Analysis:** Diamond Model, timeline reconstruction, IOC extraction

**Key Features:**
- Comprehensive attack chain analysis
- MITRE ATT&CK technique mapping
- Remediation recommendations
- IOC documentation
- Timeline reconstruction

**Use Cases:**
- SOC analyst training
- Incident response exercises
- Threat hunting skill development
- CTF competition practice

---

### 4. ⚙️ STIGS (Security Technical Implementation Guides)

**Location:** `STIGS/`

**Purpose:** Security compliance automation scripts for implementing DISA STIG configurations.

**Key Features:**
- ✅ PowerShell automation scripts
- ✅ Windows security hardening
- ✅ Audit configuration compliance
- ✅ Automated STIG implementation

**Example:** `WN10-AU-000500.ps1` - Windows 10 audit policy configuration

**Use Cases:**
- Security compliance automation
- Baseline security configuration
- Audit policy enforcement
- Regulatory compliance

---

## 🚀 Getting Started

### Prerequisites

- **Python 3.9+** (for AI Agentic SOC Analyst)
- **Azure CLI** (for Log Analytics access)
- **Ollama** (optional, for local LLM models)
- **Tenable/ Nessus** (for Vulnerability Management)
- **PowerShell 5.1+** (for STIG scripts)

### Quick Start Guide

#### 1. AI-Powered Threat Detection

```bash
cd openAI_Agentic_SOC_Analyst
pip install -r requirements.txt
python _main.py
```

See [`openAI_Agentic_SOC_Analyst/README.md`](openAI_Agentic_SOC_Analyst/README.md) for detailed setup.

#### 2. Vulnerability Management Program

```bash
cd "Vulnerability_Management_Program _Implementation"
# Follow the README.md for step-by-step implementation
```

#### 3. Threat Hunting Exercises

```bash
cd Threat_Hunting_Projects
# Review case studies and follow documented methodologies
```

#### 4. STIG Implementation

```bash
cd STIGS
# Execute PowerShell scripts with appropriate permissions
```

---

## 💡 Use Cases

### Complete SOC Transformation

This repository enables organizations to:

1. **Automate Threat Detection**
   - Deploy AI-powered hunting agents
   - Reduce false positives through learning
   - Scale threat hunting operations

2. **Establish Vulnerability Management**
   - Create formal policies and procedures
   - Implement automated scanning and remediation
   - Build stakeholder buy-in and approval workflows

3. **Train SOC Teams**
   - Practice on real-world attack scenarios
   - Learn MITRE ATT&CK framework application
   - Develop incident response skills

4. **Ensure Compliance**
   - Automate STIG implementation
   - Maintain security baselines
   - Document compliance efforts

### Integration Scenarios

**Scenario 1: Detection → Response Pipeline**
```
AI Agent detects threat → Threat Hunting Project analysis → Vulnerability Management remediation
```

**Scenario 2: Proactive Security**
```
Vulnerability scan identifies issues → STIG scripts harden systems → AI agent monitors for anomalies
```

**Scenario 3: Training & Development**
```
Threat Hunting Projects → Learn techniques → Apply in AI Agent → Verify with Vulnerability Management
```

---

## 🏛️ Architecture & Design Philosophy

### Core Principles

1. **Hybrid Intelligence**
   - Combines rule-based detection with AI/LLM analysis
   - Leverages strengths of both approaches
   - Balances speed, accuracy, and explainability

2. **Self-Learning Systems**
   - Adapts to environment and user feedback
   - Improves over time without manual tuning
   - Transparent learning mechanisms

3. **End-to-End Automation**
   - From detection to remediation
   - Minimal manual intervention
   - Scalable operations

4. **Privacy Preservation**
   - Local model support
   - Offline operation capabilities
   - Data sovereignty considerations

5. **Standards Alignment**
   - MITRE ATT&CK framework integration
   - NIST 800-61 incident response alignment
   - DISA STIG compliance

### Technology Stack

- **AI/ML:** OpenAI API, Ollama (local LLMs), Transformer models
- **Cloud:** Azure Log Analytics, Azure Virtual Machines
- **Security Tools:** Tenable/Nessus, Microsoft Defender for Endpoint
- **Automation:** PowerShell, Python, Bash
- **Frameworks:** MITRE ATT&CK, NIST 800-61, DISA STIGs

---

## 📊 Repository Statistics

- **4 Major Components** - Covering detection, management, hunting, and compliance
- **30+ Python Modules** - In AI Agentic SOC Analyst alone
- **165+ Threat Patterns** - Rule-based detection signatures
- **610+ MITRE ATT&CK Mappings** - Technique coverage
- **Multiple CTF Scenarios** - Real-world threat hunting exercises
- **Complete Vulnerability Lifecycle** - Policy to remediation

---

## 🤝 Contributing

Contributions are welcome! Areas of interest:

- **New Threat Patterns** - Additional detection signatures
- **CTF Scenarios** - More threat hunting case studies
- **STIG Scripts** - Additional compliance automation
- **Integration Workflows** - Connecting components together
- **Documentation** - Improvements and clarifications

---

## 📝 License

MIT License - See individual component README files for specific licensing details.

---

## 🔗 Related Documentation

- [AI Agentic SOC Analyst Documentation](openAI_Agentic_SOC_Analyst/README.md)
- [Vulnerability Management Program Guide](Vulnerability_Management_Program%20_Implementation/README.md)
- [Threat Hunting Projects](Threat_Hunting_Projects/)

---

## 🎓 Learning Path

### Beginner
1. Start with Threat Hunting Projects to understand attack patterns
2. Review Vulnerability Management Program workflow
3. Explore STIG scripts for security hardening

### Intermediate
1. Deploy AI Agentic SOC Analyst in a lab environment
2. Run CTF Mode exercises
3. Implement vulnerability management program

### Advanced
1. Customize threat detection patterns
2. Integrate components into unified SOC operations
3. Extend with additional data sources and frameworks

---

## ⚠️ Important Notes

- **Environment:** This repository is designed for research and educational purposes
- **Credentials:** Keep API keys and credentials secure (see `_keys.py.example`)
- **Data Sensitivity:** Be mindful of log data and security event information
- **Compliance:** Ensure compliance with your organization's security policies
- **Testing:** Test all components in isolated environments before production deployment

---

## 🌟 Key Achievements

- ✅ **80% Vulnerability Reduction** - Demonstrated through vulnerability management program
- ✅ **Self-Learning System** - AI agent improves detection accuracy over time
- ✅ **Complete Attack Chain Analysis** - From initial access to exfiltration
- ✅ **Multi-Modal Detection** - Rule-based + AI + Behavioral baseline
- ✅ **End-to-End Automation** - Policy → Detection → Remediation

---

**Built with ❤️ for SOC analysts, security researchers, and cybersecurity professionals**

*This repository represents a comprehensive approach to modern SOC operations, combining AI-powered detection, vulnerability management, threat hunting expertise, and security compliance automation.*
