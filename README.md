# Threat Defense System - Project Structure

## Current Structure

### 📁 **agents/** - Multi-Agent System Components

Contains the core intelligent agents that form the backbone of the threat detection pipeline:

- **classification/** - Machine Learning agent that classifies security events and assigns threat severity scores
- **log_ingestor/** - Log Ingestor Agent that ingests, parses, and normalizes security logs from various sources (systems, firewalls, etc.)
- **threat_hunter/** - Threat Hunting Agent that detects anomalies through pattern matching and baseline learning
- **response_coordinator/** - Response Coordinator Agent that orchestrates and executes automated remediation actions
- **threat_modeling/** - Threat Modeling Agent that performs attack path analysis, ranks risks, and integrates MITRE ATT&CK framework

**Purpose:** Each agent handles a specific stage of the threat detection and response pipeline, working together through message buses to provide intelligent security analysis.

---

### 📁 **data/** - Data Storage & Machine Learning Models

Contains training data, ML models, and security intelligence databases:

- **attack_patterns_for_training.py** - Training dataset for threat classification models
- **expanded_attack_patterns_for_training.py** - Extended attack patterns for improved model accuracy
- **modern_cves_for_testing.py** - Recently discovered CVE data for validation and testing
- **cvss_utils.py** - Utilities for CVSS severity scoring calculations
- **mitre/enterprise-attack.json** - Complete MITRE ATT&CK framework database (tactics, techniques)
- **models/** - Pre-trained ML models (`threat_classifier.pkl`, `threat_hunter.pkl`) and model definitions

**Purpose:** Provides all data assets needed for the agents to operate: training data for ML models, MITRE ATT&CK context for threat analysis, and CVSS utilities for vulnerability scoring.

---

### 📁 **shared/** - Cross-Agent Utilities

Contains shared services used by all agents:

- **communication/message_bus.py** - Inter-agent message communication system (agents use this to coordinate and share threat intelligence)
- **logging_config.py** - Centralized logging configuration ensuring consistent logging across all agents

**Purpose:** Provides the infrastructure for agent-to-agent communication and unified system logging.

---

### 📁 **vulnerability_enrichment/** - CVE Data Management

Handles integration with external vulnerability databases:

- **cve_fetcher.py** - Fetches latest CVE data from external sources (NVD, security databases)
- **cve_scheduler.py** - Schedules periodic automatic updates of CVE intelligence
- **test_api.py** - Tests connectivity and verifies CVE data source availability

**Purpose:** Keeps the system updated with the latest vulnerability information to improve threat detection accuracy.

---

## System Flow

```
Raw Security Logs
        ↓
   [Log Ingestor Agent]  → Normalizes and parses logs
        ↓
   [Classification Agent] → Categorizes threats & assigns severity
        ↓
   [Threat Hunter Agent]  → Detects anomalies via patterns
        ↓
   [Threat Modeling]      → Analyzes attack paths & risk ranking
        ↓
[Response Coordinator]    → Executes automated responses
        ↓
   Alert & Action Taken
```

---

## Key Technologies

- **Machine Learning:** ML agents for threat classification and behavior analysis
- **MITRE ATT&CK:** Framework for mapping detected techniques to known attack tactics
- **CVSS Scoring:** Standardized vulnerability severity assessment
- **Multi-Agent Architecture:** Event-driven agent system with message-based communication

---

## Dependencies

- Python 3.13+
- Machine learning libraries (scikit-learn, joblib)
- External APIs (NVD for CVE data)

---

_Created for 3rd Year Project - Cybersecurity Threat Defense System_
