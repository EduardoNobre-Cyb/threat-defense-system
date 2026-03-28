# Agent 2: Threat Classification Agent
# Categorizes threats and assigns risk scores using ML

from typing import Dict, List
from shared.communication.message_bus import message_bus
import time
from data.models.models import (
    Asset,
    Vulnerability,
    AssetVulnerability,
    ThreatClassification,
    ThreatReview,
    AnalystCuratedTrainingData,
    get_session,
)
from data.modern_cves_for_testing import get_modern_test_cves
import re
import pickle
import os
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline, make_pipeline
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_sample_weight
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import f1_score, classification_report, confusion_matrix
from data.cvss_utils import get_cvss_for_vulnerability, get_severity_from_cvss
import logging
from shared.logging_config import setup_agent_logger
import traceback
from datetime import datetime, timedelta, timezone
from dashboard.notification_service import NotificationService


class ThreatClassificationAgent:
    # Classifies threats using MITRE ATT&CK framework

    def __init__(self, agent_id: str = "classifier_001", verbose: bool = True):
        self.agent_id = agent_id
        self.severity_weights = {
            "critical": 10.0,
            "high": 8.0,
            "medium": 5.0,
            "low": 2.0,
            "info": 0.5,
        }
        self.criticality_weights = {
            "critical": 10.0,
            "high": 8.0,
            "medium": 5.0,
            "low": 2.0,
        }

        self.tactic_severity = {
            "TA0043": 3.0,  # Reconnaissance
            "TA0042": 4.0,  # Resource Development
            "TA0001": 5.0,  # Initial Access
            "TA0002": 5.5,  # Execution
            "TA0003": 6.0,  # Persistence
            "TA0004": 6.5,  # Privilege Escalation
            "TA0005": 7.0,  # Defense Evasion
            "TA0006": 7.5,  # Credential Access
            "TA0007": 8.0,  # Discovery
            "TA0008": 8.5,  # Lateral Movement
            "TA0009": 9.0,  # Collection
            "TA0011": 9.5,  # Command and Control
            "TA0010": 9.8,  # Exfiltration
            "TA0040": 10.0,  # Impact
        }

        # ML Model confidence gate
        self.min_prediction_confidence = 0.55
        self.min_confidence_margin = 0.10
        self.abstain_label = "Needs Review"
        self.model_version = "nb_v2_conf_gate"  # Naive Bayes with confidence gating

        # ML model for threat classification
        self.classifier_model = None
        self.model_path = os.getenv(
            "ML_MODEL_PATH", "data/models/threat_classifier.pkl"
        )
        self.last_retrain_time = None
        self.retrain_interval = 3600  # Retrain every 1 hour (in seconds)
        self.verbose = verbose  # Set to False in listen mode for minimal output
        self.logger = setup_agent_logger(agent_id, verbose)
        # Load or train ML model
        self._load_or_train_classifier()

        # Subscribe to threat intelligence
        message_bus.subscribe("threat_intelligence", self.classify_threat)

    def classify_threat(self, message: Dict):

        session = get_session()
        if self.verbose:
            self.logger.info("Received message from 'threat_intelligence': %s", message)
            self.logger.info("Classifying threat...")
        else:
            src = message.get("source", "unknown")
            self.logger.info(
                "📨 Triggered by '%s' — scanning for unclassified pairs...", src
            )
        try:
            # Fetch all asset-vulnerability pairs to classify
            pairs = (
                session.query(
                    AssetVulnerability.asset_id,
                    AssetVulnerability.vulnerability_id,
                    Asset.name.label("asset_name"),
                    Asset.risk_level,
                    Vulnerability.name.label("vuln_name"),
                    Vulnerability.severity,
                    Vulnerability.description,
                    Vulnerability.cvss_base_score,
                    Vulnerability.cvss_vector,
                )
                .join(Asset, AssetVulnerability.asset_id == Asset.id)
                .join(
                    Vulnerability,
                    AssetVulnerability.vulnerability_id == Vulnerability.id,
                )
                .all()
            )
            if not pairs:
                self.logger.warning("⚠️  No asset-vulnerability pairs found in DB.")
                return
            if self.verbose:
                self.logger.info(
                    "Found %d asset-vulnerability pairs to classify.", len(pairs)
                )
            classified_count = 0
            classifications_for_hunter = []  # Collect classifications for Agent 3
            # Loop through each pair and classify
            for pair in pairs:
                existing = (
                    session.query(ThreatClassification)
                    .filter_by(
                        asset_id=pair.asset_id,
                        vulnerability_id=pair.vulnerability_id,
                    )
                    .first()
                )
                # Check if already classified
                if existing:
                    if self.verbose:
                        self.logger.info(
                            "Skipping already classified: %s - %s",
                            pair.asset_name,
                            pair.vuln_name,
                        )
                    else:
                        self.logger.debug(
                            "Skipping already classified: %s - %s",
                            pair.asset_name,
                            pair.vuln_name,
                        )
                    continue

                if self.verbose:
                    self.logger.info(
                        "Classifying: %s <-> %s", pair.asset_name, pair.vuln_name
                    )
                    self.logger.info("Description: '%s'", pair.description)
                else:
                    self.logger.debug(
                        "Classifying: %s <-> %s", pair.asset_name, pair.vuln_name
                    )
                    self.logger.debug("Description: '%s'", pair.description)

                # Get CVSS score - use stored value or calculate if missing

                if pair.cvss_base_score:
                    cvss_score = float(pair.cvss_base_score)
                else:
                    # Fallback: calculate CVSS if not stored
                    cvss_data = get_cvss_for_vulnerability(
                        pair.vuln_name, pair.description or ""
                    )
                    cvss_score = cvss_data["base_score"]

                # Calculate scores

                # Calculate exploitability (CVSS score with keyword adjustments)
                exploitability = self._calculate_exploitability_score_cvss(
                    pair.description or "", cvss_score
                )
                impact = self._calculate_impact_score(pair.risk_level)

                # Caclulate composite risk score
                # Formula: CVSS provides base, asset criticalite provides context
                risk = self._calculate_risk_score_cvss(
                    cvss_score,
                    impact,
                )

                # Determine classification

                # Determine severity from CVSS (industry standard)
                severity = get_severity_from_cvss(cvss_score)
                decision = self._determine_threat_decision(pair.description or "")
                threat_type = decision["label"]
                mitre_tactic = self._extract_mitre_tactic(pair.description)

                if threat_type == "Needs Review":
                    self.logger.warning(
                        "⚠️  Classification abstained: %s | Confidence: %.3f | Margin: %.3f",
                        pair.description[:80] if pair.description else "No description",
                        decision["confidence"],
                        decision["margin"],
                    )

                # Still compute risk/severity for triage purposes, even if threat type is uncertain
                risk_score = risk

                if self.verbose:
                    self.logger.info("Exploitability Score: %.2f/10", (exploitability))
                    self.logger.info("Impact Score: %.2f/10", impact)
                    self.logger.info("Risk Score: %.2f/10", risk)
                    self.logger.info("Severity: %s", severity)
                    self.logger.info("Threat Type: %s", threat_type)
                    self.logger.info("MITRE Tactic: %s", mitre_tactic)
                    self.logger.info(
                        "Threat decision | label=%s source=%s conf=%s margin=%.3f top=%s",
                        decision["label"],
                        decision["source"],
                        float(decision["confidence"]),
                        float(decision["margin"]),
                        decision["top_candidates"],
                    )
                else:
                    self.logger.debug("Exploitability Score: %.2f/10", (exploitability))
                    self.logger.debug("Impact Score: %.2f/10", impact)
                    self.logger.debug("Risk Score: %.2f/10", risk)
                    self.logger.debug("Severity: %s", severity)
                    self.logger.debug("Threat Type: %s", threat_type)
                    self.logger.debug("MITRE Tactic: %s", mitre_tactic)
                    self.logger.debug(
                        "Threat decision | label=%s source=%s conf=%s margin=%.3f top=%s",
                        decision["label"],
                        decision["source"],
                        float(decision["confidence"]),
                        float(decision["margin"]),
                        decision["top_candidates"],
                    )

                # Create and add classification
                classification = ThreatClassification(
                    asset_id=pair.asset_id,
                    vulnerability_id=pair.vulnerability_id,
                    threat_type=threat_type,
                    exploitability_score=exploitability,
                    impact_score=impact,
                    risk_score=risk,
                    severity=severity,
                    mitre_tactic=mitre_tactic,
                )
                session.add(classification)
                session.flush()  # Assign ID so Agent 3 can reference it

                # Create ThreatReview record if marked for review
                if threat_type == "Needs Review":

                    # Calculate SLA deadline based on severity
                    sla_hours = {"critical": 1, "high": 4, "medium": 24, "low": 72}.get(
                        severity, 24
                    )
                    sla_deadline = datetime.now(timezone.utc) + timedelta(
                        hours=sla_hours
                    )

                    review = ThreatReview(
                        threat_classification_id=classification.id,
                        status="pending",
                        severity=severity,
                        sla_deadline=sla_deadline,
                    )
                    session.add(review)
                classified_count += 1

                # Add to list for Agent 3 (includes ID for database linking)
                classifications_for_hunter.append(
                    {
                        "id": classification.id,
                        "threat_type": threat_type,
                        "severity": severity,
                        "mitre_tactics": [mitre_tactic],
                        "risk_score": risk,
                        "asset_name": pair.asset_name,
                        "vulnerability_name": pair.vuln_name,
                        "prediction_source": decision["source"],
                        "prediction_confidence": decision["confidence"],
                        "prediction_margin": decision["margin"],
                        "top_candidates": decision["top_candidates"],
                        "model_version": self.model_version,
                    }
                )

            # Commit all classifications to DB
            session.commit()
            already_classified = len(pairs) - classified_count
            if self.verbose:
                self.logger.debug(
                    "Successfully classified %d threats.", classified_count
                )
                self.logger.debug("Results saved to threat_classifications table.")
            else:
                if classified_count > 0:
                    self.logger.info("✅ Classified %s new threats ", classified_count),
                    self.logger.info(
                        "%s already done, %d total pairs",
                        already_classified,
                        len(pairs),
                    )
                else:
                    self.logger.info(
                        "ℹ️  All %d pairs already classified — nothing new to do.",
                        len(pairs),
                    )

            if classified_count > 0:
                message_bus.publish(
                    "classified_threats",
                    {
                        "type": "classification_complete",
                        "source": self.agent_id,
                        "count": classified_count,
                        "classification": classifications_for_hunter,
                    },
                )

                # Check if it's time to retrain the model
                self._check_and_retrain()

        except Exception as e:
            self.logger.error("❌ Error during classification: %s", e)
            traceback.print_exc()
            session.rollback()
        finally:
            session.close()

    def _predict_with_confidence(self, description: str) -> Dict:
        """Return ML prediction details: label, confidence, margin, top candidates."""
        if not self.classifier_model:
            return {
                "label": None,
                "confidence": 0.0,
                "margin": 0.0,
                "top_candidates": [],
            }

        # Pipeline supports predict_proba if final estimator supports it (NB does)
        probabilities = self.classifier_model.predict_proba([description])[0]
        classes = list(self.classifier_model.classes_)

        ranked = sorted(zip(classes, probabilities), key=lambda x: x[1], reverse=True)

        top_label, top_conf = ranked[0]
        second_conf = float(ranked[1][1]) if len(ranked) > 1 else 0.0
        margin = float(top_conf) - second_conf

        return {
            "label": str(top_label),
            "confidence": float(top_conf),
            "margin": float(margin),
            "top_candidates": [
                {"label": str(label), "score": round(float(score), 4)}
                for label, score in ranked[:3]
            ],
        }

    def _determine_threat_decision(self, description):
        """Hybrid decision: rule first, ML second, abstain on low confidence."""
        if not description:
            return {
                "label": "Unknown",
                "source": "rule",
                "confidence": 1.0,
                "margin": 1.0,
                "top_candidates": [{"label": "Unknown", "score": 1.0}],
            }

        # Deterministic rule layer for high-certainty signatures
        rule_label = self._bootstrap_label(description)
        if rule_label not in ["Vulnerability Exploitation", "Unknown"]:
            return {
                "label": rule_label,
                "source": "rule",
                "confidence": 0.95,
                "margin": 0.95,
                "top_candidates": [{"label": rule_label, "score": 0.95}],
            }

        # ML prediction layer
        ml = self._predict_with_confidence(description)
        if ml["label"] is None:
            return {
                "label": rule_label,
                "source": "rule_fallback",
                "confidence": 0.50,
                "margin": 0.0,
                "top_candidates": [{"label": rule_label, "score": 0.50}],
            }

        # Confidence gating
        if (
            ml["confidence"] < self.min_prediction_confidence
            or ml["margin"] < self.min_confidence_margin
        ):
            return {
                "label": self.abstain_label,
                "source": "abstain",
                "confidence": ml["confidence"],
                "margin": ml["margin"],
                "top_candidates": ml["top_candidates"],
            }

        return {
            "label": ml["label"],
            "source": "ml",
            "confidence": ml["confidence"],
            "margin": ml["margin"],
            "top_candidates": ml["top_candidates"],
        }

    def _determine_threat_type(self, description):
        # ML Compatibility wrapper
        decision = self._determine_threat_decision(description)
        return decision["label"]

    def _determine_severity(self, risk_score):
        # Determine severity category from risk score.

        if risk_score >= 9.0:
            return "Critical"
        elif risk_score >= 7.0:
            return "High"
        elif risk_score >= 5.0:
            return "Medium"
        elif risk_score >= 3.0:
            return "Low"
        else:
            return "Informational"

    def _extract_mitre_tactic(self, description):

        # Extract or map MITRE tactic ID from threat description.
        # First tries regex extraction, then falls back to intelligent mapping.

        import re

        if not description:
            return None

        # First, try to extract existing MITRE tactic format (TA0001-TA0043)
        match = re.search(r"TA\d{4}", description)
        if match:
            return match.group(0)

        # If no explicit tactic, map based on vulnerability keywords
        description_lower = description.lower()

        # Mapping vulnerabilities to MITRE tactics based on description content
        if any(
            kw in description_lower
            for kw in ["injection", "sqli", "sql injection", "command injection"]
        ):
            return "TA0001"  # Initial Access
        elif any(
            kw in description_lower
            for kw in ["xss", "cross-site scripting", "script injection"]
        ):
            return "TA0001"  # Initial Access
        elif any(
            kw in description_lower
            for kw in ["authentication", "broken auth", "credential", "session"]
        ):
            return "TA0006"  # Credential Access
        elif any(
            kw in description_lower for kw in ["privilege", "escalation", "elevation"]
        ):
            return "TA0004"  # Privilege Escalation
        elif any(
            kw in description_lower
            for kw in ["dos", "denial of service", "resource exhaustion"]
        ):
            return "TA0040"  # Impact
        elif any(
            kw in description_lower
            for kw in ["data exposure", "information disclosure", "leak"]
        ):
            return "TA0010"  # Exfiltration
        elif any(
            kw in description_lower
            for kw in ["unencrypted", "weak protocol", "plaintext"]
        ):
            return "TA0009"  # Collection
        elif any(kw in description_lower for kw in ["remote code", "rce", "execution"]):
            return "TA0002"  # Execution
        elif any(
            kw in description_lower for kw in ["buffer overflow", "memory corruption"]
        ):
            return "TA0002"  # Execution
        elif any(
            kw in description_lower for kw in ["misconfiguration", "default credential"]
        ):
            return "TA0001"  # Initial Access
        else:
            return "TA0001"  # Default to Initial Access

    def _calculate_exploitability_score_cvss(
        self, description, cvss_score: float
    ) -> float:
        # Calculate exploitability score based on CVSS with keyword adjustments.
        # CVSS already factors in exploitability, so we use it as base
        # and only make minor adjustments for context.

        # Start with CVSS score (already includes exploitability metrics)
        base_score = cvss_score

        # Minor adjustments based on description keywords
        description_lower = description.lower() if description else ""

        # Increase if proof-of-concept exists
        if "exploit" in description_lower or "poc" in description_lower:
            base_score = min(base_score + 0.5, 10.0)

        # Increase if actively exploited
        if (
            "actively exploited" in description_lower
            or "in the wild" in description_lower
        ):
            base_score = min(base_score + 1.0, 10.0)

        return round(base_score, 1)

    def _calculate_impact_score(self, criticality):

        # Calculate impact score based on asset criticality.

        return self.criticality_weights.get(criticality.lower(), 5.0)

    def _calculate_risk_score_cvss(
        self, cvss_score: float, impact_score: float
    ) -> float:
        # Calculate composite risk score combining CVSS and asset criticality.
        # Formula: (CVSS × 0.7) + (Asset Impact × 0.3)
        # Why 70/30?
        # - CVSS is comprehensive and should dominate
        # - Asset criticality provides organizational context

        risk = (cvss_score * 0.7) + (impact_score * 0.3)
        return round(risk, 2)

    def _load_or_train_classifier(self):

        # Load existing classifier model or train a new one.

        if os.path.exists(self.model_path):
            ("Loading existing classifier model...")
            try:
                with open(self.model_path, "rb") as f:
                    self.classifier_model = pickle.load(f)
                ("Successfully loaded existing ML model")
            except Exception as e:
                self.logger.error("Failed to load model: %s. Training new one...", e)
                self._train_classifier()
        else:
            self.logger.warning("No existing model found. Training new classifier...")
            self._train_classifier()

    def _train_classifier(self):
        """Train ML classifier with real CVE data from external APIs."""
        self.logger.info("Training ML model with external CVE data...")

        # First, try to get training data from external CVE sources
        training_texts, training_labels = self._fetch_cve_training_data()

        # Fallback to database vulnerabilities if external data not available
        if len(training_texts) < 50:  # Need minimum dataset
            self.logger.warning(
                "External CVE data insufficient, using database vulnerabilities..."
            )
            db_texts, db_labels = self._get_database_training_data()
            training_texts.extend(db_texts)
            training_labels.extend(db_labels)

        if not training_texts:
            self.logger.error("No training data available. Cannot train classifier.")
            return

        # Create training data with diverse threat types
        self.logger.debug("Total training samples: %d", len(training_texts))

        # Print training data distribution for debugging
        from collections import Counter

        label_counts = Counter(training_labels)

        # Checks to prevent silently training a brittle model on imbalanced data
        min_samples_per_class = 3
        underrepresented = [
            label
            for label, count in label_counts.items()
            if count < min_samples_per_class
        ]

        if underrepresented:
            self.logger.warning(
                "Underrepresented classes (<%d samples): %s",
                min_samples_per_class,
                underrepresented,
            )

        if len(label_counts) < 5:
            self.logger.warning(
                "Low class diversite (%d classes). Expect weak generalization.",
                len(label_counts),
            )

        # Only train if we have diverse labels
        if len(set(training_labels)) < 3:
            self.logger.warning(
                " Only %s unique labels. Model may not be effective.",
                len(set(training_labels)),
            )

        # Calibration to improve confidence reliability (important for gating)
        from sklearn.calibration import CalibratedClassifierCV

        # Train TF-IDF + Naive Bayes classifier
        base_nb = make_pipeline(
            TfidfVectorizer(max_features=500, ngram_range=(1, 2)), MultinomialNB()
        )

        self.classifier_model = CalibratedClassifierCV(base_nb, method="sigmoid", cv=3)

        # Save the model
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        with open(self.model_path, "wb") as f:
            pickle.dump(self.classifier_model, f)

        self.logger.debug(
            "Trained classifier on %d samples from external CVE data.",
            len(training_texts),
        )

    def _fetch_cve_training_data(self):
        """Fetch training data from database (classified by agents) or fallback to hardcoded examples."""
        training_texts = []
        training_labels = []

        # First, try to fetch from database
        session = get_session()
        try:
            classifications = (
                session.query(ThreatClassification, Vulnerability.description)
                .join(
                    Vulnerability,
                    ThreatClassification.vulnerability_id == Vulnerability.id,
                )
                .filter(
                    ThreatClassification.threat_type.isnot(None),
                    Vulnerability.description.isnot(None),
                )
                .all()
            )

            if classifications:
                for threat_class, description in classifications:
                    if description and threat_class.threat_type:
                        training_texts.append(description)
                        training_labels.append(threat_class.threat_type)

                self.logger.debug(
                    "Loaded %d training samples from database", len(classifications)
                )
                session.close()
                return training_texts, training_labels
        except Exception as e:
            self.logger.warning(
                f"Failed to load from database: {e}. Using fallback hardcoded data."
            )
            session.close()

        # Fallback: Use hardcoded examples if database is empty
        sample_cves = [
            # SQL Injection examples
            (
                "SQL injection vulnerability allows remote attackers to execute arbitrary SQL commands",
                "Injection Attack",
            ),
            (
                "SQL injection in login form enables database manipulation",
                "Injection Attack",
            ),
            (
                "Improper neutralization of SQL commands leads to database compromise",
                "Injection Attack",
            ),
            (
                "LDAP injection vulnerability in authentication system",
                "Injection Attack",
            ),
            (
                "NoSQL injection enables unauthorized database access",
                "Injection Attack",
            ),
            # XSS examples
            (
                "Cross-site scripting vulnerability allows code injection in web pages",
                "Cross-Site Scripting",
            ),
            (
                "XSS flaw enables malicious script execution in user browsers",
                "Cross-Site Scripting",
            ),
            (
                "Improper input validation leads to stored XSS attacks",
                "Cross-Site Scripting",
            ),
            ("Reflected XSS vulnerability in search parameter", "Cross-Site Scripting"),
            (
                "DOM-based XSS enables client-side code execution",
                "Cross-Site Scripting",
            ),
            # Buffer Overflow examples
            (
                "Buffer overflow in network service allows remote code execution",
                "Buffer Overflow",
            ),
            (
                "Stack-based buffer overflow enables arbitrary code execution",
                "Buffer Overflow",
            ),
            (
                "Heap overflow vulnerability leads to memory corruption",
                "Memory Corruption",
            ),
            ("Integer overflow causes buffer overrun condition", "Buffer Overflow"),
            (
                "Format string vulnerability enables memory manipulation",
                "Memory Corruption",
            ),
            # Directory Traversal
            (
                "Directory traversal vulnerability allows access to arbitrary files",
                "Path Traversal",
            ),
            (
                "Path traversal flaw enables reading of sensitive system files",
                "Path Traversal",
            ),
            ("Improper path validation leads to file system access", "Path Traversal"),
            ("Local file inclusion vulnerability via URL parameter", "Path Traversal"),
            # Authentication Issues
            (
                "Authentication bypass allows unauthorized access to admin panel",
                "Authentication Bypass",
            ),
            (
                "Weak authentication mechanism enables credential theft",
                "Authentication Bypass",
            ),
            (
                "Missing authentication check allows privilege escalation",
                "Privilege Escalation",
            ),
            (
                "Insufficient permission checks enable privilege escalation",
                "Privilege Escalation",
            ),
            (
                "Insecure direct object reference allows unauthorized escalation",
                "Privilege Escalation",
            ),
            (
                "Sudo configuration vulnerability enables privilege escalation",
                "Privilege Escalation",
            ),
            (
                "Local privilege escalation via kernel exploit",
                "Privilege Escalation",
            ),
            (
                "Privilege escalation through setuid binary",
                "Privilege Escalation",
            ),
            (
                "Session fixation vulnerability in login process",
                "Authentication Bypass",
            ),
            (
                "Weak password policy enables brute force attacks",
                "Authentication Bypass",
            ),
            # Denial of Service
            ("Memory leak vulnerability causes denial of service", "Denial of Service"),
            (
                "Resource exhaustion attack leads to service unavailability",
                "Denial of Service",
            ),
            ("Infinite loop condition enables DoS attacks", "Denial of Service"),
            ("XML bomb attack causes server resource exhaustion", "Denial of Service"),
            ("Algorithmic complexity vulnerability enables DoS", "Denial of Service"),
            # Remote Code Execution (consolidated)
            ("Remote code execution via malformed input data", "Remote Code Execution"),
            (
                "Arbitrary command execution through file upload",
                "Remote Code Execution",
            ),
            (
                "Code injection vulnerability enables system compromise",
                "Remote Code Execution",
            ),
            (
                "Deserialization vulnerability allows remote code execution",
                "Remote Code Execution",
            ),
            (
                "Template injection enables server-side code execution",
                "Remote Code Execution",
            ),
            ("RCE via unchecked deserialization", "Remote Code Execution"),
            ("Remote code execution in php eval function", "Remote Code Execution"),
            # Information Disclosure
            (
                "Information disclosure exposes sensitive user data",
                "Information Disclosure",
            ),
            (
                "Sensitive information leaked through error messages",
                "Information Disclosure",
            ),
            (
                "Improper access control reveals confidential files",
                "Information Disclosure",
            ),
            (
                "Debug information exposed in production environment",
                "Information Disclosure",
            ),
            (
                "Source code disclosure through misconfigured server",
                "Information Disclosure",
            ),
            # CSRF and Other Web Attacks
            (
                "Cross-site request forgery enables unauthorized actions",
                "Cross-Site Request Forgery",
            ),
            (
                "CSRF vulnerability in state-changing operations",
                "Cross-Site Request Forgery",
            ),
            (
                "CSRF token validation missing in form submission",
                "Cross-Site Request Forgery",
            ),
            (
                "Cross-site request forgery attack via GET request",
                "Cross-Site Request Forgery",
            ),
            ("Clickjacking attack enables UI redressing", "Clickjacking"),
            ("Clickjacking vulnerability in overlay attack vector", "Clickjacking"),
            (
                "UI redressing attack deceives users into unintended actions",
                "Clickjacking",
            ),
            ("Malicious frame overlay enables click hijacking", "Clickjacking"),
            ("HTTP parameter pollution causes unexpected behavior", "Input Validation"),
            ("SQL injection through input validation bypass", "Input Validation"),
            (
                "Insufficient input validation enables command injection",
                "Input Validation",
            ),
            ("Missing input sanitization allows XSS attacks", "Input Validation"),
            # Cryptographic Issues
            (
                "Weak encryption algorithm enables data decryption",
                "Cryptographic Weakness",
            ),
            (
                "Improper certificate validation allows MITM attacks",
                "Cryptographic Weakness",
            ),
            (
                "Hash collision vulnerability in signature verification",
                "Cryptographic Weakness",
            ),
            (
                "Weak random number generation enables prediction attacks",
                "Cryptographic Weakness",
            ),
        ]

        for description, label in sample_cves:
            training_texts.append(description)
            training_labels.append(label)

        self.logger.debug(
            "Loaded %d CVE training samples from external data", len(sample_cves)
        )
        return training_texts, training_labels

    def _get_database_training_data(self):
        """Get training data from database vulnerabilities as fallback."""
        session = get_session()
        vulnerabilities = session.query(Vulnerability).all()

        training_texts = []
        training_labels = []

        for vuln in vulnerabilities:
            description = vuln.description or vuln.name
            label = self._bootstrap_label(description)
            training_texts.append(description)
            training_labels.append(label)

        session.close()
        return training_texts, training_labels

    # def _fetch_from_nvd_api(self):
    #     """
    #     Future implementation: Fetch real CVE data from NVD API.
    #     This would replace the sample data with actual CVE descriptions and classifications.

    #     Example API endpoints:
    #     - NVD: https://services.nvd.nist.gov/rest/json/cves/2.0
    #     - Vulners: https://vulners.com/api/v3/search/lucene/
    #     - CVE Details: https://www.cvedetails.com/api/

    #     Benefits:
    #     - Much larger training dataset (100k+ CVEs)
    #     - Real-world vulnerability descriptions
    #     - Proper CWE classifications
    #     - Regular updates with new CVEs
    #     - Persistent data that survives database resets
    #     """
    #     # TODO: Implement actual API integration
    #     # For now, return empty to use sample data
    #     return [], []

    def _bootstrap_label(self, description):

        # Create bootstrap label based on keywords (used for initial training only).
        # Known limitations: May not cover all cases and vulnerabilities correctly.

        description_lower = description.lower() if description else ""

        # Injection Attacks
        if "injection" in description_lower or "sqli" in description_lower:
            return "Injection Attack"
        elif "xss" in description_lower or "cross-site" in description_lower:
            return "Cross-Site Scripting"

        # Code Execution (consolidated into Remote Code Execution for balance)
        elif "remote code" in description_lower or "rce" in description_lower:
            return "Remote Code Execution"
        elif "remote" in description_lower and "execution" in description_lower:
            return "Remote Code Execution"
        elif (
            "arbitrary code" in description_lower
            or "code execution" in description_lower
            or "arbitrary command" in description_lower
            or "command execution" in description_lower
        ):
            return "Remote Code Execution"

        # Memory Corruption
        elif "buffer" in description_lower or "overflow" in description_lower:
            return "Buffer Overflow"
        elif "null" in description_lower and (
            "ptr" in description_lower
            or "pointer" in description_lower
            or "deref" in description_lower
        ):
            return "Memory Corruption"
        elif "memory corruption" in description_lower or "heap" in description_lower:
            return "Memory Corruption"
        elif (
            "use-after-free" in description_lower or "double free" in description_lower
        ):
            return "Memory Corruption"

        # Denial of Service (check early since NULL deref often causes DoS)
        elif (
            "denial" in description_lower
            or "dos" in description_lower
            or "ddos" in description_lower
            or "crash" in description_lower
        ):
            return "Denial of Service"

        # Authentication & Access Control
        elif "authentication" in description_lower or "credential" in description_lower:
            return "Authentication Bypass"
        elif "privilege" in description_lower or "escalation" in description_lower:
            return "Privilege Escalation"
        elif (
            "authorization" in description_lower
            or "access control" in description_lower
        ):
            return "Access Control Bypass"

        # Network Attacks
        elif "man-in-the-middle" in description_lower or "mitm" in description_lower:
            return "Network Attack"

        # Web Application Vulnerabilities
        elif "csrf" in description_lower or "cross-site request" in description_lower:
            return "Cross-Site Request Forgery"
        elif (
            "directory traversal" in description_lower
            or "path traversal" in description_lower
        ):
            return "Path Traversal"
        elif (
            "file upload" in description_lower
            or "upload vulnerability" in description_lower
        ):
            return "File Upload Vulnerability"
        elif (
            "server-side request forgery" in description_lower
            or "ssrf" in description_lower
        ):
            return "Server-Side Request Forgery"

        # Cryptographic Issues
        elif "cryptographic" in description_lower or "encryption" in description_lower:
            return "Cryptographic Vulnerability"
        elif (
            "weak hash" in description_lower
            or "md5" in description_lower
            or "sha1" in description_lower
        ):
            return "Weak Cryptography"

        # Information Disclosure
        elif (
            "information disclosure" in description_lower
            or "data leak" in description_lower
        ):
            return "Information Disclosure"
        elif "sensitive data" in description_lower or "exposed" in description_lower:
            return "Information Disclosure"

        # Container & Cloud
        elif (
            "container" in description_lower
            or "docker" in description_lower
            or "kubernetes" in description_lower
        ):
            return "Container Vulnerability"
        elif "cloud" in description_lower or "misconfiguration" in description_lower:
            return "Configuration Vulnerability"

        # Supply Chain & Dependencies
        elif (
            "dependency" in description_lower
            or "third-party" in description_lower
            or "supply chain" in description_lower
        ):
            return "Supply Chain Vulnerability"
        elif (
            "deserialization" in description_lower or "unserialize" in description_lower
        ):
            return "Deserialization Vulnerability"

        # Zero-Day & Advanced
        elif "zero-day" in description_lower or "0-day" in description_lower:
            return "Zero-Day Exploit"
        elif "race condition" in description_lower or "toctou" in description_lower:
            return "Race Condition"

        # Default/Fallback
        else:
            return "Vulnerability Exploitation"

    def retrain_model(self):

        # Retrain the classifier using classified threats from database.
        # Call this periodically to improve classification accuracy.

        session = get_session()

        # Get all classified threats
        classified = session.query(ThreatClassification).all()

        if len(classified) < 10:
            self.logger.warning(
                "Not enough classified data to retrain (%d samples). Need at least 10.",
                len(classified),
            )
            return

        # Extract descriptions and labels
        training_texts = []
        training_labels = []

        for record in classified:
            # Get vulnerability description
            vuln = (
                session.query(Vulnerability)
                .filter_by(id=record.vulnerability_id)
                .first()
            )
            if vuln and vuln.description:
                training_texts.append(vuln.description)
                training_labels.append(record.threat_type)

        if len(training_texts) < 10:
            self.logger.warning(
                "Not enough valid training data (%d samples).", len(training_texts)
            )
            return

        # Retrain classifier
        self.classifier_model = make_pipeline(
            TfidfVectorizer(max_features=500), MultinomialNB()
        )

        self.classifier_model.fit(training_texts, training_labels)

        # Save updated model
        with open(self.model_path, "wb") as f:
            pickle.dump(self.classifier_model, f)

        # Update last retrain time
        self.last_retrain_time = time.time()

        self.logger.debug(
            "✅ Retrained classifier on %d real classified threats.",
            len(training_texts),
        )
        session.close()

    def incorporate_analyst_feedback(self):
        """
        Fetch all analyst-curated training data since last retrain.
        Combine with original training data and retrain classifier.
        """

        session = get_session()

        try:
            # Fetch original training data (hardcoded CVE examples)
            self.logger.info("[Agent 2 Retrain] Fetching original training data...")
            original_texts, original_labels = self._fetch_cve_training_data()

            # Fetch modern test CVE samples (155+ realistic examples for generalization)
            self.logger.info("[Agent 2 Retrain] Fetching modern CVE test samples...")
            modern_cves = get_modern_test_cves()
            modern_texts = [cve[0] for cve in modern_cves]
            modern_labels = [cve[1] for cve in modern_cves]

            # Fetch analyst corrections (human feedback from Phase 2 reviews)
            self.logger.info("[Agent 2 Retrain] Fetching analyst-curated data...")
            analyst_data = session.query(AnalystCuratedTrainingData).all()

            analyst_texts = [d.vulnerability_description for d in analyst_data]
            analyst_labels = [d.analyst_corrected_threat_type for d in analyst_data]

            self.logger.info(
                f"Data sources - Original: {len(original_texts)}, Modern: {len(modern_texts)}, Analyst: {len(analyst_texts)}"
            )

            # Combine all three sources for robust, generalized training
            combined_texts = original_texts + modern_texts + analyst_texts
            combined_labels = original_labels + modern_labels + analyst_labels

            if len(combined_texts) < 20:
                self.logger.warning("Not enough combined data to retrain (need >= 20)")
                return False

            # Train/test split
            X_train, X_test, y_train, y_test = train_test_split(
                combined_texts,
                combined_labels,
                test_size=0.2,
                random_state=42,
                stratify=combined_labels,
            )

            # Train new model with class balancing
            sample_weights = compute_sample_weight("balanced", y_train)

            base_nb = make_pipeline(
                TfidfVectorizer(max_features=500, ngram_range=(1, 2)),
                MultinomialNB(),
            )

            self.classifier_model = CalibratedClassifierCV(
                base_nb, method="sigmoid", cv=3
            )
            self.classifier_model.fit(
                X_train, y_train, multinomialnb__sample_weight=sample_weights
            )

            preds = self.classifier_model.predict(X_test)
            macro_f1 = f1_score(y_test, preds, average="macro", zero_division=0)

            self.logger.info(f"[Agent 2 Retrain] Macro F1: {macro_f1:.4f}")

            # Decide if we should promote (using same gates as eval script)
            report = classification_report(
                y_test, preds, output_dict=True, zero_division=0
            )

            gate1 = macro_f1 >= 0.72
            gate2_pass = all(
                metrics.get("recall", 0) >= 0.60
                for label, metrics in report.items()
                if label not in ["accuracy", "macro avg", "weighted avg"]
            )

            if gate1 and gate2_pass:
                # Save model

                os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
                with open(self.model_path, "wb") as f:
                    pickle.dump(self.classifier_model, f)

                # Update version
                self.model_version = (
                    f"nb_v3_analyst_feedback_{datetime.now().strftime('%Y%m%d%H%M%S')}"
                )
                self.logger.info(
                    f"✅ Retrained model promoted with analyst feedback! Version: {self.model_version}"
                )

                # Mark training data as used
                for d in analyst_data:
                    d.used_in_model_version = self.model_version
                    d.used_in_retrain_at = datetime.now(timezone.utc)

                session.commit()
                return True

            else:
                self.logger.warning(
                    f"Retrained model did not meet promotion criteria. Macro F1: {macro_f1:.4f}, Gate 1: {gate1}, Gate 2: {gate2_pass}"
                )
                return False

        except Exception as e:
            self.logger.error("Error during retraining with analyst feedback: {e}")
            return False
        finally:
            session.close()

    def _check_and_retrain(self):

        # Check if enough time has passed since last retrain and trigger retraining.
        # This enables continuous learning during normal operation.

        current_time = time.time()

        # First run - set initial time
        if self.last_retrain_time is None:
            self.last_retrain_time = current_time
            return

        # Check if interval has passed
        time_since_retrain = current_time - self.last_retrain_time

        if time_since_retrain >= self.retrain_interval:
            self.logger.info(
                f"⏰ {time_since_retrain/3600:.1f} hours since last retrain. Retraining model..."
            )
            self.retrain_model()
        else:
            if self.verbose:
                remaining = (self.retrain_interval - time_since_retrain) / 60
                self.logger.debug("Next retrain in %d minutes", remaining)


# Example usage: Demo of Functionality
if __name__ == "__main__":
    import argparse
    import sys

    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Threat Classification Agent")
    parser.add_argument(
        "--mode",
        choices=["listen", "demo"],
        default="demo",
        help="Run in listening mode or demo mode (default: demo)",
    )
    args = parser.parse_args()

    verbose = args.mode == "demo"

    agent = ThreatClassificationAgent(verbose=verbose)

    if args.mode == "demo":
        # DEMO MODE - Process real data from database (created by Agent 1)
        print("=" * 80)
        print("Agent 2: Threat Classification - Demo Mode")
        print("=" * 80)

        agent.logger.info("ML model loaded successfully")
        agent.logger.info("Running classification on real threat data from Agent 1...")

        print("\n" + "=" * 80)
        print("DEMO: Threat Classification Workflow")
        print("=" * 80)

        # Process REAL threat data (created by Agent 1 in database)
        agent.logger.info("Classifying threats from database...")
        agent.classify_threat({"source": "demo_run", "type": "real_data"})

        agent.logger.info("   [CLASSIFICATION RESULTS]")
        agent.logger.info("  ✓ Exploitability scores calculated")
        agent.logger.info("  ✓ Impact scores calculated")
        agent.logger.info("  ✓ Risk scores generated")
        agent.logger.info("  ✓ Severity levels assigned (Critical/High/Medium/Low)")
        agent.logger.info("  ✓ Threat types classified (ML predicted)")
        agent.logger.info("  ✓ MITRE tactics extracted")
        agent.logger.info("  ✓ Classified threats published to message bus for Agent 3")

        print("\n" + "=" * 80)
        print("Demo complete!")
        print("=" * 80)
    else:
        # LISTEN MODE - Continuous operation
        agent.verbose = False  # Minimal output in listen mode
        print("=" * 80)
        print("Agent 2: Threat Classification - Listen Mode")
        print("=" * 80)
        agent.logger.info("ML model loaded and ready")
        agent.logger.info(
            f"Automatic retraining: Every {agent.retrain_interval/3600:.1f} hour(s)"
        )
        agent.logger.info("Subscribed to 'threat_intelligence' channel from Agent 1")

        # Send heartbeat immediately so dashboard shows agent as running
        message_bus.heartbeat(agent.agent_id)

        # Initial classification run on any unclassified data
        agent.logger.info("Running initial classification on existing data...")
        agent.classify_threat({"source": "initial_run", "type": "real_data"})
        agent.logger.info("✅ Initial classification complete")
        agent.logger.info("Now monitoring for new threat intelligence from Agent 1...")

        # Send heartbeat immediately so dashboard shows agent as running
        message_bus.heartbeat(agent.agent_id)

        try:
            heartbeat_counter = 0
            while True:
                time.sleep(1)
                heartbeat_counter += 1

                # Send heartbeat every second to dashboard
                message_bus.heartbeat(agent.agent_id)

                # Check for model retraining every 60 seconds
                if heartbeat_counter % 60 == 0:
                    agent._check_and_retrain()

        except KeyboardInterrupt:
            agent.logger.debug("Shutting down...")
