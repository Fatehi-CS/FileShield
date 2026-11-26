# 🛡️ FileShield AI — Hybrid Static Malware & ML Threat Detector

**Developed by:** Fatehi Abdulfattah Mohammed Ali Alshami

## 📌 Overview
**FileShield AI** is a modular cybersecurity web application designed to detect malicious files prior to execution. It combines **Client-Side Static Feature Extraction**, a **Random Forest Ensemble Classifier**, and **Live Cloud Threat Intelligence** via the **abuse.ch MalwareBazaar API** and **VirusTotal Hash Cross-Verification**.

## 🏗️ System Architecture
1. **`feature_extractor.js` (Static Analysis Engine):**
   - Computes cryptographic **SHA-256** file hashes.
   - Calculates **Shannon Entropy** to detect packed, encrypted, or obfuscated payloads.
   - Performs **Magic Bytes Header Inspection** to catch extension spoofing (e.g., an executable disguised as a PDF).
   - Scans binary strings for dangerous system APIs (`VirtualAlloc`, `CreateRemoteThread`, `PowerShell`) and embedded C2 URLs.
2. **`ml_classifier.js` (Machine Learning & Threat Intel Engine):**
   - Implements a **Random Forest Decision Tree Ensemble** trained on static file heuristics to flag zero-day or unknown threats.
   - Queries the **MalwareBazaar REST API** in real time to identify known malware families.
3. **`index.html` (Presentation Layer):**
   - Responsive dark-mode UI providing instant risk verdicts, entropy metrics, and direct cross-verification links.
