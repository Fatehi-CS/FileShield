import hashlib
import numpy as np
from sklearn.ensemble import RandomForestClassifier

class FileShieldEngine:
    def __init__(self):
        self.model = self._train_ml_model()
        
        self.suspicious_patterns = [
            b"powershell", b"cmd.exe", b"eval(", b"exec(", b"base64_decode",
            b"CreateRemoteThread", b"VirtualAlloc", b"WriteProcessMemory",
            b"WScript.Shell", b"RegWrite", b"DownloadFile", b"Invoke-Expression",
            b"chmod +x", b"/bin/sh", b"AutoOpen", b"ShellExecute"
        ]

        self.executable_headers = {
            b"MZ": "Windows Executable (PE/EXE/DLL)",
            b"\x7fELF": "Linux Executable (ELF)",
            b"PK\x03\x04": "Archive / APK / DOCX (ZIP Container)",
            b"%PDF": "PDF Document",
            b"\xca\xfe\xba\xbe": "macOS Mach-O / Java Class"
        }

    def _train_ml_model(self):
        X_train = np.array([
            [3.2, 0, 0, 0.05],
            [4.5, 0, 0, 0.12],
            [5.1, 1, 0, 0.20],
            [6.2, 0, 1, 0.65],
            [5.8, 0, 0, 0.85],
            [7.8, 4, 1, 0.92],
            [7.5, 3, 0, 0.70],
            [6.9, 5, 1, 0.88],
            [7.9, 2, 1, 0.95],
            [4.1, 6, 0, 0.15],
        ])
        labels = [0, 0, 0, 0, 0, 1, 1, 1, 1, 1]
        y_train = np.array(labels)

        clf = RandomForestClassifier(n_estimators=100, random_state=42)
        clf.fit(X_train, y_train)
        return clf

    def calculate_sha256(self, file_bytes):
        return hashlib.sha256(file_bytes).hexdigest()

    def calculate_entropy(self, file_bytes):
        if not file_bytes:
            return 0.0
        byte_counts = np.bincount(np.frombuffer(file_bytes, dtype=np.uint8), minlength=256)
        probabilities = byte_counts[byte_counts > 0] / len(file_bytes)
        entropy = -np.sum(probabilities * np.log2(probabilities))
        return round(float(entropy), 3)

    def detect_file_type(self, file_bytes):
        for magic, desc in self.executable_headers.items():
            if file_bytes.startswith(magic):
                is_exec = 1 if magic in [b"MZ", b"\x7fELF", b"\xca\xfe\xba\xbe"] else 0
                return desc, is_exec
        return "Generic / Text / Unknown Format", 0

    def scan_patterns(self, file_bytes):
        lower_bytes = file_bytes.lower()
        found = []
        for pattern in self.suspicious_patterns:
            if pattern.lower() in lower_bytes:
                found.append(pattern.decode("utf-8", errors="ignore"))
        return found

    def analyze_file(self, filename, file_bytes):
        sha256 = self.calculate_sha256(file_bytes)
        file_size_kb = round(len(file_bytes) / 1024, 2)
        entropy = self.calculate_entropy(file_bytes)
        detected_type, is_exec = self.detect_file_type(file_bytes)
        found_patterns = self.scan_patterns(file_bytes)

        if len(file_bytes) > 0:
            non_ascii = sum(1 for b in file_bytes if b < 32 or b > 126)
            non_ascii_ratio = round(non_ascii / len(file_bytes), 3)
        else:
            non_ascii_ratio = 0.0

        features = np.array([[entropy, len(found_patterns), is_exec, non_ascii_ratio]])
        probs = self.model.predict_proba(features)
        malicious_prob = probs.item(1)
        threat_score = round(float(malicious_prob) * 100, 1)

        if threat_score >= 65 or len(found_patterns) >= 3:
            verdict = "MALICIOUS / HIGH RISK"
            risk_level = "high"
        elif threat_score >= 35 or entropy > 7.4 or len(found_patterns) > 0:
            verdict = "SUSPICIOUS / CAUTION"
            risk_level = "medium"
        else:
            verdict = "CLEAN / SAFE"
            risk_level = "low"

        return {
            "filename": filename,
            "size_kb": file_size_kb,
            "sha256": sha256,
            "detected_type": detected_type,
            "entropy": entropy,
            "non_ascii_ratio": non_ascii_ratio,
            "suspicious_patterns": found_patterns,
            "threat_score": threat_score,
            "verdict": verdict,
            "risk_level": risk_level
        }
