import streamlit as st
import streamlit.components.v1 as components
from analyzer import FileShieldEngine

st.set_page_config(
    page_title="FileShield | AI Malware Detector",
    page_icon="🛡️",
    layout="centered"
)

welcome_overlay_html = """
<style>
    #fs-welcome-overlay {
        position: fixed;
        top: 0;
        left: 0;
        width: 100vw;
        height: 100vh;
        background: rgba(10, 15, 28, 0.94);
        backdrop-filter: blur(8px);
        z-index: 999999;
        display: flex;
        justify-content: center;
        align-items: center;
        cursor: pointer;
        transition: opacity 0.4s ease;
    }
    .fs-welcome-card {
        background: linear-gradient(145deg, #131c31, #0d1322);
        border: 1px solid #00f2fe;
        box-shadow: 0 0 30px rgba(0, 242, 254, 0.25);
        border-radius: 16px;
        padding: 40px 25px;
        max-width: 520px;
        width: 88%;
        text-align: center;
        color: #ffffff;
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        animation: fadeInScale 0.5s ease-out;
    }
    .fs-shield-icon {
        font-size: 54px;
        margin-bottom: 10px;
    }
    .fs-title {
        font-size: 28px;
        font-weight: 700;
        color: #00f2fe;
        margin: 0 0 8px 0;
        letter-spacing: 1px;
    }
    .fs-subtitle {
        font-size: 14px;
        color: #94a3b8;
        margin-bottom: 24px;
    }
    .fs-dev-label {
        font-size: 12px;
        text-transform: uppercase;
        letter-spacing: 1.5px;
        color: #38bdf8;
        margin-bottom: 6px;
    }
    .fs-dev-name {
        font-size: 19px;
        font-weight: 700;
        color: #f8fafc;
        background: rgba(56, 189, 248, 0.12);
        border: 1px solid rgba(56, 189, 248, 0.35);
        padding: 12px 16px;
        border-radius: 10px;
        margin-bottom: 24px;
    }
    .fs-tap-hint {
        font-size: 13px;
        color: #cbd5e1;
        animation: pulseText 1.8s infinite;
    }
    @keyframes fadeInScale {
        from { opacity: 0; transform: scale(0.92); }
        to { opacity: 1; transform: scale(1); }
    }
    @keyframes pulseText {
        0%, 100% { opacity: 0.5; }
        50% { opacity: 1; }
    }
</style>

<script>
    const parentDoc = window.parent.document;
    if (!parentDoc.getElementById('fs-welcome-overlay') && !window.parent.fsCardDismissed) {
        const overlay = parentDoc.createElement('div');
        overlay.id = 'fs-welcome-overlay';
        overlay.innerHTML = `
            <div class="fs-welcome-card">
                <div class="fs-shield-icon">🛡️</div>
                <div class="fs-title">FileShield AI</div>
                <div class="fs-subtitle">Static Malware Analysis & Machine Learning Threat Detector</div>
                <div class="fs-dev-label">Designed & Developed By</div>
                <div class="fs-dev-name">Fatehi Abdulfattah Mohammed Ali Alshami</div>
                <div class="fs-tap-hint">Tap anywhere on the screen to enter • اضغط في أي مكان للدخول</div>
            </div>
        `;
        overlay.addEventListener('click', function() {
            window.parent.fsCardDismissed = true;
            overlay.style.opacity = '0';
            setTimeout(() => {
                if (overlay.parentNode) {
                    overlay.parentNode.removeChild(overlay);
                }
            }, 400);
        });
        parentDoc.body.appendChild(overlay);
    }
</script>
"""

components.html(welcome_overlay_html, height=0, width=0)

st.markdown("""
<style>
    .main-header {
        text-align: center;
        padding: 15px 0;
    }
    .footer-credit {
        text-align: center;
        font-size: 13px;
        color: #64748b;
        margin-top: 40px;
        padding-top: 15px;
        border-top: 1px solid #1e293b;
    }
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="main-header">
    <h1>🛡️ FileShield</h1>
    <p>AI-Powered Static Malware Detector | فاحص الملفات الذكي قبل التشغيل</p>
</div>
""", unsafe_allow_html=True)

@st.cache_resource
def load_engine():
    return FileShieldEngine()

engine = load_engine()

uploaded_file = st.file_uploader(
    "Upload any file to analyze its structure & patterns (بدون تشغيل الملف)",
    type=None
)

if uploaded_file is not None:
    file_bytes = uploaded_file.read()
    with st.spinner("Analyzing file entropy, magic bytes, and ML patterns..."):
        result = engine.analyze_file(uploaded_file.name, file_bytes)

    st.subheader("📊 Security Analysis Report")

    if result["risk_level"] == "high":
        st.error(f"🚨 **Verdict:** {result['verdict']} (Threat Probability: {result['threat_score']}%)")
    elif result["risk_level"] == "medium":
        st.warning(f"⚠️ **Verdict:** {result['verdict']} (Threat Probability: {result['threat_score']}%)")
    else:
        st.success(f"✅ **Verdict:** {result['verdict']} (Threat Probability: {result['threat_score']}%)")

    col1, col2, col3 = st.columns(3)
    col1.metric("File Size", f"{result['size_kb']} KB")
    col2.metric("Shannon Entropy", f"{result['entropy']} / 8.0")
    col3.metric("ML Threat Score", f"{result['threat_score']}%")

    st.markdown(f"**Detected File Signature:** `{result['detected_type']}`")
    st.markdown(f"**SHA-256 Hash:** `{result['sha256']}`")

    if result["suspicious_patterns"]:
        st.warning("🔍 **Suspicious Strings / APIs Detected:**")
        st.code(", ".join(result["suspicious_patterns"]))
    else:
        st.info("🔍 **Suspicious Strings / APIs:** None detected in static scan.")

st.markdown("""
<div class="footer-credit">
    Developed by <strong>Fatehi Abdulfattah Mohammed Ali Alshami</strong> • Powered by Machine Learning & Static Heuristic Analysis
</div>
""", unsafe_allow_html=True)
