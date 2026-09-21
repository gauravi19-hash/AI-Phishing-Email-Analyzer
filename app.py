import json
import os
import tempfile

import streamlit as st

from analyzer.investigator import investigate_email
from analyzer.ai_report import generate_ai_report


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="Phishing Email Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# ============================================================
# MINIMAL CSS
# ============================================================

st.markdown(
    """
    <style>

    /* Background */
    .stApp {
        background-color: #071018;
    }

    /* Main content width */
    .main .block-container {
        max-width: 1450px;
        padding-top: 2rem;
        padding-bottom: 3rem;
    }

    /* Sidebar */
    [data-testid="stSidebar"] {
        background-color: #09121b;
        border-right: 1px solid #1d2c39;
    }

    /* Normal text */
    p {
        color: #a7b5c3;
    }

    /* Headers */
    h1, h2, h3, h4 {
        color: #edf6fb !important;
    }

    /* Buttons */
    .stButton > button {
        border-radius: 8px;
        font-weight: 600;
        min-height: 42px;
    }

    /* Tabs */
    .stTabs [data-baseweb="tab-list"] {
        background-color: #0b151f;
        border: 1px solid #1d2c39;
        border-radius: 10px;
        padding: 4px;
    }

    .stTabs [data-baseweb="tab"] {
        color: #8495a6;
    }

    /* Expanders */
    [data-testid="stExpander"] {
        background-color: #0b151f;
        border: 1px solid #1d2c39;
        border-radius: 10px;
    }

    /* File uploader */
    [data-testid="stFileUploader"] {
        background-color: #0b151f;
        border-radius: 10px;
    }

    </style>
    """,
    unsafe_allow_html=True
)


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def risk_color(level):

    level = str(level).lower()

    if level == "critical":
        return "🔴"

    if level == "high":
        return "🟠"

    if level == "suspicious":
        return "🟡"

    return "🟢"


def severity_icon(severity):

    severity = str(severity).lower()

    if severity == "critical":
        return "🔴"

    if severity == "high":
        return "🔴"

    if severity == "medium":
        return "🟠"

    if severity == "low":
        return "🟢"

    return "🔵"


def show_finding(finding):

    severity = finding.get(
        "severity",
        "Info"
    )

    with st.expander(
        f"{severity_icon(severity)}  "
        f"{finding.get('type', 'Finding')}"
    ):

        st.write(
            f"**Severity:** {severity}"
        )

        st.write(
            f"**Evidence:** "
            f"{finding.get('evidence', 'N/A')}"
        )

        st.write(
            finding.get(
                "description",
                ""
            )
        )


def show_info(label, value):

    if value is None or value == "":
        value = "N/A"

    st.caption(label)

    st.write(value)


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.title("🛡️ Investigation")

    st.caption(
        "AI-assisted phishing email "
        "investigation for SOC analysis."
    )

    st.divider()

    st.subheader("Email Sample")

    uploaded_file = st.file_uploader(
        "Upload .eml file",
        type=["eml"]
    )

    if uploaded_file:

        st.success(
            f"Loaded: {uploaded_file.name}"
        )

    analyze_button = st.button(
        "🔍 Analyze Email",
        use_container_width=True,
        type="primary"
    )

    st.divider()

    st.subheader("Analysis Pipeline")

    pipeline = [
        "Email Parser",
        "Header Analysis",
        "Content Analysis",
        "URL Analysis",
        "VirusTotal",
        "Attachment Analysis",
        "MITRE ATT&CK",
        "Risk Engine",
        "AI Analyst"
    ]

    for module in pipeline:

        st.write(
            f"🔹 {module}"
        )

    st.divider()

    st.caption(
        "SOC Portfolio Project"
    )


# ============================================================
# TOP HEADER
# ============================================================

header_left, header_right = st.columns(
    [5, 1]
)

with header_left:

    st.title(
        "🛡️ Phishing Email Analyzer"
    )

    st.caption(
        "AI-Assisted SOC Investigation Platform"
    )



st.divider()


# ============================================================
# RUN ANALYSIS
# ============================================================

if analyze_button:

    if uploaded_file is None:

        st.warning(
            "Please upload an .eml file first."
        )

    else:

        temp_path = None

        try:

            with st.spinner(
                "Running complete SOC investigation..."
            ):

                with tempfile.NamedTemporaryFile(
                    delete=False,
                    suffix=".eml"
                ) as temp_file:

                    temp_file.write(
                        uploaded_file.getbuffer()
                    )

                    temp_path = temp_file.name

                investigation = investigate_email(
                    temp_path
                )

                ai_result = generate_ai_report(
                    investigation
                )

            st.session_state[
                "investigation"
            ] = investigation

            st.session_state[
                "ai_result"
            ] = ai_result

            st.session_state[
                "filename"
            ] = uploaded_file.name

            st.success(
                "Investigation completed successfully."
            )

        except Exception as error:

            st.error(
                f"Investigation failed: {error}"
            )

        finally:

            if (
                temp_path
                and os.path.exists(temp_path)
            ):

                os.remove(temp_path)


# ============================================================
# EMPTY STATE
# ============================================================

if "investigation" not in st.session_state:

    st.info(
        "👈 Upload an .eml email from the sidebar "
        "to begin the investigation."
    )

    st.subheader(
        "What this analyzer checks"
    )

    col1, col2, col3 = st.columns(3)

    with col1:

        st.metric(
            "HEADER ANALYSIS",
            "⬇"
        )

        st.caption(
            "Sender, Reply-To, Return-Path, "
            "SPF, DKIM and DMARC indicators."
        )

    with col2:

        st.metric(
            "THREAT INTELLIGENCE",
            "⬇"
        )

        st.caption(
            "URL and file hash reputation "
            "through VirusTotal."
        )

    with col3:

        st.metric(
            "AI SOC ANALYSIS",
            "⬇"
        )

        st.caption(
            "Structured analyst report "
            "based on collected evidence."
        )

    st.stop()


# ============================================================
# LOAD RESULTS
# ============================================================

investigation = st.session_state[
    "investigation"
]

ai_result = st.session_state[
    "ai_result"
]

filename = st.session_state.get(
    "filename",
    "Unknown"
)

risk = investigation[
    "risk_assessment"
]

email = investigation[
    "email"
]


# ============================================================
# INVESTIGATION OVERVIEW
# ============================================================

st.header(
    "Investigation Overview"
)

col1, col2, col3, col4 = st.columns(4)


# Risk
with col1:

    st.metric(
        "Risk Score",
        f"{risk['score']}/100",
        help=(
            "Illustrative prioritization score. "
            "It is not a probability."
        )
    )

    st.caption(
        f"{risk_color(risk['risk_level'])} "
        f"{risk['risk_level']}"
    )


# Verdict
with col2:

    if ai_result["status"] == "success":

        verdict = ai_result[
            "report"
        ].get(
            "verdict",
            "N/A"
        )

    else:

        verdict = "Unavailable"

    st.metric(
        "AI Verdict",
        verdict
    )


# IOC count
with col3:

    if ai_result["status"] == "success":

        ioc_count = len(
            ai_result[
                "report"
            ].get(
                "observed_iocs",
                []
            )
        )

    else:

        ioc_count = 0

    st.metric(
        "Observed IOCs",
        ioc_count
    )


# MITRE
with col4:

    st.metric(
        "MITRE Techniques",
        len(
            investigation[
                "mitre_attack"
            ]
        )
    )


# ============================================================
# EMAIL DETAILS
# ============================================================

st.header(
    "Email Information"
)

row1 = st.columns(3)

with row1[0]:

    show_info(
        "FROM",
        email.get("from")
    )

with row1[1]:

    show_info(
        "TO",
        email.get("to")
    )

with row1[2]:

    show_info(
        "DATE",
        email.get("date")
    )


row2 = st.columns(2)

with row2[0]:

    show_info(
        "SUBJECT",
        email.get("subject")
    )

with row2[1]:

    show_info(
        "REPLY-TO",
        email.get("reply_to")
    )


# ============================================================
# TABS
# ============================================================

(
    tab_ai,
    tab_headers,
    tab_content,
    tab_urls,
    tab_attachments,
    tab_mitre,
    tab_risk
) = st.tabs(
    [
        "🤖 AI Assessment",
        "📨 Headers",
        "📝 Content",
        "🔗 URLs",
        "📎 Attachments",
        "🎯 MITRE ATT&CK",
        "📊 Risk Evidence"
    ]
)


# ============================================================
# AI ASSESSMENT
# ============================================================

with tab_ai:

    if ai_result["status"] == "success":

        report = ai_result[
            "report"
        ]

        col1, col2 = st.columns(
            [3, 1]
        )

        with col1:

            st.subheader(
                report["verdict"]
            )

        with col2:

            st.metric(
                "Confidence",
                report["confidence"]
            )

        st.divider()

        st.subheader(
            "Executive Summary"
        )

        st.info(
            report[
                "executive_summary"
            ]
        )

        left, right = st.columns(2)

        with left:

            st.subheader(
                "🔎 Key Findings"
            )

            for finding in report[
                "key_findings"
            ]:

                st.write(
                    f"• {finding}"
                )

        with right:

            st.subheader(
                "🛠️ Recommended Actions"
            )

            for action in report[
                "recommended_actions"
            ]:

                st.write(
                    f"• {action}"
                )

        st.subheader(
            "🎯 Observed IOCs"
        )

        if report[
            "observed_iocs"
        ]:

            for ioc in report[
                "observed_iocs"
            ]:

                st.code(
                    ioc
                )

        else:

            st.caption(
                "No IOCs reported."
            )

        st.subheader(
            "📝 Analyst Notes"
        )

        st.write(
            report[
                "analyst_notes"
            ]
        )

    else:

        st.error(
            ai_result.get(
                "message",
                "AI report unavailable."
            )
        )


# ============================================================
# HEADERS
# ============================================================

with tab_headers:

    findings = investigation[
        "header_findings"
    ]

    if findings:

        for finding in findings:

            show_finding(
                finding
            )

    else:

        st.success(
            "✓ No suspicious header findings detected."
        )


# ============================================================
# CONTENT
# ============================================================

with tab_content:

    findings = investigation[
        "content_findings"
    ]

    if findings:

        for finding in findings:

            show_finding(
                finding
            )

    else:

        st.success(
            "✓ No suspicious content indicators detected."
        )


# ============================================================
# URLS
# ============================================================

with tab_urls:

    urls = investigation[
        "urls"
    ]

    st.subheader(
        "Extracted URLs"
    )

    if urls["extracted"]:

        for url in urls[
            "extracted"
        ]:

            st.code(
                url
            )

        st.subheader(
            "Static URL Findings"
        )

        for finding in urls[
            "findings"
        ]:

            show_finding(
                finding
            )

        st.subheader(
            "VirusTotal Results"
        )

        for result in urls[
            "virustotal"
        ]:

            st.json(
                result
            )

    else:

        st.success(
            "✓ No URLs detected."
        )


# ============================================================
# ATTACHMENTS
# ============================================================

with tab_attachments:

    attachments = investigation[
        "attachments"
    ]

    files = attachments[
        "files"
    ]

    if files:

        for attachment in files:

            st.subheader(
                f"📎 {attachment['filename']}"
            )

            col1, col2 = st.columns(2)

            with col1:

                st.write(
                    "**Content Type:**"
                )

                st.write(
                    attachment[
                        "content_type"
                    ]
                )

            with col2:

                st.write(
                    "**Size:**"
                )

                st.write(
                    f"{attachment['size']} bytes"
                )

            st.write(
                "**SHA-256:**"
            )

            st.code(
                attachment[
                    "sha256"
                ]
            )

            st.divider()

        st.subheader(
            "VirusTotal Hash Results"
        )

        for result in attachments[
            "virustotal"
        ]:

            st.json(
                result
            )

    else:

        st.success(
            "✓ No attachments detected."
        )


# ============================================================
# MITRE
# ============================================================

with tab_mitre:

    techniques = investigation[
        "mitre_attack"
    ]

    if techniques:

        for technique in techniques:

            with st.expander(
                f"{technique['technique_id']}  —  "
                f"{technique['technique']}"
            ):

                st.write(
                    f"**Evidence:** "
                    f"{technique['evidence']}"
                )

                st.write(
                    f"**Confidence:** "
                    f"{technique['confidence']}"
                )

    else:

        st.success(
            "✓ No MITRE ATT&CK techniques mapped."
        )


# ============================================================
# RISK EVIDENCE
# ============================================================

with tab_risk:

    st.subheader(
        "Risk Calculation Evidence"
    )

    st.caption(
        "This score is a prioritization aid, "
        "not a probability of maliciousness."
    )

    evidence = risk[
        "evidence"
    ]

    if evidence:

        for item in evidence:

            col1, col2 = st.columns(
                [5, 1]
            )

            with col1:

                with st.expander(
                    f"{item['source']} — "
                    f"{item['type']}"
                ):

                    st.write(
                        item["evidence"]
                    )

            with col2:

                st.metric(
                    "Points",
                    f"+{item['points']}"
                )

    else:

        st.info(
            "No scored evidence."
        )


# ============================================================
# EXPORT
# ============================================================

st.divider()

st.header(
    "Export Investigation"
)

export_data = {
    "email_file": filename,
    "investigation": investigation
}

if ai_result["status"] == "success":

    export_data[
        "ai_report"
    ] = ai_result[
        "report"
    ]

json_data = json.dumps(
    export_data,
    indent=4,
    ensure_ascii=False
)

st.download_button(
    label="⬇️ Download Investigation Report",
    data=json_data,
    file_name="phishing_investigation_report.json",
    mime="application/json",
    use_container_width=True
)


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "🛡️ AI-Assisted Phishing Email Investigation Platform "
    "• SOC Portfolio Project"
)