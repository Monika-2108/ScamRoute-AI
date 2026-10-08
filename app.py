import re
from datetime import datetime
import streamlit as st


# =========================================================
# PAGE CONFIG
# =========================================================

st.set_page_config(
    page_title="ScamRoute AI",
    page_icon="🛡️",
    layout="wide"
)


# =========================================================
# CUSTOM CSS
# =========================================================

st.markdown("""
<style>

.main {
    background-color: #f7f9fc;
}

.block-container {
    max-width: 1150px;
    padding-top: 2rem;
}

.hero {
    padding: 25px;
    border-radius: 18px;
    background: linear-gradient(135deg, #111827, #1f2937);
    color: white;
    margin-bottom: 25px;
}

.hero h1 {
    margin-bottom: 5px;
}

.hero p {
    color: #d1d5db;
    font-size: 16px;
}

.risk-card {
    padding: 22px;
    border-radius: 16px;
    background: #ffffff;
    border: 1px solid #e5e7eb;
    margin: 15px 0;
}

.critical {
    border-left: 7px solid #dc2626;
}

.high {
    border-left: 7px solid #ea580c;
}

.medium {
    border-left: 7px solid #ca8a04;
}

.low {
    border-left: 7px solid #16a34a;
}

.step-card {
    padding: 18px;
    border-radius: 14px;
    background: white;
    border: 1px solid #e5e7eb;
    margin-bottom: 10px;
}

.small-muted {
    color: #6b7280;
    font-size: 14px;
}

.warning-box {
    padding: 18px;
    border-radius: 14px;
    background: #fff7ed;
    border: 1px solid #fed7aa;
}

.safe-box {
    padding: 18px;
    border-radius: 14px;
    background: #f0fdf4;
    border: 1px solid #bbf7d0;
}

</style>
""", unsafe_allow_html=True)


# =========================================================
# ENTITY DETECTION
# =========================================================

def detect_entities(text):

    t = text.lower()

    e = {
        "otp": False,
        "password": False,
        "pin": False,
        "cvv": False,
        "bank": False,
        "link": False,
        "money": False,
        "money_lost": False,
        "impersonation": False,
        "urgency": False,
        "remote_access": False,
        "app_install": False,
        "personal_data": False,
        "job": False,
        "investment": False,
        "qr": False,
        "upi": False,
        "aadhaar": False,
        "whatsapp": False,
        "click": False,
        "credentials": False,
    }

    # Authentication
    e["otp"] = bool(re.search(r"\botp\b|one[- ]time password|verification code", t))
    e["password"] = bool(re.search(r"password|passcode", t))
    e["pin"] = bool(re.search(r"\bpin\b|\bmpin\b|upi pin", t))
    e["cvv"] = bool(re.search(r"\bcvv\b|card security code", t))

    # Banking / payment
    e["bank"] = bool(re.search(
        r"\bbank\b|account|banking|payment|upi|transaction|card",
        t
    ))

    e["upi"] = bool(re.search(r"\bupi\b|upi pin|google pay|gpay|phonepe|paytm", t))

    # Suspicious link
    e["link"] = bool(re.search(
        r"link|website|url|http|www\.|\.com|click",
        t
    ))

    e["click"] = bool(re.search(
        r"clicked|click|opened the link|visited the link|entered.*website",
        t
    ))

    # QR
    e["qr"] = bool(re.search(
        r"qr code|scan.*qr|scanned.*qr",
        t
    ))

    # Money
    e["money"] = bool(re.search(
        r"₹\s?\d+|rs\.?\s?\d+|inr\s?\d+|money|payment|pay|paid|transfer|transferred|deposit|fee|registration fee",
        t
    ))

    e["money_lost"] = bool(re.search(
        r"transferred|transfer(ed)?|paid|payment made|sent money|money was deducted|lost money|was charged|debited|deducted|paid ₹|paid rs|sent ₹",
        t
    ))

    # Impersonation
    e["impersonation"] = bool(re.search(
        r"claiming to be|pretending to be|said.*from|from my bank|bank official|customer support|support team|government|police|income tax|courier|delivery agent|recruiter",
        t
    ))

    # Urgency / pressure
    e["urgency"] = bool(re.search(
        r"urgent|immediately|account.*blocked|account.*suspended|expire|deadline|act now|within.*hour|last chance",
        t
    ))

    # Remote access
    e["remote_access"] = bool(re.search(
        r"remote access|remote-access|remote control|control my phone|control your phone|screen sharing|screen-share|access my phone|access your phone|anydesk|teamviewer|quicksupport|remote desktop",
        t
    ))

    # App installation
    e["app_install"] = bool(re.search(
        r"install.*app|download.*app|install.*application|download.*application|asked me to install|asked.*download",
        t
    ))

    # Personal / identity information
    e["personal_data"] = bool(re.search(
        r"aadhaar|aadhar|pan card|pan number|date of birth|dob|address|identity|id proof|personal information|personal details|documents|send my.*details",
        t
    ))

    e["aadhaar"] = bool(re.search(
        r"aadhaar|aadhar",
        t
    ))

    # Job scam
    e["job"] = bool(re.search(
        r"job|work from home|work-from-home|employment|recruiter|hiring|vacancy|salary|registration fee|job offer",
        t
    ))

    # Investment scam
    e["investment"] = bool(re.search(
        r"investment|invest|trading|crypto|cryptocurrency|stock|profit|returns|double your money",
        t
    ))

    # WhatsApp
    e["whatsapp"] = bool(re.search(
        r"whatsapp|telegram|sms|text message",
        t
    ))

    # Generic credentials
    e["credentials"] = any([
        e["otp"],
        e["password"],
        e["pin"],
        e["cvv"]
    ])

    return e


# =========================================================
# THREAT CLASSIFICATION
# =========================================================

def classify_threat(e):

    if e["job"]:
        return "Job / Employment Scam"

    if e["investment"]:
        return "Investment / Financial Scam"

    if e["bank"] or e["upi"] or e["money"]:
        return "Banking / Payment Scam"

    if e["remote_access"] or e["app_install"]:
        return "Remote Access Scam"

    return "Suspicious Social Engineering"


# =========================================================
# RISK CALCULATION
# =========================================================

def calculate_risk(e):

    score = 0

    # Authentication exposure
    if e["otp"]:
        score += 25

    if e["password"]:
        score += 20

    if e["pin"]:
        score += 25

    if e["cvv"]:
        score += 25

    # Financial exposure
    if e["money"]:
        score += 20

    if e["money_lost"]:
        score += 40

    # Suspicious digital delivery
    if e["link"]:
        score += 15

    # Social engineering
    if e["impersonation"]:
        score += 15

    if e["urgency"]:
        score += 10

    # Device compromise
    if e["remote_access"]:
        score += 30

    if e["app_install"]:
        score += 25

    # Identity exposure
    if e["personal_data"]:
        score += 15

    # QR / UPI combination
    if e["qr"] and e["upi"]:
        score += 15

    # Job scam with payment
    if e["job"] and e["money"]:
        score += 15

    # Job scam with identity information
    if e["job"] and e["personal_data"]:
        score += 15

    # Remote access + installation
    if e["remote_access"] and e["app_install"]:
        score += 20

    # Remote access is serious even without financial loss
    if e["remote_access"]:
        score = max(score, 55)

    # Installation of remote-access software
    if e["app_install"] and e["remote_access"]:
        score = max(score, 70)

    # Money already lost + credentials
    if e["money_lost"] and e["credentials"]:
        score = max(score, 85)

    # Money already lost + remote access
    if e["money_lost"] and e["remote_access"]:
        score = max(score, 90)

    # Job scam with payment + identity information
    if e["job"] and e["money"] and e["personal_data"]:
        score = max(score, 70)

    # Cap
    score = min(score, 100)

    if score >= 85:
        severity = "CRITICAL"
    elif score >= 65:
        severity = "HIGH"
    elif score >= 40:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return score, severity


# =========================================================
# RISK DIMENSIONS
# =========================================================

def risk_dimensions(e):

    financial = 0
    account = 0
    device = 0
    identity = 0

    if e["money"]:
        financial += 25

    if e["money_lost"]:
        financial += 45

    if e["bank"] or e["upi"]:
        financial += 20

    if e["otp"]:
        account += 30

    if e["password"]:
        account += 30

    if e["pin"]:
        account += 30

    if e["cvv"]:
        account += 30

    if e["remote_access"]:
        device += 45

    if e["app_install"]:
        device += 30

    if e["link"]:
        device += 20

    if e["personal_data"]:
        identity += 55

    if e["aadhaar"]:
        identity += 20

    return (
        min(financial, 100),
        min(account, 100),
        min(device, 100),
        min(identity, 100)
    )


# =========================================================
# ATTACK CHAIN
# =========================================================

def build_attack_chain(e):

    chain = []

    if e["impersonation"]:
        chain.append((
            "🎭",
            "Impersonation",
            "Attacker establishes trust by pretending to represent someone legitimate."
        ))

    if e["urgency"]:
        chain.append((
            "⏱️",
            "Pressure",
            "Urgency or fear is used to push the victim into acting quickly."
        ))

    if e["link"] or e["whatsapp"]:
        chain.append((
            "🔗",
            "Delivery",
            "A suspicious link, website, message, or digital channel is introduced."
        ))

    if e["qr"]:
        chain.append((
            "📱",
            "QR Manipulation",
            "A QR code is used to direct the victim toward a payment or suspicious action."
        ))

    if e["credentials"]:
        chain.append((
            "🔐",
            "Credential Capture",
            "Sensitive authentication or payment information is requested."
        ))

    if e["personal_data"]:
        chain.append((
            "🪪",
            "Identity Exposure",
            "Personal identity information is requested or potentially exposed."
        ))

    if e["app_install"] or e["remote_access"]:
        chain.append((
            "💻",
            "Device Access",
            "The attacker attempts to obtain access to the victim's device."
        ))

    if e["money"]:
        chain.append((
            "💰",
            "Financial Action",
            "The interaction involves a financial account, payment, or money transfer."
        ))

    if e["money_lost"]:
        chain.append((
            "🚨",
            "Potential Loss",
            "The description indicates that money may already have moved."
        ))

    if not chain:
        chain.append((
            "🔎",
            "Suspicious Interaction",
            "The description contains patterns requiring independent verification."
        ))

    return chain


# =========================================================
# WHY FLAGGED
# =========================================================

def why_flagged(e):

    reasons = []

    if e["otp"]:
        reasons.append("⚠️ OTP or one-time authentication information was involved.")

    if e["password"]:
        reasons.append("⚠️ A password or account credential may have been exposed.")

    if e["pin"]:
        reasons.append("⚠️ A PIN or MPIN may have been exposed.")

    if e["cvv"]:
        reasons.append("⚠️ Card security information may have been exposed.")

    if e["bank"] or e["upi"]:
        reasons.append("⚠️ A financial account or transaction is involved.")

    if e["money_lost"]:
        reasons.append("⚠️ The description indicates that money may already have been transferred.")

    if e["money"] and not e["money_lost"]:
        reasons.append("⚠️ A financial payment or money request is involved.")

    if e["link"]:
        reasons.append("⚠️ A suspicious link or website is involved.")

    if e["impersonation"]:
        reasons.append("⚠️ The sender may be impersonating a trusted organization or person.")

    if e["remote_access"]:
        reasons.append("⚠️ Remote access to a device was requested.")

    if e["app_install"]:
        reasons.append("⚠️ Installation of an application was requested.")

    if e["personal_data"]:
        reasons.append("⚠️ Personal identity information may have been exposed.")

    if e["qr"]:
        reasons.append("⚠️ A QR code was used as part of the requested action.")

    return reasons


# =========================================================
# CONSEQUENCES
# =========================================================

def consequences(e):

    items = []

    if e["money_lost"]:
        items.append((
            "🚨 Immediate financial risk",
            "Additional unauthorized transactions may occur if access remains compromised."
        ))

    if e["credentials"]:
        items.append((
            "🔐 Account takeover risk",
            "Exposed authentication information may be used in further unauthorized attempts."
        ))

    if e["link"]:
        items.append((
            "🌐 Credential harvesting risk",
            "The suspicious website may have been designed to collect sensitive information."
        ))

    if e["remote_access"] or e["app_install"]:
        items.append((
            "💻 Device compromise risk",
            "Remote-access software may allow an attacker to view, control, or interact with the device."
        ))

    if e["personal_data"]:
        items.append((
            "🪪 Identity risk",
            "Exposed personal information may be reused in future impersonation attempts."
        ))

    if not items:
        items.append((
            "⚠️ Uncertain risk",
            "The available information is insufficient to confirm the impact. Independent verification is recommended."
        ))

    return items


# =========================================================
# PERSONALIZED RESPONSE ROUTE
# =========================================================

def create_route(e):

    route = []

    if e["money_lost"]:
        route.extend([
            (
                "🚨 STOP FURTHER LOSS",
                "Do not send additional money or follow further instructions from the suspected attacker."
            ),
            (
                "🏦 CONTACT FINANCIAL PROVIDER",
                "Use only the official banking/payment app, website, or verified phone number. Report the transaction immediately."
            ),
            (
                "🔒 SECURE ACCESS",
                "Change affected credentials and block or freeze compromised payment instruments where appropriate."
            ),
            (
                "📱 CHECK ACCOUNT ACTIVITY",
                "Review transactions, login sessions, devices, beneficiaries, and account changes."
            ),
            (
                "📸 PRESERVE EVIDENCE",
                "Keep screenshots, messages, phone numbers, links, receipts, timestamps, and transaction references."
            ),
            (
                "🚔 REPORT",
                "Report the incident through the appropriate official cybercrime or law-enforcement channel."
            )
        ])

    elif e["remote_access"] or e["app_install"]:
        route.extend([
            (
                "🛑 STOP REMOTE ACCESS",
                "Disconnect from the suspected attacker and stop interacting with the remote-access application."
            ),
            (
                "📱 SECURE YOUR DEVICE",
                "Remove unauthorized remote-access software and review applications and device permissions."
            ),
            (
                "🔐 SECURE ACCOUNTS",
                "Change important passwords using a trusted device and review account security settings."
            ),
            (
                "💳 CHECK FINANCIAL ACTIVITY",
                "Review banking, UPI, card, and other financial accounts for unauthorized activity."
            ),
            (
                "📸 PRESERVE EVIDENCE",
                "Save the caller's number, messages, application name, screenshots, and timestamps."
            ),
            (
                "🚔 REPORT",
                "Report the incident through the appropriate official cybercrime or law-enforcement channel."
            )
        ])

    elif e["job"] and e["money"] and e["personal_data"]:
        route.extend([
            (
                "🛑 STOP INTERACTION",
                "Do not pay additional fees or send additional identity documents."
            ),
            (
                "💳 PROTECT YOUR MONEY",
                "If payment was already made, contact the payment provider or bank through its official channel."
            ),
            (
                "🪪 PROTECT YOUR IDENTITY",
                "Monitor accounts and services where your identity information could potentially be misused."
            ),
            (
                "🔎 VERIFY THE EMPLOYER",
                "Verify the company, recruiter, job posting, and official contact details independently."
            ),
            (
                "📸 PRESERVE EVIDENCE",
                "Save WhatsApp messages, recruiter details, payment receipts, links, and documents requested."
            ),
            (
                "🚔 REPORT",
                "Report suspected fraud through the appropriate official cybercrime channel."
            )
        ])

    elif e["credentials"]:
        route.extend([
            (
                "🛑 STOP SHARING",
                "Do not provide any additional OTPs, passwords, PINs, or verification codes."
            ),
            (
                "🔐 CHANGE CREDENTIALS",
                "Change affected credentials through the legitimate service's official channel."
            ),
            (
                "🛡️ ENABLE PROTECTION",
                "Enable available multi-factor authentication and review security settings."
            ),
            (
                "🔎 CHECK ACTIVITY",
                "Review recent logins, devices, transactions, and account changes."
            ),
            (
                "📸 PRESERVE EVIDENCE",
                "Keep the original communication, suspicious links, screenshots, and sender details."
            )
        ])

    else:
        route.extend([
            (
                "🛑 STOP INTERACTION",
                "Do not provide additional information or follow further instructions."
            ),
            (
                "🔎 VERIFY INDEPENDENTLY",
                "Contact the claimed organization using a trusted channel you find independently."
            ),
            (
                "🔐 PROTECT YOURSELF",
                "Change credentials if you believe sensitive information was exposed."
            ),
            (
                "📸 PRESERVE EVIDENCE",
                "Save messages, screenshots, links, and contact details."
            )
        ])

    return route


# =========================================================
# IF YOU DO NOTHING
# =========================================================

def do_nothing_scenario(e):

    if e["money_lost"]:
        return (
            "High consequence scenario",
            "Delaying action may give an attacker more time to perform additional transactions, change account settings, or continue the social-engineering attack."
        )

    if e["remote_access"] or e["app_install"]:
        return (
            "High device-risk scenario",
            "An attacker with remote access may continue interacting with the device or attempt to access information and accounts."
        )

    if e["credentials"]:
        return (
            "Account exposure may continue",
            "Compromised credentials can potentially be reused in additional login or account-takeover attempts."
        )

    if e["personal_data"]:
        return (
            "Identity exposure may continue",
            "Exposed personal information can potentially be reused for impersonation or future fraud attempts."
        )

    return (
        "Lower immediate impact detected",
        "No direct financial loss or credential exposure was detected from the information provided, but independent verification is still recommended."
    )


# =========================================================
# EVIDENCE CHECKLIST
# =========================================================

def evidence_checklist(e):

    items = [
        "Screenshot the suspicious message or website",
        "Save the sender's phone number / email / username",
        "Keep the suspicious URL",
        "Record the approximate time of the incident"
    ]

    if e["money"] or e["money_lost"]:
        items.append("Save transaction ID, amount, and payment reference")

    if e["credentials"]:
        items.append("Record which type of credential was exposed")

    if e["remote_access"] or e["app_install"]:
        items.append("Record the remote-access application name and device involved")

    if e["personal_data"]:
        items.append("Record which personal or identity information was shared")

    return items


# =========================================================
# INCIDENT REPORT
# =========================================================

def create_report(
    incident,
    threat,
    score,
    severity,
    dimensions,
    reasons,
    route
):

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    financial, account, device, identity = dimensions

    report = f"""
SCAMROUTE AI — INCIDENT REPORT
================================

Generated: {now}

INCIDENT
--------
{incident}

INCIDENT INTELLIGENCE
---------------------
Threat: {threat}
Risk Score: {score}/100
Severity: {severity}

RISK BREAKDOWN
--------------
Financial: {financial}/100
Account: {account}/100
Device: {device}/100
Identity: {identity}/100

WHY FLAGGED
-----------
"""

    for reason in reasons:
        report += f"- {reason}\n"

    report += """
PERSONALIZED RESPONSE ROUTE
----------------------------
"""

    for i, (title, description) in enumerate(route, 1):
        report += f"{i}. {title}\n   {description}\n"

    report += """

VERIFICATION RULE
-----------------
Never verify a suspicious request through the same channel that delivered it.
Find the organization's official contact details independently.

DISCLAIMER
----------
ScamRoute AI provides automated incident-response guidance based on information
supplied by the user. It does not replace banks, official government services,
cybersecurity professionals, or law enforcement.
"""

    return report


# =========================================================
# HEADER
# =========================================================

st.markdown("""
<div class="hero">
    <h1>🛡️ ScamRoute AI</h1>
    <p>AI-assisted scam incident response intelligence</p>
    <p>Don't just ask "Is this a scam?"<br>
    Reconstruct what happened, understand the risk, and get the safest next route.</p>
</div>
""", unsafe_allow_html=True)


# =========================================================
# INPUT
# =========================================================

st.subheader("🔎 Describe what happened")

incident = st.text_area(
    "Incident description",
    height=180,
    label_visibility="collapsed",
    placeholder="Example: Someone claiming to be my bank called me and asked for my OTP..."
)


# =========================================================
# ANALYZE
# =========================================================

if st.button("🔍 Analyze Incident", type="primary", use_container_width=True):

    if not incident.strip():

        st.warning("Please describe what happened first.")

    else:

        entities = detect_entities(incident)

        threat = classify_threat(entities)

        score, severity = calculate_risk(entities)

        dimensions = risk_dimensions(entities)

        chain = build_attack_chain(entities)

        reasons = why_flagged(entities)

        consequence_list = consequences(entities)

        route = create_route(entities)

        nothing_title, nothing_description = do_nothing_scenario(entities)

        evidence = evidence_checklist(entities)

        # Save results for download
        st.session_state["report"] = create_report(
            incident,
            threat,
            score,
            severity,
            dimensions,
            reasons,
            route
        )

        # =================================================
        # INCIDENT INTELLIGENCE
        # =================================================

        st.markdown("---")
        st.subheader("📊 Incident Intelligence")

        indicator_count = len(reasons)

        c1, c2, c3, c4 = st.columns(4)

        c1.metric("Risk Score", f"{score}/100")
        c2.metric("Severity", severity)
        c3.metric("Threat", threat)
        c4.metric("Indicators", indicator_count)

        # =================================================
        # RISK CARD
        # =================================================

        severity_class = severity.lower()

        st.markdown(
            f"""
            <div class="risk-card {severity_class}">
                <h2>🚨 {severity} RISK</h2>
                <p>ScamRoute classified this incident as <b>{threat}</b>.</p>
            </div>
            """,
            unsafe_allow_html=True
        )

        # =================================================
        # MONEY WARNING
        # =================================================

        if entities["money_lost"]:

            st.markdown("""
            <div class="warning-box">
                <h3>💰 Financial loss may already have occurred</h3>
                <p>
                The incident description indicates that money may already have
                been transferred or deducted.
                </p>
                <b>
                Your highest priority is to contact the financial provider
                through an independently verified official channel.
                </b>
            </div>
            """, unsafe_allow_html=True)

        # =================================================
        # RISK BREAKDOWN
        # =================================================

        st.subheader("🎯 Risk Breakdown")

        financial, account, device, identity = dimensions

        d1, d2, d3, d4 = st.columns(4)

        d1.metric("Financial", f"{financial}/100")
        d2.metric("Account", f"{account}/100")
        d3.metric("Device", f"{device}/100")
        d4.metric("Identity", f"{identity}/100")

        # =================================================
        # ATTACK CHAIN
        # =================================================

        st.subheader("🕵️ How the incident may have unfolded")

        st.caption(
            "ScamRoute reconstructs the likely attack chain from the user's description."
        )

        for icon, title, description in chain:

            st.markdown(
                f"""
                <div class="step-card">
                    <h4>{icon} {title}</h4>
                    <p>{description}</p>
                </div>
                """,
                unsafe_allow_html=True
            )

        # =================================================
        # WHY FLAGGED
        # =================================================

        st.subheader("🧠 Why ScamRoute flagged this")

        if reasons:

            for reason in reasons:
                st.write(reason)

        else:
            st.info("No strong risk indicators were detected.")

        # =================================================
        # CONSEQUENCES
        # =================================================

        st.subheader("💥 What could happen next?")

        for title, description in consequence_list:

            st.markdown(f"### {title}")
            st.write(description)

        # =================================================
        # PERSONALIZED ROUTE
        # =================================================

        st.subheader("🛡️ Your Personalized ScamRoute")

        st.caption(
            "The response route is generated from the specific actions and exposure detected in your incident."
        )

        for i, (title, description) in enumerate(route, 1):

            st.markdown(f"**PRIORITY {i}**")
            st.markdown(f"### {title}")
            st.write(description)

        # =================================================
        # IF YOU DO NOTHING
        # =================================================

        st.subheader("⏳ If you do nothing")

        st.markdown(f"### {nothing_title}")
        st.write(nothing_description)

        # =================================================
        # EVIDENCE
        # =================================================

        st.subheader("📸 Evidence to preserve")

        for item in evidence:
            st.checkbox(item, key=f"{item}_{score}")

        # =================================================
        # VERIFICATION RULE
        # =================================================

        st.subheader("🔍 ScamRoute Verification Rule")

        st.info(
            "Never verify a suspicious request through the same channel that "
            "delivered it. Find the organization's official contact details independently."
        )

        # =================================================
        # REPORT
        # =================================================

        st.subheader("📋 Generate Incident Report")

        st.download_button(
            label="⬇️ Download Incident Report",
            data=st.session_state["report"],
            file_name="ScamRoute_Incident_Report.txt",
            mime="text/plain",
            use_container_width=True
        )

        # =================================================
        # DISCLAIMER
        # =================================================

        st.markdown("---")

        st.caption(
            "ScamRoute AI provides automated incident-response guidance based "
            "on information supplied by the user. It does not replace banks, "
            "official government services, cybersecurity professionals, or law enforcement."
        )