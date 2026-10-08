# ScamRoute AI

ScamRoute AI is an AI-assisted scam incident response tool that helps users understand suspicious messages, calls, links, and fraud attempts.

Instead of only saying whether something is a scam, the system analyzes the incident, identifies risk indicators, estimates the severity, reconstructs the possible attack chain, and provides practical next steps.

## Features

- Scam and threat classification
- Risk score from 0–100
- Severity assessment
- Detection of suspicious indicators
- Financial, account, device, and identity risk analysis
- Attack-chain reconstruction
- Explanation of why the incident was flagged
- Personalized response guidance
- Evidence preservation checklist
- Verification guidance
- Downloadable incident report

## How It Works

1. The user describes the suspicious incident.
2. ScamRoute AI extracts relevant risk indicators.
3. The incident is classified into a suitable threat category.
4. A risk score and severity level are calculated.
5. The system identifies the possible attack chain and affected risk areas.
6. The user receives recommended actions to reduce further damage.

## Example

A user may report:

> Someone claiming to be my bank called me and said my account would be blocked. They sent me a link and asked for my OTP. I entered the OTP and transferred ₹20,000.

ScamRoute AI can identify indicators such as impersonation, suspicious links, OTP exposure, and financial loss, then provide an appropriate response route.

## Technology

- Python
- Streamlit
- OpenAI API
- Python-dotenv

## Running Locally

Clone the repository and install the required packages.

```bash
python -m pip install streamlit openai python-dotenv
```

Create a `.env` file and add the required API configuration.

Then run:

```bash
python -m streamlit run app.py
```

The application will open in the browser.

## Project Structure

```text
ScamRoute-AI/
│
├── app.py
├── .gitignore
└── README.md
```

## Purpose

ScamRoute AI is designed as a practical first-response assistant for people who encounter potential scams. It focuses on helping users understand what may have happened and what actions they should take next.