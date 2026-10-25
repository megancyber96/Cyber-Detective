# Cyber Detective 🕵️

**Cyber Detective v1.0** is a Streamlit app for inspecting suspicious patterns in URL text. It assigns a heuristic risk score, shows visual alerts, keeps a short session-only scan history, and exports JSON reports.

**Designed & Developed by Megan © 2026**

## Features

- URL syntax validation and offline heuristic inspection
- Indicators for brand-like hostnames, HTTP, IP-address hosts, Punycode, URL userinfo, long URLs, and encoded hostname characters
- LOW / MEDIUM / HIGH risk categories and a visual risk gauge
- Up to 25 recent scans stored in Streamlit session state
- Downloadable scan and history JSON reports
- Dark-themed dashboard

## Run locally

Requires Python 3.10+.

```bash
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

## Example

Try `https://paypal-login.example.org` to demonstrate a suspicious-looking hostname. This example is for testing the heuristic, not a confirmed malicious website.

## Limitations

**This is an educational URL-text heuristic tool, not an antivirus or a full security scanner.** It does not visit URLs, check threat-intelligence databases, verify TLS, or detect malware. A LOW score does **not** mean a website is safe; a HIGH score is not proof that it is malicious. The radar is decorative. Scores are indicators, not probabilities.

Scan history is stored only for the current Streamlit session, not persisted to disk.
