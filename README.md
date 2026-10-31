# 🛡️ PhishGuard - AI-Powered Phishing URL Detection System

[![Live Demo](https://img.shields.io/badge/Live_Demo-Render-46E3B7?style=for-the-badge&logo=render)](https://phishguard-f2vi.onrender.com)
[![Python](https://img.shields.io/badge/Python-3.13+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)](https://streamlit.io/)
[![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)

**PhishGuard** is a real-time cybersecurity web application that detects malicious and phishing URLs using Machine Learning, lexical feature extraction, and live network/domain intelligence checks.

🔗 **Live Application:** [https://phishguard-f2vi.onrender.com](https://phishguard-f2vi.onrender.com)

---

## 🚀 Key Features

* **🤖 ML-Based URL Classification:** Predicts whether a URL is legitimate or a phishing attempt using a pre-trained Scikit-Learn model (`url_model.pkl`).
* **🔍 Lexical & Structural Feature Extraction:** Analyzes URL length, special characters, subdomains, TLD structure, and suspicious patterns (`features.py`).
* **🌐 Live Domain & Webpage Verification:** Performs real-time WHOIS lookups, domain age checks, HTTP response inspection, and HTML DOM scraping (`live_checks.py`).
* **🗄️ Scan History & Logging:** Automatically logs scanned URLs and prediction results into a local SQLite database (`db.py` / `phishguard.db`).
* **📊 Interactive Dashboard:** Clean, responsive web interface built with Streamlit for instant URL scanning and security breakdown (`app.py`).

---

## 🛠️ Tech Stack & Libraries Used

| Category | Technology / Library | Purpose |
| :--- | :--- | :--- |
| **Frontend / UI** | `Streamlit` | Interactive web dashboard and user interface |
| **Machine Learning** | `Scikit-Learn` (`1.9.1`), `Joblib` | Model training, serialization, and real-time inference |
| **Data Processing** | `NumPy`, `Pandas` | Feature vector manipulation and structured data handling |
| **Domain Intelligence** | `python-whois`, `tldextract` | WHOIS registration queries and Top-Level Domain (TLD) parsing |
| **Web Scraping & Network** | `Requests`, `BeautifulSoup4` | Live HTTP status verification and HTML content inspection |
| **Database** | `SQLite3` | Lightweight relational storage for scan logs and history |
| **Deployment** | `Render` | Cloud hosting with automated CI/CD from GitHub |

---

## 📂 Project Structure

```text
Phishguard/
├── app.py               # Main Streamlit web application entry point
├── features.py          # URL lexical and structural feature extraction pipeline
├── live_checks.py       # Real-time WHOIS, DNS, and HTTP/HTML security checks
├── db.py                # SQLite database initialization and query functions
├── url_model.pkl        # Pre-trained Scikit-Learn phishing detection model
├── requirements.txt     # Python dependencies required for deployment
└── .gitignore           # Ignored files (__pycache__, *.pyc, *.db)


Run Locally
Clone the repository:
Bash
git clone [https://github.com/shubhamkrmu/Phishguard.git](https://github.com/shubhamkrmu/Phishguard.git)
cd Phishguard
Install dependencies:

Bash
pip install -r requirements.txt
Run the Streamlit app:

Bash
streamlit run app.py
Open your browser at http://localhost:8501.

👨‍💻 Author
Shubham

GitHub: @shubhamkrmu
