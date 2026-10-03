# Cyber Risk Quantification Platform

An AI-powered continuous cyber risk quantification and investment optimization platform. 

## Quick Start

Open two terminals and run the following commands:

**Terminal 1: Backend**
```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Add your GEMINI_API_KEY to .env
uvicorn main:app --reload
```

**Terminal 2: Frontend**
```bash
cd frontend
npm install
npm run dev
```

Visit `http://localhost:5173` to view the application.
