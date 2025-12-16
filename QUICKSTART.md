# Quick Start Guide

## Installation Steps

1. **Install Python Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Get Google AI API Key**
   - Visit: https://makersuite.google.com/app/apikey
   - Create a new API key
   - Copy the key

3. **Create Environment File**
   Create a `.env` file in the project root:
   ```env
   GEMINI_API_KEY=your_actual_api_key_here
   ```

4. **Run the Application**
   ```bash
   streamlit run app.py
   ```

   The app will open at: http://localhost:8501

## First Audit

1. **Enter API Key** (if not in .env file)
   - Paste your Google AI API key in the sidebar

2. **Configure Test Settings**
   - Number of tests: Start with 20
   - Select vulnerability types: Choose SQL Injection, XSS, CSRF
   - (Optional) Add custom payloads

3. **Run Audit**
   - Click "🚀 Run Security Audit"
   - Wait for fuzzing to complete
   - Wait for AI analysis to complete

4. **Review Results**
   - Check the overview metrics
   - Review vulnerability findings table
   - Explore analytics charts
   - Read detailed findings with remediation advice

5. **Download Report**
   - Click "📥 Download PDF Report"
   - Save the professional PDF report

## Troubleshooting

### API Key Issues
- Ensure your API key is correct
- Check API quota/limits on Google AI Studio
- Verify internet connection

### Flask Server Errors
- Ensure port 5000 is not in use
- Change `FLASK_PORT` in `.env` if needed

### Import Errors
- Ensure all dependencies are installed: `pip install -r requirements.txt`
- Check Python version: `python --version` (should be 3.8+)

### Database Errors
- Ensure `data/` directory exists and is writable
- Check file permissions

## Next Steps

- Review the README.md for detailed documentation
- Explore different vulnerability types
- Add custom payloads for specific testing
- Review audit history in the database

