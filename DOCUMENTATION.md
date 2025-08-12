# AI Code Review Dashboard - Documentation

## Overview
An AI-enabled platform to analyze code, review pull requests, and provide security/compliance insights.

## Features
- Dashboard with metrics and trends
- Code Analysis with progress, results, and downloadable report
- Auto-Fix Suggestions (experimental) for pasted code
- PR Review: analyze pull requests by URL (GitHub/GitLab/Bitbucket/Azure DevOps)
- Reviews history with HTML report downloads
- Repositories: fetch and trigger full repo analysis
- Compliance: SOC2, HIPAA, GDPR, OWASP status and recommendations
- AI Assistant chat (contextual helper)

## Quick Start (Local)
1. Python 3.11 recommended
2. Install dependencies:
   - `python -m pip install --upgrade pip`
   - `python -m pip install -r requirements.txt`
3. Start backend:
   - `python backend/main.py` (FastAPI on 8000)
4. Start frontend:
   - `python frontend/app.py` (Flask on 5000)
5. Visit `http://127.0.0.1:5000` (Login: admin/admin123)

## Key Pages
- Dashboard: `/`
- Code Analysis: `/code-analysis`
  - Paste code → Analyze → View results → Download report
  - Auto-Fix Suggestions button to get fixes
- PR Review: `/pr-review`
  - Enter PR URL → Analyze → View findings → Export
- Repositories: `/repositories`
  - Fetch repos → Analyze repo → See results under Reviews
- Reviews: `/reviews` and `/reviews/<id>`
  - View results, download HTML report
- AI Assistant: `/ai-assistant`
- Compliance: `/compliance`
- Settings: `/settings`

## Backend API
- File analysis: `POST /api/analyze/file { code, file_path, language }`
- Review status: `GET /api/reviews/{id}/status`
- Review details: `GET /api/reviews/{id}`
- Review download: `GET /api/reviews/{id}/download`
- Repo analysis: `POST /api/analyze/repository/{repo_id}`
- PR analysis: `POST /api/pr/analyze?platform=github|gitlab|bitbucket|azuredevops`
- Auto-fix analysis: `POST /api/autofix/analyze { file_path, content, language }`
- Compliance report: `GET /api/compliance/report`

## Production Notes
- Configure secrets via environment variables, not files
- Run behind a reverse proxy; enable TLS; set proper CORS
- Use a production WSGI server (e.g., `waitress-serve` for Windows) for Flask
- Rotate logs and avoid storing tokens on disk

## Azure DevOps CI
- Pipeline file: `azure-pipelines.yml`
- Steps:
  - Select Python version
  - Install dependencies
  - Sanity check
  - Publish artifacts
- Extend with deployment stages as needed (App Service/VM/Containers)

## Security
- No secrets committed to repo
- Token file `github_token.json` removed
- Backend sanitizes requests and uses timeouts for external calls

## Troubleshooting
- 500 errors on pages: check `frontend/templates/base.html` integrity and server logs
- Analysis hangs: ensure backend is running and reachable from frontend
- Repo analysis requires GitHub token in backend env (`GITHUB_TOKEN`)

## License
Internal project for coding competition—custom license as applicable. 