# 🔍 AI Code Review Dashboard

A comprehensive full-stack AI-enabled code review system for IT companies, powered by Azure OpenAI, FastAPI, and Streamlit.

## 🌟 Features

### 🤖 AI-Powered Code Analysis
- **Automated Code Review**: Leverages Azure OpenAI GPT-4 for intelligent code analysis
- **Bug Detection**: Identifies logical errors, syntax issues, and potential bugs
- **Security Analysis**: Detects vulnerabilities like SQL injection, XSS, authentication flaws
- **Performance Optimization**: Suggests performance improvements and bottlenecks
- **Code Style & Best Practices**: Ensures adherence to coding standards
- **Documentation Generation**: Automatically generates code documentation

### 🔧 Git Integration
- **Multi-Platform Support**: GitHub and GitLab integration
- **Repository Management**: Fetch and manage repositories from Git platforms
- **Pull Request Analysis**: Automated PR review and feedback
- **Commit Analysis**: Review specific commits and changes
- **Real-time Sync**: Keep repositories synchronized with remote sources

### 📊 Advanced Dashboard
- **Interactive UI**: Modern, responsive Streamlit-based dashboard
- **Real-time Analytics**: Code quality metrics and trends
- **Issue Tracking**: Comprehensive issue management with severity levels
- **Suggestion Management**: AI-generated improvement suggestions
- **Progress Monitoring**: Track analysis progress and status
- **Export Capabilities**: Export reports and analysis results

### 🛠️ Enterprise Features
- **Role-based Access Control**: User management and permissions
- **API-First Architecture**: RESTful APIs for integration
- **Scalable Backend**: FastAPI with async support
- **Database Storage**: Persistent storage with MySQL
- **Background Processing**: Async analysis for large codebases
- **Extensible AI Models**: Support for multiple AI providers

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│                 │    │                 │    │                 │
│   Streamlit     │    │     FastAPI     │    │   Azure OpenAI  │
│   Frontend      │◄──►│     Backend     │◄──►│   AI Service    │
│                 │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       
         │                       │                       
         ▼                       ▼                       
┌─────────────────┐    ┌─────────────────┐              
│                 │    │                 │              
│   Web Browser   │    │   MySQL         │              
│   Dashboard     │    │   Database      │              
│                 │    │                 │              
└─────────────────┘    └─────────────────┘              
         │                       │                       
         │                       │                       
         ▼                       ▼                       
┌─────────────────┐    ┌─────────────────┐              
│                 │    │                 │              
│   GitHub/       │    │   File System   │              
│   GitLab APIs   │    │   Storage       │              
│                 │    │                 │              
└─────────────────┘    └─────────────────┘              
```

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- MySQL 5.7+ or 8.0+
- Git
- Azure OpenAI API access

### 1. Installation

```bash
# Clone the repository
git clone <your-repo-url>
cd Code_Review

# Install dependencies
pip install -r requirements.txt
```

### 2. Database Setup

Make sure MySQL is running and accessible with the credentials in `config.py`:
- Host: `localhost:3306`
- Username: `root`
- Password: `root`

### 3. Initialize Database

```bash
# Initialize database and create tables
python init_db.py
```

This will:
- Create the `code_review_db` database
- Set up all required tables
- Create an admin user (username: `admin`, password: `admin123`)
- Add sample data for testing

### 4. Start the Application

#### Option A: Start Both Services Separately

**Terminal 1 - Backend API:**
```bash
python run_backend.py
```

**Terminal 2 - Frontend Dashboard:**
```bash
python run_frontend.py
```

#### Option B: Manual Startup

**Backend:**
```bash
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

**Frontend:**
```bash
streamlit run frontend/dashboard.py --server.port 8501
```

### 5. Access the Application

- **Dashboard**: http://localhost:8501
- **API Documentation**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

## 📖 Usage Guide

### Initial Setup

1. **Access the Dashboard**: Open http://localhost:8501
2. **Configure Git Tokens**: 
   - Go to Settings page
   - Add your GitHub/GitLab tokens in `config.py`
   - Update `GITHUB_TOKEN` and `GITLAB_TOKEN` variables

### Repository Management

1. **Fetch Repositories**:
   - Navigate to "Repositories" page
   - Select platform (GitHub/GitLab)
   - Enter username/organization
   - Click "Fetch Repositories"

2. **Start Analysis**:
   - Select a repository
   - Click "Start Analysis"
   - Monitor progress in Analytics page

### Code Analysis Types

#### 1. Single File Analysis
- Upload a code file
- Get instant AI feedback
- View issues and suggestions

#### 2. Repository Analysis
- Analyze entire repositories
- Batch processing of multiple files
- Comprehensive reporting

#### 3. Pull Request Analysis
- Automated PR review
- Change-focused analysis
- Integration with Git workflows

### Understanding Results

#### Issue Severity Levels
- **Critical**: Security vulnerabilities, major bugs
- **High**: Performance issues, important bugs
- **Medium**: Code style, minor optimizations
- **Low**: Suggestions, cosmetic improvements

#### Suggestion Types
- **Fix**: Bug fixes and corrections
- **Optimize**: Performance improvements
- **Refactor**: Code structure improvements
- **Document**: Documentation additions

## 🔧 Configuration

### Environment Variables

Update `config.py` with your settings:

```python
# Azure OpenAI Configuration
AZURE_OPENAI_ENDPOINT = "your-endpoint"
AZURE_OPENAI_API_KEY = "your-api-key"

# GitHub/GitLab Tokens
GITHUB_TOKEN = "your-github-token"
GITLAB_TOKEN = "your-gitlab-token"

# Database Configuration
DATABASE_USER = "root"
DATABASE_PASSWORD = "root"
DATABASE_HOST = "localhost"
DATABASE_NAME = "code_review_db"
```

### GitHub Token Setup

1. Go to GitHub Settings → Developer settings → Personal access tokens
2. Create new token with these scopes:
   - `repo` (for private repositories)
   - `public_repo` (for public repositories)
   - `read:org` (for organization access)

### GitLab Token Setup

1. Go to GitLab User Settings → Access Tokens
2. Create token with these scopes:
   - `read_api`
   - `read_repository`

## 📊 API Reference

### Core Endpoints

#### Repositories
- `GET /api/repositories` - List repositories
- `GET /api/repositories/{repo_id}/pull-requests` - Get PRs

#### Analysis
- `POST /api/analyze/repository/{repo_id}` - Start repo analysis
- `POST /api/analyze/pull-request/{pr_id}` - Start PR analysis
- `POST /api/analyze/file` - Analyze single file

#### Reviews
- `GET /api/reviews/{review_id}` - Get review details
- `GET /api/reviews/{review_id}/status` - Get review status

#### Analytics
- `GET /api/analytics/dashboard` - Dashboard metrics

## 🏢 Enterprise Deployment

### Docker Deployment

Create `docker-compose.yml`:

```yaml
version: '3.8'
services:
  db:
    image: mysql:8.0
    environment:
      MYSQL_ROOT_PASSWORD: root
      MYSQL_DATABASE: code_review_db
    ports:
      - "3306:3306"
    volumes:
      - mysql_data:/var/lib/mysql

  backend:
    build: .
    ports:
      - "8000:8000"
    depends_on:
      - db
    environment:
      - DATABASE_HOST=db

  frontend:
    build: -f Dockerfile.frontend .
    ports:
      - "8501:8501"
    depends_on:
      - backend

volumes:
  mysql_data:
```

### Azure Deployment

1. **Azure App Service**: Deploy backend as web app
2. **Azure Container Instances**: Deploy frontend
3. **Azure Database for MySQL**: Managed database
4. **Azure Key Vault**: Secure configuration storage

### Production Considerations

- Use environment variables for sensitive data
- Set up SSL/TLS certificates
- Configure load balancing for high availability
- Implement logging and monitoring
- Set up backup and disaster recovery

## 🧪 Testing

### Run Tests

```bash
# Backend tests
python -m pytest backend/tests/

# Frontend tests
python -m pytest frontend/tests/
```

### Manual Testing

1. **API Testing**: Use `/docs` endpoint for interactive testing
2. **Frontend Testing**: Use sample data created by `init_db.py`
3. **Integration Testing**: Test full workflow from repo fetch to analysis

## 🔒 Security

### Best Practices Implemented

- **API Authentication**: JWT-based authentication
- **Input Validation**: Comprehensive request validation
- **SQL Injection Prevention**: Parameterized queries
- **CORS Configuration**: Proper cross-origin settings
- **Rate Limiting**: API rate limiting (configurable)

### Security Configuration

Update production settings:
- Change default admin password
- Use strong secret keys
- Enable HTTPS only
- Configure firewall rules
- Regular security updates

## 🐛 Troubleshooting

### Common Issues

#### Database Connection Failed
```bash
# Check MySQL status
systemctl status mysql

# Test connection
mysql -u root -p -h localhost
```

#### Azure OpenAI API Errors
- Verify API key and endpoint
- Check quota and rate limits
- Ensure proper API version

#### Git Integration Issues
- Verify tokens have correct permissions
- Check repository accessibility
- Ensure network connectivity

#### Memory Issues with Large Repositories
- Increase system memory
- Limit file analysis (modify background tasks)
- Use file filtering options

### Debug Mode

Enable debug logging in `config.py`:
```python
DEBUG = True
```

View logs:
```bash
# Backend logs
tail -f backend.log

# Frontend logs (in terminal)
```

## 🤝 Contributing

### Development Setup

1. **Fork the repository**
2. **Create feature branch**: `git checkout -b feature/amazing-feature`
3. **Install dev dependencies**: `pip install -r requirements-dev.txt`
4. **Make changes**
5. **Run tests**: `python -m pytest`
6. **Commit changes**: `git commit -m 'Add amazing feature'`
7. **Push branch**: `git push origin feature/amazing-feature`
8. **Create Pull Request**

### Code Standards

- Follow PEP 8 for Python code
- Use type hints
- Add docstrings for functions
- Write tests for new features
- Update documentation

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Azure OpenAI**: For powerful AI capabilities
- **FastAPI**: For the excellent API framework
- **Streamlit**: For rapid dashboard development
- **SQLAlchemy**: For robust database ORM
- **PyGithub/python-gitlab**: For Git platform integration

## 📞 Support

### Documentation
- **API Docs**: http://localhost:8000/docs
- **User Guide**: See Usage Guide section above

### Community
- **Issues**: Use GitHub Issues for bug reports
- **Discussions**: Use GitHub Discussions for questions
- **Email**: [your-email@company.com]

### Professional Support
Contact us for enterprise support, custom integrations, and training.

---

**Built with ❤️ for better code quality** 

## Azure DevOps CI (pipeline)

This repo includes a minimal `azure-pipelines.yml` to build and package the app:
- Install Python and dependencies
- Lint and run a basic sanity check
- Publish build artifacts (frontend and backend sources)

Update variables and service connections as needed for your environment. 