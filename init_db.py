#!/usr/bin/env python3
"""
Database Initialization Script for AI Code Review Dashboard
Creates database tables and initial data
"""

import sys
import logging
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError
from backend.database import create_database, SessionLocal
from backend.models import *
from config import Config
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def create_mysql_database():
    """Create the MySQL database if it doesn't exist"""
    try:
        # Connect to MySQL server without specifying database
        server_url = f"mysql+pymysql://{Config.DATABASE_USER}:{Config.DATABASE_PASSWORD}@{Config.DATABASE_HOST}:{Config.DATABASE_PORT}"
        engine = create_engine(server_url)
        
        with engine.connect() as conn:
            # Create database if it doesn't exist
            conn.execute(text(f"CREATE DATABASE IF NOT EXISTS {Config.DATABASE_NAME}"))
            conn.commit()
            logger.info(f"Database '{Config.DATABASE_NAME}' created or verified to exist")
            
    except SQLAlchemyError as e:
        logger.error(f"Failed to create database: {e}")
        raise

def create_initial_user():
    """Create initial admin user"""
    db = SessionLocal()
    try:
        # Check if admin user already exists
        admin_user = db.query(User).filter(User.username == "admin").first()
        
        if not admin_user:
            admin_user = User(
                username="admin",
                email="admin@company.com",
                hashed_password="$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/lewE6aKzNpzYg1O2y",  # password: admin123
                full_name="System Administrator",
                is_active=True,
                is_admin=True
            )
            db.add(admin_user)
            db.commit()
            logger.info("Admin user created (username: admin, password: admin123)")
        else:
            logger.info("Admin user already exists")
            
    except SQLAlchemyError as e:
        logger.error(f"Failed to create admin user: {e}")
        db.rollback()
    finally:
        db.close()

def create_sample_ai_model():
    """Create sample AI model configuration"""
    db = SessionLocal()
    try:
        # Check if AI model already exists
        ai_model = db.query(AIModel).filter(AIModel.name == "Azure OpenAI GPT-4").first()
        
        if not ai_model:
            ai_model = AIModel(
                name="Azure OpenAI GPT-4",
                model_type="code_analysis",
                provider="azure_openai",
                model_id="cts-vibecode-gpt-4.1",
                endpoint=Config.AZURE_OPENAI_ENDPOINT,
                api_version=Config.AZURE_OPENAI_API_VERSION,
                temperature=0.3,
                max_tokens=2000,
                is_active=True,
                configuration={
                    "api_key": Config.AZURE_OPENAI_API_KEY,
                    "deployment_name": "cts-vibecode-gpt-4.1"
                }
            )
            db.add(ai_model)
            db.commit()
            logger.info("Azure OpenAI model configuration created")
        else:
            logger.info("AI model configuration already exists")
            
    except SQLAlchemyError as e:
        logger.error(f"Failed to create AI model: {e}")
        db.rollback()
    finally:
        db.close()

def create_sample_data():
    """Create sample data for testing"""
    db = SessionLocal()
    try:
        # Sample repository
        sample_repo = db.query(Repository).filter(Repository.name == "sample-project").first()
        
        if not sample_repo:
            sample_repo = Repository(
                name="sample-project",
                full_name="company/sample-project",
                description="Sample project for testing AI code review",
                url="https://github.com/company/sample-project",
                clone_url="https://github.com/company/sample-project.git",
                ssh_url="git@github.com:company/sample-project.git",
                default_branch="main",
                language="Python",
                is_public=False,
                platform="github",
                external_id="123456",
                owner_id=1,  # Admin user
                last_synced=datetime.utcnow()
            )
            db.add(sample_repo)
            db.commit()
            
            # Sample pull request
            sample_pr = PullRequest(
                external_id="789",
                number=1,
                title="Add user authentication feature",
                description="Implements user login and registration functionality",
                state="open",
                author="developer1",
                source_branch="feature/auth",
                target_branch="main",
                url="https://github.com/company/sample-project/pull/1",
                repository_id=sample_repo.id
            )
            db.add(sample_pr)
            
            # Sample code review
            sample_review = CodeReview(
                repository_id=sample_repo.id,
                pull_request_id=sample_pr.id,
                reviewer_id=1,  # Admin user
                review_type="automated",
                status="completed",
                overall_score=78.5,
                completed_at=datetime.utcnow()
            )
            db.add(sample_review)
            db.commit()
            
            # Sample issues
            sample_issues = [
                CodeIssue(
                    review_id=sample_review.id,
                    file_path="auth.py",
                    line_number=45,
                    issue_type="security",
                    severity="high",
                    title="Potential SQL injection vulnerability",
                    description="Direct string concatenation in SQL query without parameterization",
                    code_snippet="query = f'SELECT * FROM users WHERE username = {username}'",
                    confidence=0.85
                ),
                CodeIssue(
                    review_id=sample_review.id,
                    file_path="utils.py",
                    line_number=12,
                    issue_type="performance",
                    severity="medium",
                    title="Inefficient loop operation",
                    description="List comprehension would be more efficient than explicit loop",
                    code_snippet="result = []\nfor item in items:\n    result.append(process(item))",
                    confidence=0.75
                )
            ]
            
            for issue in sample_issues:
                db.add(issue)
            
            # Sample suggestions
            sample_suggestions = [
                CodeSuggestion(
                    review_id=sample_review.id,
                    file_path="auth.py",
                    line_number=45,
                    suggestion_type="fix",
                    title="Use parameterized query",
                    description="Replace string concatenation with parameterized query to prevent SQL injection",
                    original_code="query = f'SELECT * FROM users WHERE username = {username}'",
                    suggested_code="query = 'SELECT * FROM users WHERE username = %s'\ncursor.execute(query, (username,))",
                    impact="high",
                    confidence=0.95
                ),
                CodeSuggestion(
                    review_id=sample_review.id,
                    file_path="utils.py",
                    line_number=12,
                    suggestion_type="optimize",
                    title="Use list comprehension",
                    description="Replace explicit loop with list comprehension for better performance",
                    original_code="result = []\nfor item in items:\n    result.append(process(item))",
                    suggested_code="result = [process(item) for item in items]",
                    impact="medium",
                    confidence=0.85
                )
            ]
            
            for suggestion in sample_suggestions:
                db.add(suggestion)
            
            db.commit()
            logger.info("Sample data created successfully")
        else:
            logger.info("Sample data already exists")
            
    except SQLAlchemyError as e:
        logger.error(f"Failed to create sample data: {e}")
        db.rollback()
    finally:
        db.close()

def verify_installation():
    """Verify that the installation is working correctly"""
    db = SessionLocal()
    try:
        # Check if tables exist and have data
        user_count = db.query(User).count()
        repo_count = db.query(Repository).count()
        review_count = db.query(CodeReview).count()
        
        logger.info(f"Installation verification:")
        logger.info(f"  Users: {user_count}")
        logger.info(f"  Repositories: {repo_count}")
        logger.info(f"  Reviews: {review_count}")
        
        if user_count > 0 and repo_count > 0:
            logger.info("✅ Installation verification successful!")
            return True
        else:
            logger.warning("⚠️ Installation may be incomplete")
            return False
            
    except SQLAlchemyError as e:
        logger.error(f"Installation verification failed: {e}")
        return False
    finally:
        db.close()

def main():
    """Main initialization function"""
    logger.info("Starting AI Code Review Dashboard database initialization...")
    
    try:
        # Step 1: Create MySQL database
        logger.info("Step 1: Creating MySQL database...")
        create_mysql_database()
        
        # Step 2: Create tables
        logger.info("Step 2: Creating database tables...")
        create_database()
        
        # Step 3: Create initial user
        logger.info("Step 3: Creating initial admin user...")
        create_initial_user()
        
        # Step 4: Create AI model configuration
        logger.info("Step 4: Creating AI model configuration...")
        create_sample_ai_model()
        
        # Step 5: Create sample data
        logger.info("Step 5: Creating sample data...")
        create_sample_data()
        
        # Step 6: Verify installation
        logger.info("Step 6: Verifying installation...")
        if verify_installation():
            logger.info("🎉 Database initialization completed successfully!")
            logger.info("\n" + "="*60)
            logger.info("NEXT STEPS:")
            logger.info("1. Start the backend API: python -m uvicorn backend.main:app --reload")
            logger.info("2. Start the frontend: streamlit run frontend/dashboard.py")
            logger.info("3. Access the dashboard at: http://localhost:8501")
            logger.info("4. Admin credentials: username=admin, password=admin123")
            logger.info("="*60)
        else:
            logger.error("❌ Database initialization completed with warnings")
            sys.exit(1)
            
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 