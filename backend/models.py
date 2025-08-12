from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, ForeignKey, Float, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from backend.database import Base
from datetime import datetime
from typing import Optional

class User(Base):
    """User model for authentication and authorization"""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(100))
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    github_username = Column(String(100))
    gitlab_username = Column(String(100))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    repositories = relationship("Repository", back_populates="owner")
    reviews = relationship("CodeReview", back_populates="reviewer")

class Repository(Base):
    """Repository model for storing Git repository information"""
    __tablename__ = "repositories"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=False)  # owner/repo
    description = Column(Text)
    url = Column(String(500), nullable=False)
    clone_url = Column(String(500))
    ssh_url = Column(String(500))
    default_branch = Column(String(100), default="main")
    language = Column(String(50))
    is_public = Column(Boolean, default=True)
    is_active = Column(Boolean, default=True)
    platform = Column(String(20), nullable=False)  # github, gitlab, etc.
    external_id = Column(String(100))  # GitHub/GitLab repo ID
    owner_id = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    last_synced = Column(DateTime(timezone=True))
    
    # Relationships
    owner = relationship("User", back_populates="repositories")
    pull_requests = relationship("PullRequest", back_populates="repository")
    reviews = relationship("CodeReview", back_populates="repository")

class PullRequest(Base):
    """Pull Request model for storing PR information"""
    __tablename__ = "pull_requests"
    
    id = Column(Integer, primary_key=True, index=True)
    external_id = Column(String(100), nullable=False)  # GitHub/GitLab PR ID
    number = Column(Integer, nullable=False)
    title = Column(String(500), nullable=False)
    description = Column(Text)
    state = Column(String(20), nullable=False)  # open, closed, merged
    author = Column(String(100), nullable=False)
    source_branch = Column(String(255), nullable=False)
    target_branch = Column(String(255), nullable=False)
    url = Column(String(500), nullable=False)
    repository_id = Column(Integer, ForeignKey("repositories.id"))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    merged_at = Column(DateTime(timezone=True))
    closed_at = Column(DateTime(timezone=True))
    
    # Relationships
    repository = relationship("Repository", back_populates="pull_requests")
    reviews = relationship("CodeReview", back_populates="pull_request")

class CodeReview(Base):
    """Code Review model for storing AI analysis results"""
    __tablename__ = "code_reviews"
    
    id = Column(Integer, primary_key=True, index=True)
    repository_id = Column(Integer, ForeignKey("repositories.id"))
    pull_request_id = Column(Integer, ForeignKey("pull_requests.id"), nullable=True)
    reviewer_id = Column(Integer, ForeignKey("users.id"))
    commit_hash = Column(String(255))
    file_path = Column(String(1000))
    review_type = Column(String(50), nullable=False)  # automated, manual, hybrid
    status = Column(String(20), default="pending")  # pending, in_progress, completed, failed
    overall_score = Column(Float)  # 0-100
    summary = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    completed_at = Column(DateTime(timezone=True))
    
    # Relationships
    repository = relationship("Repository", back_populates="reviews")
    pull_request = relationship("PullRequest", back_populates="reviews")
    reviewer = relationship("User", back_populates="reviews")
    issues = relationship("CodeIssue", back_populates="review")
    suggestions = relationship("CodeSuggestion", back_populates="review")

class CodeIssue(Base):
    """Code Issue model for storing detected problems"""
    __tablename__ = "code_issues"
    
    id = Column(Integer, primary_key=True, index=True)
    review_id = Column(Integer, ForeignKey("code_reviews.id"))
    file_path = Column(String(1000), nullable=False)
    line_number = Column(Integer)
    end_line_number = Column(Integer)
    issue_type = Column(String(50), nullable=False)  # bug, security, performance, style
    severity = Column(String(20), nullable=False)  # critical, high, medium, low
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=False)
    code_snippet = Column(Text)
    rule_id = Column(String(100))
    confidence = Column(Float)  # 0-1
    is_false_positive = Column(Boolean, default=False)
    is_resolved = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    resolved_at = Column(DateTime(timezone=True))
    
    # Relationships
    review = relationship("CodeReview", back_populates="issues")

class CodeSuggestion(Base):
    """Code Suggestion model for storing AI-generated improvements"""
    __tablename__ = "code_suggestions"
    
    id = Column(Integer, primary_key=True, index=True)
    review_id = Column(Integer, ForeignKey("code_reviews.id"))
    file_path = Column(String(1000), nullable=False)
    line_number = Column(Integer)
    end_line_number = Column(Integer)
    suggestion_type = Column(String(50), nullable=False)  # refactor, optimize, document, fix
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=False)
    original_code = Column(Text)
    suggested_code = Column(Text)
    impact = Column(String(20))  # high, medium, low
    confidence = Column(Float)  # 0-1
    is_applied = Column(Boolean, default=False)
    is_accepted = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    applied_at = Column(DateTime(timezone=True))
    
    # Relationships
    review = relationship("CodeReview", back_populates="suggestions")

class ReviewMetrics(Base):
    """Review Metrics model for storing analytics data"""
    __tablename__ = "review_metrics"
    
    id = Column(Integer, primary_key=True, index=True)
    repository_id = Column(Integer, ForeignKey("repositories.id"))
    date = Column(DateTime(timezone=True), nullable=False)
    total_reviews = Column(Integer, default=0)
    automated_reviews = Column(Integer, default=0)
    manual_reviews = Column(Integer, default=0)
    issues_found = Column(Integer, default=0)
    critical_issues = Column(Integer, default=0)
    high_issues = Column(Integer, default=0)
    medium_issues = Column(Integer, default=0)
    low_issues = Column(Integer, default=0)
    suggestions_made = Column(Integer, default=0)
    suggestions_applied = Column(Integer, default=0)
    average_review_time = Column(Float)  # in minutes
    code_quality_score = Column(Float)  # 0-100
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class AIModel(Base):
    """AI Model configuration for different analysis tasks"""
    __tablename__ = "ai_models"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    model_type = Column(String(50), nullable=False)  # code_analysis, suggestion, documentation
    provider = Column(String(50), nullable=False)  # azure_openai, openai, custom
    model_id = Column(String(100), nullable=False)
    endpoint = Column(String(500))
    api_version = Column(String(20))
    temperature = Column(Float, default=0.3)
    max_tokens = Column(Integer, default=1000)
    is_active = Column(Boolean, default=True)
    configuration = Column(JSON)  # Additional model-specific config
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now()) 