#!/usr/bin/env python3
"""
Git Service Module
Handles Git operations including repository cloning, file access, and GitHub/GitLab integration.
"""

import os
import sys
import tempfile
import logging
import requests
import shutil
from typing import List, Dict, Any, Optional
from git import Repo, GitCommandError
from github import Github, GithubException
from gitlab import Gitlab, GitlabError

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Config

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class GitService:
    """
    Service for handling Git operations and repository management.
    Supports GitHub and GitLab integration with comprehensive error handling.
    """
    
    def __init__(self):
        """Initialize Git service with configuration."""
        self.github_token = Config.GITHUB_TOKEN
        self.github_client = None
        self.gitlab_client = None
        
        # Initialize GitHub client if token is available
        if self.github_token:
            try:
                self.github_client = Github(self.github_token)
                logger.info("✅ GitHub client initialized successfully")
            except Exception as e:
                logger.error(f"Failed to initialize GitHub client: {e}")
        
        # Initialize GitLab client if needed
        # self.gitlab_client = Gitlab(url='https://gitlab.com', private_token=Config.GITLAB_TOKEN)
    
    def refresh_github_client(self, new_token: Optional[str] = None) -> bool:
        """Refresh GitHub client with new token from environment or parameter."""
        try:
            # Use provided token or get from environment
            token = new_token or os.getenv("GITHUB_TOKEN")
            
            if token and token != self.github_token:
                self.github_token = token
                self.github_client = Github(token)
                logger.info("✅ GitHub client refreshed with new token")
                return True
            elif token == self.github_token:
                logger.info("ℹ️ GitHub token unchanged, no refresh needed")
                return True
            else:
                logger.warning("⚠️ No GitHub token available for refresh")
                return False
                
        except Exception as e:
            logger.error(f"❌ Failed to refresh GitHub client: {e}")
            return False
    
    def get_user_repositories(self, platform: str = "github") -> List[Dict[str, Any]]:
        """
        Fetch user repositories from the specified platform.
        
        Args:
            platform: The Git platform ("github" or "gitlab")
            
        Returns:
            List of repository dictionaries with metadata
        """
        try:
            if platform.lower() == "github":
                return self._get_github_repositories()
            elif platform.lower() == "gitlab":
                return self._get_gitlab_repositories()
            else:
                logger.error(f"Unsupported platform: {platform}")
                return []
        except Exception as e:
            logger.error(f"Error fetching repositories from {platform}: {e}")
            return []
    
    def _get_github_repositories(self) -> List[Dict[str, Any]]:
        """Fetch repositories from GitHub."""
        if not self.github_client:
            logger.error("GitHub client not initialized")
            return []
        
        try:
            user = self.github_client.get_user()
            repos = []
            
            for repo in user.get_repos():
                # Handle potential None values safely
                created_at = repo.created_at.isoformat() if repo.created_at else None
                updated_at = repo.updated_at.isoformat() if repo.updated_at else None
                
                repos.append({
                    "id": repo.id,
                    "name": repo.name,
                    "full_name": repo.full_name,
                    "description": repo.description or "",
                    "url": repo.html_url,
                    "language": repo.language or "Unknown",
                    "created_at": created_at,
                    "updated_at": updated_at,
                    "private": repo.private,
                    "fork": repo.fork,
                    "stars": repo.stargazers_count,
                    "forks": repo.forks_count
                })
            
            logger.info(f"Successfully fetched {len(repos)} GitHub repositories")
            return repos
            
        except GithubException as e:
            logger.error(f"GitHub API error: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error fetching GitHub repositories: {e}")
            return []
    
    def _get_gitlab_repositories(self) -> List[Dict[str, Any]]:
        """Fetch repositories from GitLab."""
        if not self.gitlab_client:
            logger.warning("GitLab client not initialized")
            return []
        
        try:
            projects = self.gitlab_client.projects.list()
            repos = []
            
            # Ensure projects is properly typed as a list
            if projects and hasattr(projects, '__iter__'):
                for project in projects:
                    repos.append({
                        "id": project.id,
                        "name": project.name,
                        "full_name": project.path_with_namespace,
                        "description": project.description or "",
                        "url": project.web_url,
                        "language": getattr(project, 'default_branch', None),
                        "platform": "gitlab",
                        "stars": getattr(project, 'star_count', 0),
                        "updated_at": getattr(project, 'last_activity_at', None)
                    })
            
            return repos
            
        except GitlabError as e:
            logger.error(f"GitLab API error: {e}")
            return []
        except Exception as e:
            logger.error(f"Error fetching GitLab repositories: {e}")
            return []
    
    def clone_repository(self, repo_url: str, target_dir: str) -> Optional[str]:
        """
        Clone a repository to the specified directory.
        
        Args:
            repo_url: The repository URL to clone
            target_dir: The target directory for cloning
            
        Returns:
            Path to the cloned repository or None if failed
        """
        try:
            logger.info(f"Cloning repository: {repo_url}")
            
            # Create target directory if it doesn't exist
            os.makedirs(target_dir, exist_ok=True)
            
            # Clone the repository
            repo = Repo.clone_from(repo_url, target_dir)
            
            logger.info(f"Successfully cloned repository to: {target_dir}")
            return target_dir
            
        except GitCommandError as e:
            logger.error(f"Git command error during cloning: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error during cloning: {e}")
            return None
    
    def get_repository_files(self, repo_path: str, file_extensions: Optional[List[str]] = None) -> List[str]:
        """
        Get all files in a repository with specified extensions.
        
        Args:
            repo_path: Path to the repository
            file_extensions: List of file extensions to include (e.g., ['.py', '.js'])
            
        Returns:
            List of file paths
        """
        if file_extensions is None:
            file_extensions = ['.py', '.js', '.ts', '.java', '.go', '.cs']
        
        files = []
        
        try:
            for root, dirs, filenames in os.walk(repo_path):
                # Skip common directories that shouldn't be analyzed
                dirs[:] = [d for d in dirs if d not in ['.git', '__pycache__', 'node_modules', 'venv', '.venv', 'build', 'dist']]
                
                for filename in filenames:
                    file_path = os.path.join(root, filename)
                    _, ext = os.path.splitext(filename)
                    
                    if ext.lower() in file_extensions:
                        files.append(file_path)
            
            logger.info(f"Found {len(files)} files to analyze in {repo_path}")
            return files
            
        except Exception as e:
            logger.error(f"Error getting repository files: {e}")
            return []
    
    def get_file_content(self, file_path: str) -> Optional[str]:
        """
        Read the content of a file.
        
        Args:
            file_path: Path to the file
            
        Returns:
            File content as string or None if failed
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            return content
        except UnicodeDecodeError:
            # Try with different encoding
            try:
                with open(file_path, 'r', encoding='latin-1') as f:
                    content = f.read()
                return content
            except Exception as e:
                logger.error(f"Failed to read file {file_path} with any encoding: {e}")
                return None
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
            return None
    
    def get_pull_request_diff(self, repo_full_name: str, pr_number: int, platform: str = "github") -> Optional[str]:
        """
        Get the diff content for a pull request.
        
        Args:
            repo_full_name: Full name of the repository (e.g., "owner/repo")
            pr_number: Pull request number
            platform: Git platform ("github" or "gitlab")
            
        Returns:
            Diff content as string or None if failed
        """
        try:
            if platform.lower() == "github":
                return self._get_github_pr_diff(repo_full_name, pr_number)
            elif platform.lower() == "gitlab":
                return self._get_gitlab_pr_diff(repo_full_name, pr_number)
            else:
                logger.error(f"Unsupported platform: {platform}")
                return None
        except Exception as e:
            logger.error(f"Error getting pull request diff: {e}")
            return None
    
    def _get_github_pr_diff(self, repo_full_name: str, pr_number: int) -> Optional[str]:
        """Get pull request diff from GitHub."""
        if not self.github_client:
            logger.error("GitHub client not initialized")
            return None
        
        try:
            repo = self.github_client.get_repo(repo_full_name)
            pr = repo.get_pull(pr_number)
            
            # Get the diff content
            diff_content = pr.get_files()
            
            # Format the diff content
            formatted_diff = []
            for file in diff_content:
                formatted_diff.append(f"--- {file.filename}")
                formatted_diff.append(f"+++ {file.filename}")
                formatted_diff.append(file.patch or "")
                formatted_diff.append("")
            
            return "\n".join(formatted_diff)
            
        except GithubException as e:
            logger.error(f"GitHub API error getting PR diff: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error getting GitHub PR diff: {e}")
            return None
    
    def _get_gitlab_pr_diff(self, repo_full_name: str, pr_number: int) -> Optional[str]:
        """Get pull request diff from GitLab."""
        if not self.gitlab_client:
            logger.error("GitLab client not initialized")
            return None
        
        try:
            # GitLab uses merge requests instead of pull requests
            project = self.gitlab_client.projects.get(repo_full_name)
            mr = project.mergerequests.get(pr_number)
            
            # Get the diff content
            changes = mr.changes()
            
            # Format the diff content
            formatted_diff = []
            for change in changes['changes']:
                formatted_diff.append(f"--- {change['old_path']}")
                formatted_diff.append(f"+++ {change['new_path']}")
                formatted_diff.append(change.get('diff', ''))
                formatted_diff.append("")
            
            return "\n".join(formatted_diff)
            
        except GitlabError as e:
            logger.error(f"GitLab API error getting MR diff: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error getting GitLab MR diff: {e}")
            return None
    
    def cleanup_repository(self, repo_path: str) -> None:
        """
        Clean up a cloned repository by removing the directory.
        
        Args:
            repo_path: Path to the repository to clean up
        """
        try:
            if os.path.exists(repo_path):
                shutil.rmtree(repo_path)
                logger.info(f"Cleaned up repository: {repo_path}")
        except Exception as e:
            logger.error(f"Error cleaning up repository {repo_path}: {e}")
    
    def get_commit_history(self, repo_path: str, file_path: str = None, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get commit history for a repository or specific file.
        
        Args:
            repo_path: Path to the repository
            file_path: Optional specific file path
            limit: Maximum number of commits to return
            
        Returns:
            List of commit dictionaries
        """
        try:
            repo = Repo(repo_path)
            commits = []
            
            if file_path:
                # Get commits for specific file
                for commit in repo.iter_commits(paths=file_path, max_count=limit):
                    commits.append({
                        "hash": commit.hexsha,
                        "author": commit.author.name,
                        "email": commit.author.email,
                        "date": commit.committed_datetime.isoformat(),
                        "message": commit.message.strip(),
                        "files": list(commit.stats.files.keys())
                    })
            else:
                # Get all commits
                for commit in repo.iter_commits(max_count=limit):
                    commits.append({
                        "hash": commit.hexsha,
                        "author": commit.author.name,
                        "email": commit.author.email,
                        "date": commit.committed_datetime.isoformat(),
                        "message": commit.message.strip(),
                        "files": list(commit.stats.files.keys())
                    })
            
            return commits
            
        except Exception as e:
            logger.error(f"Error getting commit history: {e}")
            return [] 