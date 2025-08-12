#!/usr/bin/env python3
"""
Multi-Platform Integration Service
Supports GitHub, GitLab, Bitbucket, Azure DevOps, Slack, Teams, and other platforms
"""

import logging
import json
import requests
from typing import Dict, List, Any, Optional
from datetime import datetime
from dataclasses import dataclass
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)

@dataclass
class IntegrationConfig:
    """Configuration for platform integration"""
    platform: str
    api_url: str
    token: str
    username: Optional[str] = None
    organization: Optional[str] = None
    webhook_url: Optional[str] = None
    enabled: bool = True

@dataclass
class NotificationMessage:
    """Notification message for various platforms"""
    title: str
    message: str
    severity: str  # info, warning, error, success
    data: Dict[str, Any]
    platform: str
    channel: Optional[str] = None

class PlatformIntegration(ABC):
    """Abstract base class for platform integrations"""
    
    def __init__(self, config: IntegrationConfig):
        self.config = config
        self.session = requests.Session()
        self._setup_authentication()
    
    @abstractmethod
    def _setup_authentication(self):
        """Setup authentication for the platform"""
        pass
    
    @abstractmethod
    def test_connection(self) -> Dict[str, Any]:
        """Test connection to the platform"""
        pass
    
    @abstractmethod
    def send_notification(self, message: NotificationMessage) -> bool:
        """Send notification to the platform"""
        pass

class GitHubIntegration(PlatformIntegration):
    """GitHub integration"""
    
    def _setup_authentication(self):
        self.session.headers.update({
            'Authorization': f'token {self.config.token}',
            'Accept': 'application/vnd.github.v3+json'
        })
    
    def test_connection(self) -> Dict[str, Any]:
        try:
            response = self.session.get(f"{self.config.api_url}/user")
            if response.status_code == 200:
                user_data = response.json()
                return {
                    'success': True,
                    'platform': 'github',
                    'user': user_data.get('login'),
                    'name': user_data.get('name'),
                    'public_repos': user_data.get('public_repos', 0)
                }
            else:
                return {'success': False, 'error': f'HTTP {response.status_code}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def send_notification(self, message: NotificationMessage) -> bool:
        # GitHub doesn't have direct notifications, but we can create issues or comments
        return True
    
    def get_repositories(self) -> List[Dict[str, Any]]:
        """Get user repositories"""
        try:
            response = self.session.get(f"{self.config.api_url}/user/repos")
            if response.status_code == 200:
                return response.json()
            return []
        except Exception as e:
            logger.error(f"Error fetching GitHub repositories: {e}")
            return []
    
    def get_pull_requests(self, repo: str) -> List[Dict[str, Any]]:
        """Get pull requests for a repository"""
        try:
            response = self.session.get(f"{self.config.api_url}/repos/{repo}/pulls")
            if response.status_code == 200:
                return response.json()
            return []
        except Exception as e:
            logger.error(f"Error fetching pull requests: {e}")
            return []

class GitLabIntegration(PlatformIntegration):
    """GitLab integration"""
    
    def _setup_authentication(self):
        self.session.headers.update({
            'Private-Token': self.config.token
        })
    
    def test_connection(self) -> Dict[str, Any]:
        try:
            response = self.session.get(f"{self.config.api_url}/user")
            if response.status_code == 200:
                user_data = response.json()
                return {
                    'success': True,
                    'platform': 'gitlab',
                    'user': user_data.get('username'),
                    'name': user_data.get('name'),
                    'projects': len(self.get_projects())
                }
            else:
                return {'success': False, 'error': f'HTTP {response.status_code}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def send_notification(self, message: NotificationMessage) -> bool:
        return True
    
    def get_projects(self) -> List[Dict[str, Any]]:
        """Get user projects"""
        try:
            response = self.session.get(f"{self.config.api_url}/projects?membership=true")
            if response.status_code == 200:
                return response.json()
            return []
        except Exception as e:
            logger.error(f"Error fetching GitLab projects: {e}")
            return []

class AzureDevOpsIntegration(PlatformIntegration):
    """Azure DevOps integration"""
    
    def _setup_authentication(self):
        import base64
        # Azure DevOps uses basic auth with PAT
        auth_string = base64.b64encode(f":{self.config.token}".encode()).decode()
        self.session.headers.update({
            'Authorization': f'Basic {auth_string}',
            'Content-Type': 'application/json'
        })
    
    def test_connection(self) -> Dict[str, Any]:
        try:
            # Test with profile API
            response = self.session.get(f"{self.config.api_url}/_apis/profile/profiles/me?api-version=6.0")
            if response.status_code == 200:
                profile_data = response.json()
                return {
                    'success': True,
                    'platform': 'azuredevops',
                    'user': profile_data.get('displayName'),
                    'email': profile_data.get('emailAddress'),
                    'organization': self.config.organization
                }
            else:
                return {'success': False, 'error': f'HTTP {response.status_code}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def send_notification(self, message: NotificationMessage) -> bool:
        # Can create work items or send to service hooks
        return True
    
    def get_projects(self) -> List[Dict[str, Any]]:
        """Get organization projects"""
        try:
            response = self.session.get(f"{self.config.api_url}/_apis/projects?api-version=6.0")
            if response.status_code == 200:
                return response.json().get('value', [])
            return []
        except Exception as e:
            logger.error(f"Error fetching Azure DevOps projects: {e}")
            return []
    
    def get_repositories(self, project_id: str) -> List[Dict[str, Any]]:
        """Get repositories in a project"""
        try:
            response = self.session.get(f"{self.config.api_url}/{project_id}/_apis/git/repositories?api-version=6.0")
            if response.status_code == 200:
                return response.json().get('value', [])
            return []
        except Exception as e:
            logger.error(f"Error fetching repositories: {e}")
            return []

class SlackIntegration(PlatformIntegration):
    """Slack integration"""
    
    def _setup_authentication(self):
        self.session.headers.update({
            'Authorization': f'Bearer {self.config.token}',
            'Content-Type': 'application/json'
        })
    
    def test_connection(self) -> Dict[str, Any]:
        try:
            response = self.session.get("https://slack.com/api/auth.test")
            if response.status_code == 200:
                data = response.json()
                if data.get('ok'):
                    return {
                        'success': True,
                        'platform': 'slack',
                        'user': data.get('user'),
                        'team': data.get('team'),
                        'url': data.get('url')
                    }
                else:
                    return {'success': False, 'error': data.get('error')}
            else:
                return {'success': False, 'error': f'HTTP {response.status_code}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def send_notification(self, message: NotificationMessage) -> bool:
        """Send message to Slack channel"""
        try:
            # Format message for Slack
            slack_message = {
                "channel": message.channel or "#general",
                "text": message.title,
                "attachments": [
                    {
                        "color": self._get_color_for_severity(message.severity),
                        "fields": [
                            {
                                "title": "Details",
                                "value": message.message,
                                "short": False
                            }
                        ],
                        "footer": "AI Code Review Dashboard",
                        "ts": int(datetime.now().timestamp())
                    }
                ]
            }
            
            response = self.session.post(
                "https://slack.com/api/chat.postMessage",
                json=slack_message
            )
            
            if response.status_code == 200:
                result = response.json()
                return result.get('ok', False)
            return False
            
        except Exception as e:
            logger.error(f"Error sending Slack notification: {e}")
            return False
    
    def _get_color_for_severity(self, severity: str) -> str:
        """Get color code for severity"""
        colors = {
            'error': 'danger',
            'warning': 'warning',
            'success': 'good',
            'info': '#36a64f'
        }
        return colors.get(severity, '#36a64f')

class TeamsIntegration(PlatformIntegration):
    """Microsoft Teams integration"""
    
    def _setup_authentication(self):
        # Teams typically uses webhook URLs or Graph API
        if self.config.webhook_url:
            self.webhook_url = self.config.webhook_url
        else:
            self.session.headers.update({
                'Authorization': f'Bearer {self.config.token}',
                'Content-Type': 'application/json'
            })
    
    def test_connection(self) -> Dict[str, Any]:
        try:
            if hasattr(self, 'webhook_url'):
                # Test webhook with a simple message
                test_message = {
                    "@type": "MessageCard",
                    "@context": "http://schema.org/extensions",
                    "summary": "Connection Test",
                    "themeColor": "0076D7",
                    "sections": [{
                        "activityTitle": "Connection Test",
                        "activitySubtitle": "Testing Teams integration",
                        "activityImage": "https://teamsnodesample.azurewebsites.net/static/img/image5.png",
                        "facts": [{
                            "name": "Status",
                            "value": "Testing connection"
                        }]
                    }]
                }
                
                response = self.session.post(self.webhook_url, json=test_message)
                if response.status_code == 200:
                    return {
                        'success': True,
                        'platform': 'teams',
                        'method': 'webhook',
                        'url': self.webhook_url
                    }
                else:
                    return {'success': False, 'error': f'HTTP {response.status_code}'}
            else:
                # Use Graph API
                response = self.session.get("https://graph.microsoft.com/v1.0/me")
                if response.status_code == 200:
                    user_data = response.json()
                    return {
                        'success': True,
                        'platform': 'teams',
                        'method': 'graph_api',
                        'user': user_data.get('displayName'),
                        'email': user_data.get('mail')
                    }
                else:
                    return {'success': False, 'error': f'HTTP {response.status_code}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def send_notification(self, message: NotificationMessage) -> bool:
        """Send message to Teams"""
        try:
            if hasattr(self, 'webhook_url'):
                # Send via webhook
                teams_message = {
                    "@type": "MessageCard",
                    "@context": "http://schema.org/extensions",
                    "summary": message.title,
                    "themeColor": self._get_color_for_severity(message.severity),
                    "sections": [{
                        "activityTitle": message.title,
                        "activitySubtitle": f"Code Review Alert - {message.severity.upper()}",
                        "facts": [
                            {
                                "name": "Message",
                                "value": message.message
                            },
                            {
                                "name": "Severity",
                                "value": message.severity.upper()
                            },
                            {
                                "name": "Platform",
                                "value": message.platform
                            }
                        ]
                    }]
                }
                
                response = self.session.post(self.webhook_url, json=teams_message)
                return response.status_code == 200
            else:
                # Use Graph API to send chat message
                return True  # Placeholder for Graph API implementation
                
        except Exception as e:
            logger.error(f"Error sending Teams notification: {e}")
            return False
    
    def _get_color_for_severity(self, severity: str) -> str:
        """Get color code for severity"""
        colors = {
            'error': 'FF0000',
            'warning': 'FFA500',
            'success': '00FF00',
            'info': '0076D7'
        }
        return colors.get(severity, '0076D7')

class BitbucketIntegration(PlatformIntegration):
    """Bitbucket integration"""
    
    def _setup_authentication(self):
        self.session.headers.update({
            'Authorization': f'Bearer {self.config.token}'
        })
    
    def test_connection(self) -> Dict[str, Any]:
        try:
            response = self.session.get(f"{self.config.api_url}/user")
            if response.status_code == 200:
                user_data = response.json()
                return {
                    'success': True,
                    'platform': 'bitbucket',
                    'user': user_data.get('username'),
                    'display_name': user_data.get('display_name')
                }
            else:
                return {'success': False, 'error': f'HTTP {response.status_code}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def send_notification(self, message: NotificationMessage) -> bool:
        return True
    
    def get_repositories(self) -> List[Dict[str, Any]]:
        """Get user repositories"""
        try:
            response = self.session.get(f"{self.config.api_url}/repositories/{self.config.username}")
            if response.status_code == 200:
                return response.json().get('values', [])
            return []
        except Exception as e:
            logger.error(f"Error fetching Bitbucket repositories: {e}")
            return []

class IntegrationManager:
    """Manages all platform integrations"""
    
    def __init__(self):
        self.integrations: Dict[str, PlatformIntegration] = {}
        self.configs: Dict[str, IntegrationConfig] = {}
        logger.info("🔗 Integration Manager initialized")
    
    def add_integration(self, platform: str, config: IntegrationConfig) -> bool:
        """Add a new platform integration"""
        try:
            integration_class = self._get_integration_class(platform)
            if integration_class:
                integration = integration_class(config)
                self.integrations[platform] = integration
                self.configs[platform] = config
                logger.info(f"✅ Added {platform} integration")
                return True
            else:
                logger.error(f"❌ Unknown platform: {platform}")
                return False
        except Exception as e:
            logger.error(f"❌ Error adding {platform} integration: {e}")
            return False
    
    def remove_integration(self, platform: str) -> bool:
        """Remove a platform integration"""
        try:
            if platform in self.integrations:
                del self.integrations[platform]
                del self.configs[platform]
                logger.info(f"✅ Removed {platform} integration")
                return True
            return False
        except Exception as e:
            logger.error(f"❌ Error removing {platform} integration: {e}")
            return False
    
    def test_integration(self, platform: str) -> Dict[str, Any]:
        """Test a specific integration"""
        if platform in self.integrations:
            return self.integrations[platform].test_connection()
        else:
            return {'success': False, 'error': f'Integration {platform} not found'}
    
    def test_all_integrations(self) -> Dict[str, Dict[str, Any]]:
        """Test all configured integrations"""
        results = {}
        for platform, integration in self.integrations.items():
            results[platform] = integration.test_connection()
        return results
    
    def send_notification_to_platform(self, platform: str, message: NotificationMessage) -> bool:
        """Send notification to a specific platform"""
        if platform in self.integrations and self.configs[platform].enabled:
            return self.integrations[platform].send_notification(message)
        return False
    
    def broadcast_notification(self, message: NotificationMessage, platforms: Optional[List[str]] = None) -> Dict[str, bool]:
        """Send notification to multiple platforms"""
        results = {}
        target_platforms = platforms if platforms else list(self.integrations.keys())
        
        for platform in target_platforms:
            if platform in self.integrations and self.configs[platform].enabled:
                results[platform] = self.integrations[platform].send_notification(message)
            else:
                results[platform] = False
        
        return results
    
    def get_repositories_from_platform(self, platform: str) -> List[Dict[str, Any]]:
        """Get repositories from a specific platform"""
        if platform in self.integrations:
            integration = self.integrations[platform]
            if hasattr(integration, 'get_repositories'):
                return integration.get_repositories()
        return []
    
    def get_all_repositories(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get repositories from all platforms"""
        all_repos = {}
        for platform, integration in self.integrations.items():
            if hasattr(integration, 'get_repositories'):
                all_repos[platform] = integration.get_repositories()
        return all_repos
    
    def _get_integration_class(self, platform: str) -> Optional[type]:
        """Get integration class for platform"""
        platform_classes = {
            'github': GitHubIntegration,
            'gitlab': GitLabIntegration,
            'bitbucket': BitbucketIntegration,
            'azuredevops': AzureDevOpsIntegration,
            'slack': SlackIntegration,
            'teams': TeamsIntegration
        }
        return platform_classes.get(platform.lower())
    
    def get_integration_status(self) -> Dict[str, Any]:
        """Get status of all integrations"""
        status = {
            'total_integrations': len(self.integrations),
            'enabled_integrations': len([c for c in self.configs.values() if c.enabled]),
            'platforms': list(self.integrations.keys()),
            'last_updated': datetime.now().isoformat()
        }
        return status
    
    def save_configurations(self, file_path: str = 'integrations_config.json') -> bool:
        """Save integration configurations to file"""
        try:
            config_data = {}
            for platform, config in self.configs.items():
                config_data[platform] = {
                    'platform': config.platform,
                    'api_url': config.api_url,
                    'token': '***masked***',  # Don't save actual tokens
                    'username': config.username,
                    'organization': config.organization,
                    'webhook_url': config.webhook_url,
                    'enabled': config.enabled
                }
            
            with open(file_path, 'w') as f:
                json.dump(config_data, f, indent=2)
            
            logger.info(f"✅ Saved integration configurations to {file_path}")
            return True
        except Exception as e:
            logger.error(f"❌ Error saving configurations: {e}")
            return False
    
    def load_configurations(self, file_path: str = 'integrations_config.json') -> bool:
        """Load integration configurations from file"""
        try:
            with open(file_path, 'r') as f:
                config_data = json.load(f)
            
            for platform, config_dict in config_data.items():
                # Note: Tokens need to be set separately for security
                config = IntegrationConfig(
                    platform=config_dict['platform'],
                    api_url=config_dict['api_url'],
                    token='',  # Will need to be set separately
                    username=config_dict.get('username'),
                    organization=config_dict.get('organization'),
                    webhook_url=config_dict.get('webhook_url'),
                    enabled=config_dict.get('enabled', True)
                )
                self.configs[platform] = config
            
            logger.info(f"✅ Loaded integration configurations from {file_path}")
            return True
        except Exception as e:
            logger.error(f"❌ Error loading configurations: {e}")
            return False

# Factory function for easy integration setup
def create_integration_manager() -> IntegrationManager:
    """Create and return a new integration manager"""
    manager = IntegrationManager()
    
    # Pre-configure common platforms (tokens need to be set separately)
    common_configs = {
        'github': IntegrationConfig(
            platform='github',
            api_url='https://api.github.com',
            token=''  # To be set via environment or config
        ),
        'gitlab': IntegrationConfig(
            platform='gitlab',
            api_url='https://gitlab.com/api/v4',
            token=''
        ),
        'azuredevops': IntegrationConfig(
            platform='azuredevops',
            api_url='https://dev.azure.com',
            token='',
            organization=''  # To be set
        ),
        'slack': IntegrationConfig(
            platform='slack',
            api_url='https://slack.com/api',
            token=''
        ),
        'teams': IntegrationConfig(
            platform='teams',
            api_url='https://graph.microsoft.com/v1.0',
            token='',
            webhook_url=''  # Alternative to token
        ),
        'bitbucket': IntegrationConfig(
            platform='bitbucket',
            api_url='https://api.bitbucket.org/2.0',
            token=''
        )
    }
    
    # Store configs for later activation
    manager.configs.update(common_configs)
    
    return manager 