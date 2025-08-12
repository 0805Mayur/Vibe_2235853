#!/usr/bin/env python3
"""
AI-Powered Pull Request Review Service
Provides instant PR summaries, contextual chat, and inline AI comments
"""

import logging
import json
import re
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import requests
from dataclasses import dataclass

from backend.ai_service_enhanced import EnhancedAIService

logger = logging.getLogger(__name__)

@dataclass
class PRFile:
    """Represents a file in a pull request"""
    filename: str
    additions: int
    deletions: int
    changes: int
    status: str  # added, modified, deleted, renamed
    patch: str
    content: str = ""

@dataclass
class PRComment:
    """Represents an AI-generated comment on PR"""
    file: str
    line: int
    suggestion: str
    severity: str  # critical, high, medium, low
    category: str  # security, performance, quality, architecture
    auto_fixable: bool = False
    fix_suggestion: str = ""

@dataclass
class PRSummary:
    """Represents a PR summary"""
    overall_impact: str
    files_changed: int
    lines_added: int
    lines_deleted: int
    risk_level: str  # low, medium, high, critical
    key_changes: List[str]
    potential_issues: List[str]
    recommendations: List[str]

class AIpoweredPRReviewService:
    """AI-powered pull request review service"""
    
    def __init__(self):
        self.ai_service = EnhancedAIService()
        logger.info("🔍 AI-Powered PR Review Service initialized")
    
    async def analyze_pull_request(self, pr_data: Dict[str, Any], platform: str = "github") -> Dict[str, Any]:
        """
        Analyze a complete pull request
        
        Args:
            pr_data: Pull request data from GitHub/GitLab API
            platform: Source platform (github, gitlab, bitbucket, azuredevops)
        
        Returns:
            Complete PR analysis with summary, comments, and insights
        """
        logger.info(f"🔍 Starting AI-powered analysis of PR #{pr_data.get('number', 'unknown')}")
        
        try:
            # Extract PR information
            pr_files = await self._extract_pr_files(pr_data, platform)
            
            # Generate instant PR summary
            pr_summary = await self._generate_pr_summary(pr_data, pr_files)
            
            # Generate inline AI comments
            inline_comments = await self._generate_inline_comments(pr_files)
            
            # Analyze security and quality
            security_analysis = await self._analyze_security_risks(pr_files)
            
            # Generate contextual insights
            contextual_insights = await self._generate_contextual_insights(pr_data, pr_files)
            
            # Calculate overall score and recommendations
            overall_score = self._calculate_pr_score(pr_summary, inline_comments, security_analysis)
            
            analysis_result = {
                "pr_id": pr_data.get('number'),
                "title": pr_data.get('title'),
                "author": pr_data.get('user', {}).get('login'),
                "platform": platform,
                "summary": pr_summary,
                "inline_comments": inline_comments,
                "security_analysis": security_analysis,
                "contextual_insights": contextual_insights,
                "overall_score": overall_score,
                "files_analyzed": len(pr_files),
                "analysis_timestamp": datetime.now().isoformat(),
                "auto_fix_suggestions": self._generate_auto_fix_suggestions(inline_comments)
            }
            
            logger.info(f"✅ PR analysis completed: {len(inline_comments)} comments, score: {overall_score}")
            return analysis_result
            
        except Exception as e:
            logger.error(f"❌ Error analyzing PR: {e}")
            return self._create_fallback_pr_analysis(pr_data)
    
    async def _extract_pr_files(self, pr_data: Dict[str, Any], platform: str) -> List[PRFile]:
        """Extract files from PR data"""
        files = []
        
        try:
            # Handle different platform formats
            if platform == "github":
                files_data = pr_data.get('files', [])
            elif platform == "gitlab":
                files_data = pr_data.get('changes', [])
            else:
                files_data = pr_data.get('files', [])
            
            for file_data in files_data:
                pr_file = PRFile(
                    filename=file_data.get('filename', ''),
                    additions=file_data.get('additions', 0),
                    deletions=file_data.get('deletions', 0),
                    changes=file_data.get('changes', 0),
                    status=file_data.get('status', 'modified'),
                    patch=file_data.get('patch', ''),
                    content=file_data.get('content', '')
                )
                files.append(pr_file)
            
            logger.info(f"📁 Extracted {len(files)} files from PR")
            return files
            
        except Exception as e:
            logger.error(f"❌ Error extracting PR files: {e}")
            return []
    
    async def _generate_pr_summary(self, pr_data: Dict[str, Any], files: List[PRFile]) -> PRSummary:
        """Generate instant PR summary using AI"""
        try:
            # Prepare context for AI
            files_context = []
            total_additions = sum(f.additions for f in files)
            total_deletions = sum(f.deletions for f in files)
            
            for file in files[:10]:  # Limit to first 10 files for AI context
                files_context.append({
                    "file": file.filename,
                    "status": file.status,
                    "additions": file.additions,
                    "deletions": file.deletions,
                    "patch_preview": file.patch[:500] if file.patch else ""
                })
            
            prompt = f"""
Analyze this pull request and provide an instant summary:

PR TITLE: {pr_data.get('title', 'N/A')}
PR DESCRIPTION: {pr_data.get('body', 'N/A')[:1000]}
FILES CHANGED: {len(files)}
LINES ADDED: {total_additions}
LINES DELETED: {total_deletions}

FILE CHANGES:
{json.dumps(files_context, indent=2)}

Provide a comprehensive PR summary in JSON format:
{{
    "overall_impact": "Brief description of what this PR does",
    "risk_level": "low|medium|high|critical",
    "key_changes": ["List of 3-5 key changes"],
    "potential_issues": ["List of potential problems or risks"],
    "recommendations": ["List of recommendations for reviewer"]
}}
"""
            
            # Get AI analysis
            response = self.ai_service.client.chat.completions.create(
                model=self.ai_service.deployment_name,
                messages=[
                    {"role": "system", "content": "You are an expert code reviewer who provides instant, accurate PR summaries."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=1500
            )
            
            ai_response = response.choices[0].message.content
            if ai_response:
                # Parse AI response
                summary_data = self._parse_ai_summary(ai_response)
                
                return PRSummary(
                    overall_impact=summary_data.get("overall_impact", "Code changes analyzed"),
                    files_changed=len(files),
                    lines_added=total_additions,
                    lines_deleted=total_deletions,
                    risk_level=summary_data.get("risk_level", "medium"),
                    key_changes=summary_data.get("key_changes", []),
                    potential_issues=summary_data.get("potential_issues", []),
                    recommendations=summary_data.get("recommendations", [])
                )
            
        except Exception as e:
            logger.error(f"❌ Error generating PR summary: {e}")
        
        # Fallback summary
        return PRSummary(
            overall_impact=f"Pull request modifies {len(files)} files with {sum(f.additions for f in files)} additions and {sum(f.deletions for f in files)} deletions",
            files_changed=len(files),
            lines_added=sum(f.additions for f in files),
            lines_deleted=sum(f.deletions for f in files),
            risk_level="medium",
            key_changes=["Code modifications detected"],
            potential_issues=["Manual review recommended"],
            recommendations=["Review changes carefully before merging"]
        )
    
    async def _generate_inline_comments(self, files: List[PRFile]) -> List[PRComment]:
        """Generate AI-powered inline comments for PR files"""
        comments = []
        
        try:
            for file in files:
                if not file.patch or file.status == "deleted":
                    continue
                
                # Analyze file changes
                file_comments = await self._analyze_file_changes(file)
                comments.extend(file_comments)
            
            logger.info(f"💬 Generated {len(comments)} inline comments")
            return comments
            
        except Exception as e:
            logger.error(f"❌ Error generating inline comments: {e}")
            return []
    
    async def _analyze_file_changes(self, file: PRFile) -> List[PRComment]:
        """Analyze individual file changes and generate comments"""
        comments = []
        
        try:
            # Extract added/modified lines from patch
            added_lines = self._extract_added_lines(file.patch)
            
            if not added_lines:
                return comments
            
            # Prepare context for AI analysis
            prompt = f"""
Analyze the following code changes in file: {file.filename}

PATCH CONTENT:
{file.patch}

ADDED/MODIFIED LINES:
{chr(10).join(added_lines)}

Provide inline code review comments focusing on:
1. Security vulnerabilities
2. Performance issues
3. Code quality problems
4. Architecture concerns
5. Best practices violations

Return JSON array of comments:
[
    {{
        "line": line_number,
        "suggestion": "Specific suggestion text",
        "severity": "critical|high|medium|low",
        "category": "security|performance|quality|architecture",
        "auto_fixable": true/false,
        "fix_suggestion": "Specific fix if auto_fixable"
    }}
]
"""
            
            response = self.ai_service.client.chat.completions.create(
                model=self.ai_service.deployment_name,
                messages=[
                    {"role": "system", "content": "You are an expert code reviewer providing specific, actionable feedback on code changes."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=2000
            )
            
            ai_response = response.choices[0].message.content
            if ai_response:
                comments_data = self._parse_ai_comments(ai_response)
                
                for comment_data in comments_data:
                    comment = PRComment(
                        file=file.filename,
                        line=comment_data.get("line", 1),
                        suggestion=comment_data.get("suggestion", ""),
                        severity=comment_data.get("severity", "medium"),
                        category=comment_data.get("category", "quality"),
                        auto_fixable=comment_data.get("auto_fixable", False),
                        fix_suggestion=comment_data.get("fix_suggestion", "")
                    )
                    comments.append(comment)
            
        except Exception as e:
            logger.error(f"❌ Error analyzing file {file.filename}: {e}")
        
        return comments
    
    def _extract_added_lines(self, patch: str) -> List[str]:
        """Extract added lines from git patch"""
        added_lines = []
        
        try:
            lines = patch.split('\n')
            for line in lines:
                if line.startswith('+') and not line.startswith('+++'):
                    added_lines.append(line[1:])  # Remove the '+' prefix
            
        except Exception as e:
            logger.error(f"❌ Error extracting added lines: {e}")
        
        return added_lines
    
    async def _analyze_security_risks(self, files: List[PRFile]) -> Dict[str, Any]:
        """Analyze security risks in PR"""
        security_issues = []
        risk_score = 0
        
        try:
            for file in files:
                # Check for common security patterns
                security_patterns = {
                    "hardcoded_secrets": [r"api[_-]?key\s*=\s*['\"][\w-]+['\"]", r"password\s*=\s*['\"][\w-]+['\"]", r"secret\s*=\s*['\"][\w-]+['\"]"],
                    "sql_injection": [r"SELECT.*\+.*", r"INSERT.*\+.*", r"UPDATE.*\+.*"],
                    "command_injection": [r"exec\(.*\+.*\)", r"system\(.*\+.*\)", r"shell=True"],
                    "xss_vulnerabilities": [r"innerHTML\s*=.*", r"document\.write\(.*\+.*\)"],
                    "path_traversal": [r"\.\./", r"\.\.\\\\"]
                }
                
                for issue_type, patterns in security_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, file.patch, re.IGNORECASE):
                            security_issues.append({
                                "file": file.filename,
                                "type": issue_type,
                                "severity": "high" if issue_type in ["sql_injection", "command_injection"] else "medium",
                                "description": f"Potential {issue_type.replace('_', ' ')} detected"
                            })
                            risk_score += 10 if issue_type in ["sql_injection", "command_injection"] else 5
            
            return {
                "issues": security_issues,
                "risk_score": min(risk_score, 100),
                "risk_level": "critical" if risk_score >= 50 else "high" if risk_score >= 25 else "medium" if risk_score >= 10 else "low"
            }
            
        except Exception as e:
            logger.error(f"❌ Error analyzing security risks: {e}")
            return {"issues": [], "risk_score": 0, "risk_level": "low"}
    
    async def _generate_contextual_insights(self, pr_data: Dict[str, Any], files: List[PRFile]) -> Dict[str, Any]:
        """Generate contextual insights about the PR"""
        return {
            "complexity_score": self._calculate_complexity(files),
            "test_coverage_impact": self._analyze_test_impact(files),
            "architecture_impact": self._analyze_architecture_impact(files),
            "dependencies_changed": self._check_dependency_changes(files),
            "breaking_changes_risk": self._assess_breaking_changes(files)
        }
    
    def _calculate_complexity(self, files: List[PRFile]) -> int:
        """Calculate complexity score based on changes"""
        complexity = 0
        for file in files:
            complexity += file.additions + file.deletions
            if file.filename.endswith(('.py', '.js', '.ts', '.java')):
                complexity += 5  # Code files are more complex
        return min(complexity // 10, 100)
    
    def _analyze_test_impact(self, files: List[PRFile]) -> str:
        """Analyze impact on test coverage"""
        test_files = [f for f in files if 'test' in f.filename.lower()]
        code_files = [f for f in files if f.filename.endswith(('.py', '.js', '.ts', '.java'))]
        
        if len(test_files) == 0 and len(code_files) > 0:
            return "No test changes detected - consider adding tests"
        elif len(test_files) > 0:
            return "Test files modified - good coverage"
        return "No significant impact"
    
    def _analyze_architecture_impact(self, files: List[PRFile]) -> str:
        """Analyze architectural impact"""
        config_files = [f for f in files if f.filename in ['package.json', 'requirements.txt', 'pom.xml', 'Dockerfile']]
        if config_files:
            return "Configuration changes detected - review dependencies"
        return "No architectural changes"
    
    def _check_dependency_changes(self, files: List[PRFile]) -> List[str]:
        """Check for dependency changes"""
        dependency_files = ['package.json', 'requirements.txt', 'pom.xml', 'Gemfile', 'composer.json']
        changed_deps = []
        
        for file in files:
            if file.filename in dependency_files:
                changed_deps.append(file.filename)
        
        return changed_deps
    
    def _assess_breaking_changes(self, files: List[PRFile]) -> str:
        """Assess risk of breaking changes"""
        api_files = [f for f in files if 'api' in f.filename.lower() or 'controller' in f.filename.lower()]
        if api_files:
            return "Potential API changes - verify backward compatibility"
        return "Low risk of breaking changes"
    
    def _calculate_pr_score(self, summary: PRSummary, comments: List[PRComment], security: Dict[str, Any]) -> int:
        """Calculate overall PR score"""
        base_score = 100
        
        # Deduct for issues
        for comment in comments:
            if comment.severity == "critical":
                base_score -= 20
            elif comment.severity == "high":
                base_score -= 10
            elif comment.severity == "medium":
                base_score -= 5
            else:
                base_score -= 2
        
        # Deduct for security risks
        base_score -= security.get("risk_score", 0) // 2
        
        # Deduct for high risk level
        if summary.risk_level == "critical":
            base_score -= 30
        elif summary.risk_level == "high":
            base_score -= 20
        elif summary.risk_level == "medium":
            base_score -= 10
        
        return max(base_score, 0)
    
    def _generate_auto_fix_suggestions(self, comments: List[PRComment]) -> List[Dict[str, Any]]:
        """Generate auto-fix suggestions for fixable issues"""
        auto_fixes = []
        
        for comment in comments:
            if comment.auto_fixable and comment.fix_suggestion:
                auto_fixes.append({
                    "file": comment.file,
                    "line": comment.line,
                    "issue": comment.suggestion,
                    "fix": comment.fix_suggestion,
                    "category": comment.category,
                    "confidence": 0.8
                })
        
        return auto_fixes
    
    def _parse_ai_summary(self, ai_response: str) -> Dict[str, Any]:
        """Parse AI summary response"""
        try:
            # Try to extract JSON from response
            json_match = re.search(r'\{.*\}', ai_response, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
        except:
            pass
        
        return {
            "overall_impact": "AI analysis completed",
            "risk_level": "medium",
            "key_changes": ["Changes detected"],
            "potential_issues": ["Manual review recommended"],
            "recommendations": ["Review carefully"]
        }
    
    def _parse_ai_comments(self, ai_response: str) -> List[Dict[str, Any]]:
        """Parse AI comments response"""
        try:
            # Try to extract JSON array from response
            json_match = re.search(r'\[.*\]', ai_response, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
        except:
            pass
        
        return []
    
    def _create_fallback_pr_analysis(self, pr_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create fallback analysis when AI fails"""
        return {
            "pr_id": pr_data.get('number'),
            "title": pr_data.get('title'),
            "author": pr_data.get('user', {}).get('login'),
            "platform": "unknown",
            "summary": PRSummary(
                overall_impact="Pull request analysis completed",
                files_changed=0,
                lines_added=0,
                lines_deleted=0,
                risk_level="medium",
                key_changes=["Manual review required"],
                potential_issues=[],
                recommendations=["Review changes manually"]
            ),
            "inline_comments": [],
            "security_analysis": {"issues": [], "risk_score": 0, "risk_level": "low"},
            "contextual_insights": {},
            "overall_score": 75,
            "files_analyzed": 0,
            "analysis_timestamp": datetime.now().isoformat(),
            "auto_fix_suggestions": []
        }

    async def contextual_pr_chat(self, pr_id: str, question: str, pr_context: Dict[str, Any]) -> str:
        """
        Contextual PR chat - answer questions about the PR
        """
        try:
            prompt = f"""
You are an AI code review assistant. Answer the developer's question about this pull request:

PR CONTEXT:
- Title: {pr_context.get('title', 'N/A')}
- Files changed: {pr_context.get('files_analyzed', 0)}
- Summary: {pr_context.get('summary', {}).get('overall_impact', 'N/A')}
- Risk level: {pr_context.get('summary', {}).get('risk_level', 'N/A')}

DEVELOPER QUESTION: {question}

Provide a clear, helpful answer explaining the code changes, potential issues, or recommendations.
Be specific and reference actual code changes when possible.
"""
            
            response = self.ai_service.client.chat.completions.create(
                model=self.ai_service.deployment_name,
                messages=[
                    {"role": "system", "content": "You are a helpful code review assistant who explains code changes clearly."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2,
                max_tokens=1000
            )
            
            return response.choices[0].message.content or "I couldn't analyze that question. Please try rephrasing it."
            
        except Exception as e:
            logger.error(f"❌ Error in contextual PR chat: {e}")
            return "I'm having trouble analyzing that question right now. Please try again later." 