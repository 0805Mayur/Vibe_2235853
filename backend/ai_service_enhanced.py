#!/usr/bin/env python3
"""
Enhanced AI Service with Advanced Code Analysis
Integrates Azure OpenAI with comprehensive static analysis, ML-based features,
and enterprise-grade code review capabilities.
"""

import logging
import json
import re
import os
import sys
from typing import Dict, List, Any, Optional
from datetime import datetime

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.ai_service import AICodeAnalyzer

logger = logging.getLogger(__name__)

class EnhancedAIService(AICodeAnalyzer):
    """Enhanced AI Service with advanced analysis capabilities"""
    
    def __init__(self):
        super().__init__()
        # Initialize advanced analyzer with fallback
        try:
            from backend.advanced_analysis import AdvancedCodeAnalyzer
            self.advanced_analyzer = AdvancedCodeAnalyzer()
            self.has_advanced_features = True
            logger.info("✅ Advanced analysis features loaded")
        except ImportError as e:
            logger.warning(f"⚠️ Advanced analysis not available: {e}")
            self.advanced_analyzer = None
            self.has_advanced_features = False
    
    def analyze_code_comprehensive(self, code: str, language: str = "python", file_path: str = "unknown.py") -> Dict[str, Any]:
        """Perform comprehensive code analysis combining AI and static analysis"""
        logger.info(f"🚀 Starting comprehensive analysis for {file_path}")
        
        try:
            if self.has_advanced_features and self.advanced_analyzer:
                # Perform advanced static analysis
                static_results = self.advanced_analyzer.perform_comprehensive_analysis(code, language, file_path)
                
                # Get AI-powered insights
                ai_insights = self._get_ai_insights(code, language, file_path, static_results)
                
                # Combine results
                combined_results = self._merge_analysis_results(static_results, ai_insights)
                
                logger.info(f"✅ Comprehensive analysis completed for {file_path}")
                return combined_results
            else:
                # Fallback to basic analysis with enhanced prompts
                logger.info(f"🔄 Using enhanced basic analysis for {file_path}")
                return self._enhanced_basic_analysis(code, language, file_path)
            
        except Exception as e:
            logger.error(f"❌ Error in comprehensive analysis: {e}")
            # Fallback to basic analysis
            return self._create_fallback_analysis(code, file_path)
    
    def _get_ai_insights(self, code: str, language: str, file_path: str, static_results: Dict[str, Any]) -> Dict[str, Any]:
        """Get AI-powered insights and recommendations"""
        try:
            # Create enhanced prompt with static analysis context
            prompt = self._create_enhanced_analysis_prompt(code, language, file_path, static_results)
            
            response = self.client.chat.completions.create(
                model=self.deployment_name,
                messages=[
                    {"role": "system", "content": self._get_enhanced_system_prompt()},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=2000,
                timeout=30
            )
            
            ai_response = response.choices[0].message.content
            if ai_response is None:
                logger.warning("AI response content is None, using fallback")
                return {"refactoring_suggestions": [], "performance_tips": [], "intelligent_comments": [], "advanced_insights": []}
            
            return self._parse_ai_insights(ai_response)
            
        except Exception as e:
            logger.error(f"Error getting AI insights: {e}")
            return {"insights": [], "refactoring_suggestions": [], "performance_tips": []}
    
    def _create_enhanced_analysis_prompt(self, code: str, language: str, file_path: str, static_results: Dict[str, Any]) -> str:
        """Create enhanced analysis prompt with static analysis context"""
        
        issues_summary = ""
        if static_results.get("issues"):
            critical_issues = [i for i in static_results["issues"] if i.severity == "critical"]
            high_issues = [i for i in static_results["issues"] if i.severity == "high"]
            
            if critical_issues:
                issues_summary += f"Critical issues found: {len(critical_issues)} security vulnerabilities. "
            if high_issues:
                issues_summary += f"High-priority issues: {len(high_issues)} items need attention. "
        
        metrics_summary = ""
        if static_results.get("metrics"):
            metrics = static_results["metrics"]
            metrics_summary = f"Code metrics: {metrics.lines_of_code} LOC, complexity {metrics.cyclomatic_complexity}, maintainability {metrics.maintainability_index:.1f}. "
        
        return f"""
You are an expert AI code reviewer analyzing {file_path}. Based on static analysis findings, provide actionable insights.

STATIC ANALYSIS CONTEXT:
{issues_summary}{metrics_summary}

Natural Language Summary: {static_results.get('natural_language_summary', 'N/A')}

CODE TO ANALYZE:
```{language}
{code}
```

Provide specific, actionable AI-powered insights:

1. REFACTORING OPPORTUNITIES (provide at least 2-3 suggestions):
   - Extract methods from complex functions (>15 lines)
   - Apply design patterns (Strategy, Factory, Observer)
   - Reduce cyclomatic complexity through decomposition
   - Eliminate code duplication through abstraction

2. PERFORMANCE OPTIMIZATIONS (provide specific improvements):
   - Replace O(n²) algorithms with O(n log n) alternatives
   - Use list comprehensions instead of loops
   - Implement caching for expensive operations
   - Optimize database queries and API calls

3. INTELLIGENT COMMENTS (suggest meaningful documentation):
   - Add docstrings explaining business logic
   - Comment complex algorithms and edge cases
   - Document API contracts and return types
   - Explain non-obvious performance optimizations

4. ADVANCED CODE INSIGHTS:
   - Suggest better error handling patterns
   - Recommend security improvements
   - Identify maintainability issues
   - Propose testing strategies

Format your response as JSON with specific line numbers and detailed suggestions:
{{
    "refactoring_suggestions": [
        {{
            "line_number": 25,
            "type": "extract_method",
            "description": "Extract complex validation logic into separate method",
            "suggestion": "Create 'validate_user_input()' method to handle lines 25-32",
            "impact": "high",
            "estimated_effort": "15 minutes"
        }}
    ],
    "performance_tips": [
        {{
            "line_number": 45,
            "optimization": "Replace nested loops with dictionary lookup",
            "expected_improvement": "Reduce from O(n²) to O(n) complexity",
            "difficulty": "medium",
            "code_example": "user_dict = {{u.id: u for u in users}}"
        }}
    ],
    "intelligent_comments": [
        {{
            "line_number": 12,
            "suggested_comment": "# Implements OAuth 2.0 authorization code flow with PKCE",
            "reason": "Complex security logic needs clear explanation",
            "type": "business_logic"
        }}
    ],
    "advanced_insights": [
        {{
            "category": "security",
            "insight": "Consider using parameterized queries to prevent SQL injection",
            "impact": "critical",
            "lines": [18, 22, 35]
        }}
    ]
}}

Ensure all suggestions are specific, actionable, and include line numbers where applicable."""
    
    def _get_enhanced_system_prompt(self) -> str:
        """Get enhanced system prompt for comprehensive analysis"""
        return """You are a Senior Software Architect and AI Code Review Expert with 15+ years of experience in enterprise software development. You specialize in:

🔧 REFACTORING EXPERTISE:
- Design patterns (SOLID principles, Gang of Four patterns)
- Code smell detection and remediation
- Legacy code modernization
- Microservices architecture

⚡ PERFORMANCE OPTIMIZATION:
- Algorithm complexity analysis
- Database query optimization
- Caching strategies and patterns
- Memory management and resource optimization

📚 CODE QUALITY & DOCUMENTATION:
- Clean code principles
- API design and documentation
- Technical debt assessment
- Testing strategies and best practices

🔒 SECURITY & COMPLIANCE:
- OWASP Top 10 vulnerabilities
- Secure coding practices
- Data protection and privacy
- Compliance frameworks (SOX, GDPR, HIPAA)

ANALYSIS APPROACH:
1. Identify specific code locations (line numbers)
2. Provide actionable, step-by-step recommendations
3. Estimate effort and impact for each suggestion
4. Include code examples where helpful
5. Prioritize high-impact, low-effort improvements

Your insights should be practical, specific, and immediately actionable by developers. Focus on suggestions that improve maintainability, performance, security, and readability."""
    
    def _parse_ai_insights(self, ai_response: str) -> Dict[str, Any]:
        """Parse AI insights from response"""
        try:
            # Try to extract JSON from the response
            json_match = re.search(r'\{.*\}', ai_response, re.DOTALL)
            if json_match:
                insights_data = json.loads(json_match.group())
                return insights_data
            else:
                # Fallback parsing
                return self._parse_insights_fallback(ai_response)
        except Exception as e:
            logger.error(f"Error parsing AI insights: {e}")
            return {"refactoring_suggestions": [], "performance_tips": [], "intelligent_comments": [], "advanced_insights": []}
    
    def _parse_insights_fallback(self, ai_response: str) -> Dict[str, Any]:
        """Fallback parsing for AI insights"""
        return {
            "refactoring_suggestions": [
                {
                    "line_number": 1,
                    "type": "general",
                    "description": "AI analysis completed",
                    "suggestion": ai_response[:200] + "...",
                    "impact": "medium"
                }
            ],
            "performance_tips": [],
            "intelligent_comments": [],
            "advanced_insights": []
        }
    
    def _merge_analysis_results(self, static_results: Dict[str, Any], ai_insights: Dict[str, Any]) -> Dict[str, Any]:
        """Merge static analysis results with AI insights"""
        
        # Convert static issues to the expected format
        organized_issues = {
            "security": [],
            "performance": [],
            "quality": [],
            "architecture": []
        }
        
        for issue in static_results.get("issues", []):
            issue_dict = {
                "line": issue.line_number,
                "severity": issue.severity,
                "description": issue.description,
                "suggestion": issue.suggestion,
                "confidence": issue.confidence,
                "rule_id": issue.rule_id
            }
            
            category = issue.category
            if category in organized_issues:
                organized_issues[category].append(issue_dict)
        
        # Add AI-powered refactoring suggestions as architecture issues
        for suggestion in ai_insights.get("refactoring_suggestions", []):
            organized_issues["architecture"].append({
                "line": suggestion.get("line_number", 1),
                "severity": "medium",
                "description": f"Refactoring opportunity: {suggestion.get('description', 'N/A')}",
                "suggestion": suggestion.get("suggestion", "Consider refactoring this code"),
                "confidence": 0.8,
                "rule_id": "AI_REFACTOR"
            })
        
        # Add performance tips as performance issues
        for tip in ai_insights.get("performance_tips", []):
            organized_issues["performance"].append({
                "line": tip.get("line_number", 1),
                "severity": "low",
                "description": f"Performance optimization: {tip.get('optimization', 'N/A')}",
                "suggestion": f"Expected improvement: {tip.get('expected_improvement', 'Better performance')}",
                "confidence": 0.7,
                "rule_id": "AI_PERFORMANCE"
            })
        
        # Calculate enhanced scores
        scores = static_results.get("category_scores", {
            "security": 100,
            "performance": 100,
            "quality": 100,
            "architecture": 100
        })
        
        overall_score = static_results.get("overall_score", 85)
        
        # Create comprehensive summary
        nl_summary = static_results.get("natural_language_summary", "Code analysis completed")
        
        total_issues = sum(len(issues) for issues in organized_issues.values())
        
        enhanced_summary = f"{nl_summary} Advanced AI analysis identified {total_issues} areas for improvement including refactoring opportunities and performance optimizations."
        
        return {
            "overall_score": overall_score,
            "analysis_summary": enhanced_summary,
            "security": {
                "score": scores.get("security", 100),
                "issues": organized_issues["security"]
            },
            "performance": {
                "score": scores.get("performance", 100),
                "issues": organized_issues["performance"]
            },
            "quality": {
                "score": scores.get("quality", 100),
                "issues": organized_issues["quality"]
            },
            "architecture": {
                "score": scores.get("architecture", 100),
                "issues": organized_issues["architecture"]
            },
            "ai_insights": ai_insights,
            "metrics": static_results.get("metrics"),
            "recommendations": static_results.get("recommendations", []),
            "duplications": static_results.get("duplications", [])
        }
    
    def generate_commit_message_analysis(self, commit_message: str, code_changes: str) -> Dict[str, Any]:
        """Analyze commit message quality and suggest improvements"""
        try:
            prompt = f"""
Analyze this commit message and code changes for quality and clarity:

COMMIT MESSAGE: "{commit_message}"

CODE CHANGES:
{code_changes[:1000]}...

Evaluate:
1. Clarity and descriptiveness
2. Follows conventional commit format
3. Matches the actual code changes
4. Appropriate level of detail

Provide:
- Quality score (0-100)
- Specific improvement suggestions
- Recommended commit message if current one is poor

Format as JSON:
{{
    "quality_score": 85,
    "issues": ["Too vague", "Missing scope"],
    "suggestions": ["Add specific scope", "Describe what was changed"],
    "recommended_message": "feat(auth): add JWT token validation middleware"
}}
"""
            
            response = self.client.chat.completions.create(
                model=self.deployment_name,
                messages=[
                    {"role": "system", "content": "You are a Git commit message expert who helps developers write clear, informative commit messages."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=500,
                timeout=15
            )
            
            response_content = response.choices[0].message.content
            if response_content is None:
                logger.warning("Commit analysis response content is None")
                return {
                    "quality_score": 50,
                    "issues": ["Analysis unavailable"],
                    "suggestions": ["Write clear, descriptive commit messages"],
                    "recommended_message": commit_message
                }
            
            return self._parse_commit_analysis(response_content)
            
        except Exception as e:
            logger.error(f"Error analyzing commit message: {e}")
            return {
                "quality_score": 50,
                "issues": ["Analysis unavailable"],
                "suggestions": ["Write clear, descriptive commit messages"],
                "recommended_message": commit_message
            }
    
    def _parse_commit_analysis(self, response: str) -> Dict[str, Any]:
        """Parse commit message analysis response"""
        try:
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
        except:
            pass
        
        return {
            "quality_score": 70,
            "issues": [],
            "suggestions": ["Consider more descriptive commit messages"],
            "recommended_message": "Improve commit message clarity"
        }
    
    def generate_code_documentation(self, code: str, language: str) -> Dict[str, Any]:
        """Generate intelligent documentation suggestions"""
        try:
            prompt = f"""
Analyze this {language} code and suggest intelligent documentation:

```{language}
{code}
```

Provide:
1. Missing docstrings for functions/classes
2. Inline comments for complex logic
3. README documentation suggestions
4. API documentation if applicable

Format as JSON with specific line numbers and suggested content.
"""
            
            response = self.client.chat.completions.create(
                model=self.deployment_name,
                messages=[
                    {"role": "system", "content": "You are a technical documentation expert who creates clear, helpful documentation."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2,
                max_tokens=1000,
                timeout=20
            )
            
            response_content = response.choices[0].message.content
            if response_content is None:
                logger.warning("Documentation generation response content is None")
                return {"suggestions": []}
            
            return self._parse_documentation_suggestions(response_content)
            
        except Exception as e:
            logger.error(f"Error generating documentation: {e}")
            return {"suggestions": []}
    
    def _parse_documentation_suggestions(self, response: str) -> Dict[str, Any]:
        """Parse documentation suggestions"""
        try:
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
        except:
            pass
        
        return {
            "suggestions": [
                {
                    "type": "docstring",
                    "line_number": 1,
                    "suggestion": "Add comprehensive documentation to improve code maintainability"
                }
            ]
        }
    
    def _enhanced_basic_analysis(self, code: str, language: str, file_path: str) -> Dict[str, Any]:
        """Enhanced basic analysis when advanced features aren't available"""
        try:
            # Use the parent class analyze_code method with enhanced prompts
            basic_result = self.analyze_code(code, file_path)
            
            # Enhance the basic result with enterprise-style formatting
            if isinstance(basic_result, dict):
                # Convert to enhanced format
                enhanced_result = {
                    "overall_score": basic_result.get("overall_score", 75),
                    "analysis_summary": f"Enhanced AI analysis completed for {file_path}. " + 
                                      basic_result.get("analysis_summary", "Code analysis performed with AI insights."),
                    "security": {
                        "score": basic_result.get("security", {}).get("score", 80),
                        "issues": basic_result.get("security", {}).get("issues", [])
                    },
                    "performance": {
                        "score": basic_result.get("performance", {}).get("score", 75),
                        "issues": basic_result.get("performance", {}).get("issues", [])
                    },
                    "quality": {
                        "score": basic_result.get("quality", {}).get("score", 70),
                        "issues": basic_result.get("quality", {}).get("issues", [])
                    },
                    "architecture": {
                        "score": basic_result.get("architecture", {}).get("score", 75),
                        "issues": basic_result.get("architecture", {}).get("issues", [])
                    },
                    "ai_insights": {"refactoring_suggestions": [], "performance_tips": []},
                    "recommendations": ["Consider using advanced static analysis for deeper insights"]
                }
                return enhanced_result
            else:
                return self._create_fallback_analysis(code, file_path)
                
        except Exception as e:
            logger.error(f"Enhanced basic analysis failed: {e}")
            return self._create_fallback_analysis(code, file_path)
    
    def _create_fallback_analysis(self, code: str, file_path: str) -> Dict[str, Any]:
        """Create fallback analysis when advanced analysis fails"""
        return {
            "overall_score": 75,
            "analysis_summary": f"Basic code analysis completed for {file_path}. Advanced features temporarily unavailable.",
            "security": {"score": 80, "issues": []},
            "performance": {"score": 75, "issues": []},
            "quality": {"score": 70, "issues": []},
            "architecture": {"score": 75, "issues": []},
            "ai_insights": {"refactoring_suggestions": [], "performance_tips": []},
            "recommendations": ["Enable advanced analysis for comprehensive insights"]
        } 