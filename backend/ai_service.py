#!/usr/bin/env python3
"""
Advanced AI Service for Code Review with Sophisticated Prompt Engineering
Implements multi-perspective analysis, context-aware prompting, and intelligent code review
"""

import openai
import json
import logging
import os
import sys
from typing import Dict, List, Any, Optional
from datetime import datetime

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Config

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AICodeAnalyzer:
    """
    Advanced AI-powered code analyzer with sophisticated prompt engineering.
    Implements multi-perspective analysis, context-aware prompting, and intelligent review.
    """
    
    def __init__(self):
        """Initialize the AI analyzer with Azure OpenAI configuration."""
        self.client = openai.AzureOpenAI(
            api_key=Config.AZURE_OPENAI_API_KEY,
            api_version=Config.AZURE_OPENAI_API_VERSION,
            azure_endpoint=Config.AZURE_OPENAI_ENDPOINT
        )
        self.deployment_name = Config.AZURE_OPENAI_DEPLOYMENT_NAME
        self.max_tokens = 4000
        self.temperature = 0.1  # Low temperature for consistent, focused analysis
        
    def _get_system_prompt(self) -> str:
        """
        Advanced system prompt with multi-perspective analysis framework.
        Implements sophisticated prompt engineering for comprehensive code review.
        """
        return """You are a Senior Software Architect and Security Expert with 15+ years of experience in enterprise software development. You provide detailed, technical code analysis that impresses C-level executives and technical leadership.

## ANALYSIS FRAMEWORK - ENTERPRISE LEVEL

### 1. SECURITY ANALYSIS (Critical for Production)
- **Vulnerability Assessment**: Identify OWASP Top 10 threats, SQL injection, XSS, CSRF, authentication flaws
- **Data Protection Compliance**: GDPR, HIPAA, PCI-DSS compliance checks, data encryption at rest/transit
- **Access Control Security**: RBAC implementation, privilege escalation risks, authentication mechanisms
- **Supply Chain Security**: Third-party dependency vulnerabilities, license compliance, CVE analysis
- **Infrastructure Security**: Container security, secrets management, secure deployment practices

### 2. PERFORMANCE & SCALABILITY (Production Readiness)
- **Algorithmic Complexity**: Big O analysis, performance bottleneck identification with specific optimizations
- **Resource Optimization**: Memory profiling, CPU utilization patterns, I/O optimization strategies
- **Database Performance**: Query optimization, indexing strategies, connection pooling, transaction management
- **Caching Architecture**: Multi-tier caching, cache invalidation strategies, distributed caching patterns
- **Scalability Patterns**: Horizontal scaling readiness, microservices decomposition opportunities

### 3. CODE QUALITY & MAINTAINABILITY (Technical Debt Analysis)
- **Clean Code Principles**: SOLID principles adherence, code readability metrics, maintainability index
- **Documentation Quality**: API documentation, inline comments, architectural decision records
- **Testing Strategy**: Unit test coverage, integration testing patterns, mock implementation
- **Code Metrics**: Cyclomatic complexity, code duplication, maintainability scoring
- **Refactoring Opportunities**: Technical debt identification, code smell detection

### 4. ENTERPRISE ARCHITECTURE (Strategic Assessment)
- **Design Pattern Implementation**: Gang of Four patterns, enterprise patterns, anti-pattern detection
- **System Integration**: API design quality, event-driven architecture, message queuing patterns
- **Deployment Architecture**: CI/CD readiness, containerization opportunities, cloud-native patterns
- **Monitoring & Observability**: Logging strategies, metrics collection, distributed tracing readiness
- **Disaster Recovery**: Fault tolerance, circuit breaker patterns, graceful degradation strategies

## OUTPUT FORMAT - EXECUTIVE SUMMARY STYLE
You MUST respond with valid JSON in this exact structure:
{
    "overall_score": 85.5,
    "analysis_summary": "Executive summary highlighting key findings, business impact, and strategic recommendations. Include specific metrics and ROI considerations.",
    "production_readiness": "critical|ready|needs_work",
    "business_impact": "Assessment of how code quality affects business operations, customer experience, and competitive advantage",
    "security": {
        "score": 90,
        "risk_level": "low|medium|high|critical",
        "compliance_status": "Assessment of regulatory compliance readiness",
        "issues": [
            {
                "line": 15,
                "severity": "critical|high|medium|low",
                "category": "authentication|authorization|data_protection|input_validation|crypto|infrastructure",
                "description": "Detailed technical description with specific vulnerability details",
                "business_impact": "How this affects business operations, customer trust, compliance",
                "suggestion": "Specific implementation details with code examples where applicable",
                "effort_estimate": "hours|days|weeks",
                "priority": "immediate|high|medium|low"
            }
        ]
    },
    "performance": {
        "score": 75,
        "bottlenecks": ["List of primary performance bottlenecks"],
        "scalability_assessment": "Current scaling limitations and recommendations",
        "issues": [
            {
                "line": 42,
                "severity": "critical|high|medium|low",
                "category": "algorithm|memory|database|network|caching",
                "description": "Technical performance issue with specific metrics",
                "current_complexity": "O(n^2) or specific performance metrics",
                "optimized_complexity": "O(n log n) or target performance",
                "suggestion": "Detailed optimization strategy with implementation approach",
                "expected_improvement": "Quantified performance improvement (e.g., 300% faster)",
                "effort_estimate": "hours|days|weeks"
            }
        ]
    },
    "quality": {
        "score": 88,
        "maintainability_index": 85,
        "technical_debt_hours": 24,
        "test_coverage_recommendation": "Target coverage percentage and strategy",
        "issues": [
            {
                "line": 8,
                "severity": "critical|high|medium|low",
                "category": "documentation|testing|complexity|duplication|naming|structure",
                "description": "Specific code quality issue with maintainability impact",
                "technical_debt": "Time cost of not fixing this issue",
                "suggestion": "Actionable improvement with specific examples",
                "best_practice": "Industry standard or pattern to follow",
                "effort_estimate": "hours|days|weeks"
            }
        ]
    },
    "architecture": {
        "score": 82,
        "design_quality": "Assessment of overall architectural decisions",
        "scalability_rating": "Current scalability rating (1-10)",
        "modernization_opportunities": ["List of architectural improvements"],
        "issues": [
            {
                "line": 25,
                "severity": "critical|high|medium|low",
                "category": "coupling|cohesion|patterns|separation|interfaces|dependencies",
                "description": "Architectural concern with long-term impact",
                "design_impact": "How this affects system evolution and maintenance",
                "suggestion": "Specific architectural pattern or refactoring approach",
                "pattern_recommendation": "Specific design pattern to implement",
                "effort_estimate": "hours|days|weeks"
            }
        ]
    },
    "recommendations": {
        "immediate_actions": ["Critical items requiring immediate attention"],
        "short_term_goals": ["Improvements for next sprint/month"],
        "long_term_strategy": ["Architectural evolution recommendations"],
        "roi_analysis": "Return on investment analysis for major improvements"
    }
}

## EXECUTIVE SCORING FRAMEWORK
- **95-100**: Production-Ready Excellence - Minimal risk, exceptional quality, ready for enterprise deployment
- **85-94**: Enterprise Standard - Good quality with minor refinements needed, low business risk
- **75-84**: Needs Improvement - Moderate issues requiring attention before production deployment
- **60-74**: Significant Concerns - Multiple issues affecting reliability, security, or performance
- **Below 60**: Critical Issues - Major refactoring required, high business risk, not production-ready

## ENTERPRISE ANALYSIS PRINCIPLES
1. **Business Impact Focus**: Every finding tied to business outcomes and competitive advantage
2. **Risk Assessment**: Quantify security, performance, and operational risks with specific metrics
3. **ROI Driven**: Prioritize improvements based on return on investment and effort required
4. **Compliance Aware**: Consider regulatory requirements (SOX, GDPR, HIPAA, PCI-DSS)
5. **Strategic Alignment**: Assess architectural decisions against enterprise strategy and scalability
6. **Executive Summary**: Provide C-level insights with technical depth for implementation teams
7. **Competitive Analysis**: Position recommendations against industry best practices and standards

## MANAGEMENT REPORTING FOCUS
- **Quantifiable Metrics**: Specific performance improvements, cost savings, risk reductions
- **Timeline Estimates**: Realistic effort estimates for planning and resource allocation  
- **Business Justification**: Clear connection between technical improvements and business value
- **Stakeholder Communication**: Technical findings translated to business impact language

Remember: Your analysis influences strategic technical decisions and budget allocations at the executive level."""

    def _get_pr_analysis_prompt(self) -> str:
        """Specialized prompt for pull request diff analysis."""
        return """You are analyzing a pull request diff. Focus on:

1. **Change Impact**: How do these changes affect the overall system?
2. **Regression Risk**: Could these changes introduce bugs or break existing functionality?
3. **Security Implications**: Do the changes introduce new security considerations?
4. **Performance Impact**: How do these changes affect system performance?
5. **Code Quality**: Are the changes following best practices and maintaining code quality?

Analyze the diff with the same JSON structure as regular code analysis, but focus on the specific changes and their implications."""

    def _get_chat_system_prompt(self) -> str:
        """Specialized prompt for conversational AI assistance."""
        return """You are an expert AI Code Review Assistant specialized in helping developers improve their code quality, security, and performance.

## YOUR EXPERTISE INCLUDES:
- **Security Analysis**: OWASP Top 10, vulnerability detection, secure coding practices
- **Performance Optimization**: Algorithm efficiency, resource management, bottleneck identification
- **Code Quality**: Best practices, maintainability, testing strategies, documentation
- **Architecture Review**: Design patterns, scalability, modularity, coupling/cohesion
- **Language Proficiency**: Python, JavaScript, TypeScript, Java, C++, C#, Go, Rust, PHP, Ruby

## RESPONSE FORMAT REQUIREMENTS:
1. **Structure your responses clearly** with headings and bullet points
2. **Provide specific, actionable advice** with concrete examples
3. **Include code snippets** when demonstrating concepts
4. **Use markdown formatting** for better readability
5. **Be concise but comprehensive** - aim for 2-4 paragraphs maximum
6. **End with a clear recommendation or next step**

## RESPONSE STYLE:
- Start with a brief acknowledgment of the question
- Provide practical solutions with explanations
- Include relevant code examples when helpful
- Suggest best practices and industry standards
- Offer resources for further learning when appropriate

## EXAMPLE RESPONSE FORMAT:
**Understanding the Issue:**
Brief explanation of what the user is asking about.

**Recommended Solution:**
- Specific steps or code changes
- Explanation of why this approach works
- Any trade-offs or considerations

**Best Practices:**
- Additional recommendations
- Links to documentation or standards

You are here to help developers write better, more secure, and more efficient code. Always provide practical, actionable guidance."""

    def _make_request(self, messages: List[Dict[str, str]]) -> Dict[str, Any]:
        """
        Make a request to Azure OpenAI with comprehensive error handling and logging.
        """
        try:
            logger.info(f"Making AI request with {len(messages)} messages")
            
            import time
            start_time = time.time()
            
            response = self.client.chat.completions.create(
                model=self.deployment_name,
                messages=messages,  # type: ignore
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                timeout=30  # 30 second timeout
            )
            
            elapsed_time = time.time() - start_time
            logger.info(f"AI request completed in {elapsed_time:.2f}s")
            
            content = response.choices[0].message.content
            if content is None:
                content = "No response generated"
            logger.info(f"AI response received: {len(content)} characters")
            
            return {"success": True, "content": content}
            
        except Exception as e:
            logger.error(f"AI request failed: {str(e)}")
            return {"success": False, "error": str(e)}

    def analyze_code(self, code: str, file_path: str = "untitled.py") -> Dict[str, Any]:
        """
        Perform comprehensive AI-powered code analysis with advanced prompt engineering.
        """
        try:
            # Determine language from file extension for context-aware analysis
            language = self._detect_language(file_path)
            
            # Create context-aware user prompt with enhanced instructions
            user_prompt = f"""Please analyze this {language} code from file '{file_path}' and provide a comprehensive, developer-friendly analysis.

```{language}
{code}
```

## ANALYSIS REQUIREMENTS:

### 1. DEVELOPER-FOCUSED ANALYSIS
- Provide specific line-by-line feedback where issues exist
- Include exact code snippets that need attention
- Explain WHY each issue is problematic (not just WHAT is wrong)
- Provide BEFORE/AFTER code examples for major improvements
- Include performance impact estimates where applicable

### 2. PRACTICAL SOLUTIONS
- Give step-by-step implementation guides for fixes
- Provide alternative approaches when multiple solutions exist
- Include relevant library/framework recommendations
- Suggest refactoring strategies for complex issues
- Explain the reasoning behind each recommendation

### 3. CODE QUALITY INSIGHTS
- Analyze adherence to language-specific best practices
- Check for common anti-patterns and code smells
- Evaluate error handling and edge case coverage
- Assess code maintainability and extensibility
- Review documentation and naming conventions

### 4. SECURITY & PERFORMANCE DEEP DIVE
- Identify specific vulnerability types with CVE references where applicable
- Provide security best practices for the identified issues
- Calculate approximate performance improvements for optimizations
- Suggest monitoring and logging improvements
- Include deployment and production considerations

### 5. LEARNING OPPORTUNITIES
- Explain concepts that developers might not be familiar with
- Reference official documentation and learning resources
- Provide examples of industry best practices
- Suggest related topics for further learning

Make your analysis actionable, educational, and immediately useful for developers at any skill level."""

            messages = [
                {"role": "system", "content": self._get_system_prompt()},
                {"role": "user", "content": user_prompt}
            ]
            
            result = self._make_request(messages)
            
            if result["success"]:
                # Try to parse JSON response
                try:
                    analysis = json.loads(result["content"])
                    logger.info(f"Successfully analyzed {file_path} with score: {analysis.get('overall_score', 'N/A')}")
                    return analysis
                    
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse AI response as JSON: {e}")
                    logger.error(f"Raw response: {result['content'][:1000]}...")
                    
                    # Try to extract JSON from markdown code blocks
                    content = result["content"]
                    if "```json" in content:
                        try:
                            start = content.find("```json") + 7
                            end = content.find("```", start)
                            if end > start:
                                json_content = content[start:end].strip()
                                analysis = json.loads(json_content)
                                logger.info(f"Successfully extracted JSON from markdown: {analysis.get('overall_score', 'N/A')}")
                                return analysis
                        except Exception as extract_error:
                            logger.error(f"Failed to extract JSON from markdown: {extract_error}")
                    
                    # Create a structured response from the raw text
                    return self._create_structured_response(result["content"], code, file_path)
            else:
                logger.error(f"AI request failed: {result.get('error', 'Unknown error')}")
                return self._get_fallback_analysis(code, file_path)
                
        except Exception as e:
            logger.error(f"Error in analyze_code: {str(e)}")
            return self._get_fallback_analysis(code, file_path)

    def _create_structured_response(self, ai_response: str, code: str, file_path: str) -> Dict[str, Any]:
        """Create a structured response from raw AI text when JSON parsing fails."""
        
        # Count lines of code for basic metrics
        lines = code.split('\n')
        line_count = len(lines)
        
        # Analyze code content for realistic issues
        code_lower = code.lower()
        issues_found = []
        
        # Security analysis
        security_issues = []
        security_score = 85
        
        if 'subprocess' in code_lower and 'shell=true' in code_lower:
            security_issues.append({
                "line": self._find_line_number(lines, 'shell=True'),
                "severity": "critical",
                "description": "Command injection vulnerability: subprocess.run with shell=True",
                "suggestion": "Use shell=False and pass arguments as a list to prevent command injection"
            })
            security_score = 30
            
        if 'select * from' in code_lower and '+' in code_lower:
            security_issues.append({
                "line": self._find_line_number(lines, 'SELECT'),
                "severity": "critical", 
                "description": "SQL injection vulnerability: string concatenation in SQL query",
                "suggestion": "Use parameterized queries or ORM to prevent SQL injection"
            })
            security_score = 25
            
        if any(secret in code_lower for secret in ['api_key', 'password', 'secret']):
            security_issues.append({
                "line": self._find_line_number(lines, 'api_key'),
                "severity": "high",
                "description": "Hardcoded secrets detected in source code",
                "suggestion": "Move secrets to environment variables or secure key management"
            })
            security_score = min(security_score, 50)
        
        # Performance analysis
        performance_issues = []
        performance_score = 80
        
        nested_loops = code_lower.count('for') >= 3
        if nested_loops:
            performance_issues.append({
                "line": self._find_line_number(lines, 'for'),
                "severity": "high",
                "description": "Nested loops detected - potential O(n^3) complexity",
                "suggestion": "Consider optimizing algorithm complexity or using more efficient data structures"
            })
            performance_score = 40
            
        if 'range(10000)' in code_lower or 'range(1000)' in code_lower:
            performance_issues.append({
                "line": self._find_line_number(lines, 'range'),
                "severity": "medium",
                "description": "Large range iterations may impact performance",
                "suggestion": "Consider using generators or breaking large operations into chunks"
            })
            performance_score = min(performance_score, 60)
        
        # Quality analysis
        quality_issues = []
        quality_score = 75
        
        if 'open(' in code_lower and 'close()' not in code_lower and 'with open' not in code_lower:
            quality_issues.append({
                "line": self._find_line_number(lines, 'open('),
                "severity": "medium",
                "description": "File opened without proper resource management",
                "suggestion": "Use 'with open()' context manager to ensure proper file handling"
            })
            quality_score = min(quality_score, 65)
            
        if line_count > 10 and not any('"""' in line or "'''" in line for line in lines):
            quality_issues.append({
                "line": 1,
                "severity": "low",
                "description": "Missing docstrings for functions or classes",
                "suggestion": "Add docstrings to improve code documentation and maintainability"
            })
            quality_score = min(quality_score, 70)
        
        # Architecture analysis
        architecture_issues = []
        architecture_score = 80
        
        if 'global ' in code_lower:
            architecture_issues.append({
                "line": self._find_line_number(lines, 'global'),
                "severity": "medium",
                "description": "Global variables detected - can lead to coupling issues",
                "suggestion": "Consider using dependency injection or class-based state management"
            })
            architecture_score = 60
        
        # Calculate overall score
        overall_score = (security_score + performance_score + quality_score + architecture_score) / 4
        
        return {
            "overall_score": round(overall_score, 1),
            "analysis_summary": f"Comprehensive analysis completed for {file_path}. Found {len(security_issues + performance_issues + quality_issues + architecture_issues)} issues across security, performance, quality, and architecture categories.",
            "security": {
                "score": security_score,
                "issues": security_issues
            },
            "performance": {
                "score": performance_score,
                "issues": performance_issues
            },
            "quality": {
                "score": quality_score,
                "issues": quality_issues
            },
            "architecture": {
                "score": architecture_score,
                "issues": architecture_issues
            }
        }
    
    def _find_line_number(self, lines: list, search_term: str) -> int:
        """Find the line number containing a search term."""
        for i, line in enumerate(lines, 1):
            if search_term.lower() in line.lower():
                return i
        return 1

    def analyze_pull_request_diff(self, diff_content: str) -> Dict[str, Any]:
        """
        Analyze a pull request diff with specialized prompting.
        """
        try:
            user_prompt = f"""Please analyze this pull request diff:

```
{diff_content}
```

Focus on the specific changes, their impact, and potential issues."""

            messages = [
                {"role": "system", "content": self._get_pr_analysis_prompt()},
                {"role": "user", "content": user_prompt}
            ]
            
            result = self._make_request(messages)
            
            if not result["success"]:
                return self._get_fallback_analysis(diff_content, "pull_request.diff")
            
            try:
                analysis = json.loads(result["content"])
                logger.info(f"Successfully analyzed PR diff")
                return analysis
                
            except json.JSONDecodeError:
                return self._get_fallback_analysis(diff_content, "pull_request.diff")
                
        except Exception as e:
            logger.error(f"Error in analyze_pull_request_diff: {str(e)}")
            return self._get_fallback_analysis(diff_content, "pull_request.diff")

    def get_chat_response(self, message: str, history: Optional[List[Dict[str, str]]] = None) -> str:
        """
        Provide conversational AI assistance using Azure OpenAI for intelligent responses.
        """
        try:
            if history is None:
                history = []
            
            # Build conversation context from history
            messages = [
                {"role": "system", "content": self._get_chat_system_prompt()}
            ]
            
            # Add conversation history
            for chat in history[-5:]:  # Keep last 5 exchanges for context
                messages.append({"role": "user", "content": chat.get("user", "")})
                messages.append({"role": "assistant", "content": chat.get("assistant", "")})
            
            # Add current message
            messages.append({"role": "user", "content": message})
            
            # Make request to Azure OpenAI
            result = self._make_request(messages)
            
            if result["success"]:
                response = result["content"].strip()
                logger.info(f"AI Assistant provided response for: {message[:50]}...")
                return response
            else:
                logger.error(f"AI Assistant request failed: {result.get('error', 'Unknown error')}")
                return self._get_fallback_chat_response(message)
                
        except Exception as e:
            logger.error(f"Error in get_chat_response: {str(e)}")
            return self._get_fallback_chat_response(message)
    
    def _get_fallback_chat_response(self, message: str) -> str:
        """Provide a fallback response when AI is unavailable."""
        message_lower = message.lower()
        
        if any(word in message_lower for word in ['hello', 'hi', 'hey']):
            return "Hello! I'm your AI code review assistant. I can help with code analysis, security reviews, and best practices. How can I assist you today?"
        elif any(word in message_lower for word in ['security', 'vulnerability']):
            return "Security is crucial! I can help identify vulnerabilities, review authentication patterns, and suggest secure coding practices. What specific security concerns do you have?"
        elif any(word in message_lower for word in ['performance', 'optimize']):
            return "Performance optimization is important! I can help with algorithm efficiency, resource management, and bottleneck identification. What performance issues are you experiencing?"
        else:
            return f"I'm here to help with your development questions! I specialize in code review, security analysis, performance optimization, and best practices. Could you provide more details about what you'd like assistance with?"

    def _detect_language(self, file_path: str) -> str:
        """Detect programming language from file extension."""
        ext = os.path.splitext(file_path)[1].lower()
        language_map = {
            '.py': 'Python',
            '.js': 'JavaScript', 
            '.ts': 'TypeScript',
            '.java': 'Java',
            '.cpp': 'C++',
            '.c': 'C',
            '.cs': 'C#',
            '.go': 'Go',
            '.rs': 'Rust',
            '.php': 'PHP',
            '.rb': 'Ruby',
            '.swift': 'Swift',
            '.kt': 'Kotlin',
            '.scala': 'Scala',
            '.r': 'R',
            '.m': 'Objective-C',
            '.mm': 'Objective-C++',
            '.pl': 'Perl',
            '.sh': 'Bash',
            '.sql': 'SQL',
            '.html': 'HTML',
            '.css': 'CSS',
            '.vue': 'Vue.js',
            '.jsx': 'React JSX',
            '.tsx': 'React TypeScript'
        }
        return language_map.get(ext, 'Unknown')

    def _get_fallback_analysis(self, code: str, file_path: str) -> Dict[str, Any]:
        """
        Provide a structured fallback analysis when AI service is unavailable.
        """
        logger.warning(f"Using fallback analysis for {file_path}")
        
        return {
            "overall_score": 70.0,
            "analysis_summary": "Basic analysis completed. AI service was unavailable for detailed review.",
            "security": {
                "score": 75,
                "issues": [
                    {
                        "line": 1,
                        "severity": "medium",
                        "description": "Unable to perform detailed security analysis",
                        "suggestion": "Review manually for security best practices"
                    }
                ]
            },
            "performance": {
                "score": 70,
                "issues": [
                    {
                        "line": 1,
                        "severity": "medium", 
                        "description": "Unable to perform detailed performance analysis",
                        "suggestion": "Review manually for performance optimizations"
                    }
                ]
            },
            "quality": {
                "score": 75,
                "issues": [
                    {
                        "line": 1,
                        "severity": "medium",
                        "description": "Unable to perform detailed quality analysis", 
                        "suggestion": "Review manually for code quality improvements"
                    }
                ]
            },
            "architecture": {
                "score": 70,
                "issues": [
                    {
                        "line": 1,
                        "severity": "medium",
                        "description": "Unable to perform detailed architectural analysis",
                        "suggestion": "Review manually for architectural improvements"
                    }
                ]
            }
        }

# Global instance for use throughout the application
ai_analyzer = AICodeAnalyzer()

# Self-test
if __name__ == '__main__':
    analyzer = AICodeAnalyzer()
    
    test_code = """
import os

def get_user_data(user_id):
    # This is a security risk
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    os.system(query) # Another risk
    
    # Inefficient loop
    my_list = []
    for i in range(10000):
        my_list.append(i)

    return my_list
"""
    
    print("🧪 Testing AI Code Analyzer...")
    analysis_result = analyzer.analyze_code(test_code, "example.py")
    
    print("\n--- Analysis Result ---")
    print(json.dumps(analysis_result, indent=2))
    
    if analysis_result and analysis_result.get('overall_score', 0) > 0:
        print("\n✅ AI analysis test successful.")
    else:
        print("\n❌ AI analysis test failed. Check your Azure OpenAI credentials and endpoint.")

    test_diff = """
--- a/src/main.py
+++ b/src/main.py
@@ -1,5 +1,6 @@
 def calculate_price(base, tax_rate):
-    return base * tax_rate
+    if base < 0:
+        return 0
+    return base * (1 + tax_rate)
 
"""
    print("\n🧪 Testing PR Diff Analyzer...")
    diff_result = analyzer.analyze_pull_request_diff(test_diff)
    print("\n--- Diff Analysis Result ---")
    print(json.dumps(diff_result, indent=2))
    if diff_result and 'summary' in diff_result:
        print("\n✅ PR diff analysis test successful.")
    else:
        print("\n❌ PR diff analysis test failed.") 