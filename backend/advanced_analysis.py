#!/usr/bin/env python3
"""
Advanced Code Analysis Module
Implements enterprise-grade code review features including static analysis,
security scanning, ML-based bug prediction, and code quality metrics.
"""

import ast
import re
import hashlib
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from collections import defaultdict
import difflib

logger = logging.getLogger(__name__)

@dataclass
class CodeIssue:
    """Represents a code issue found during analysis"""
    line_number: int
    severity: str  # critical, high, medium, low
    category: str  # security, performance, quality, architecture, style
    issue_type: str
    description: str
    suggestion: str
    confidence: float
    rule_id: str

@dataclass
class CodeMetrics:
    """Code complexity and quality metrics"""
    cyclomatic_complexity: int
    lines_of_code: int
    maintainability_index: float
    technical_debt_ratio: float
    duplication_percentage: float
    test_coverage: float

class StaticCodeAnalyzer:
    """Performs comprehensive static code analysis"""
    
    def __init__(self):
        self.security_patterns = self._load_security_patterns()
        self.performance_patterns = self._load_performance_patterns()
        self.quality_rules = self._load_quality_rules()
    
    def analyze_code(self, code: str, language: str, file_path: str) -> Dict[str, Any]:
        """Perform comprehensive static analysis"""
        try:
            issues = []
            metrics = self._calculate_metrics(code, language)
            
            # Static analysis checks
            issues.extend(self._check_security_vulnerabilities(code, language))
            issues.extend(self._check_performance_issues(code, language))
            issues.extend(self._check_code_quality(code, language))
            issues.extend(self._check_style_compliance(code, language))
            issues.extend(self._check_complexity(code, language))
            
            # Advanced ML-based checks
            issues.extend(self._predict_bugs(code, language))
            issues.extend(self._detect_code_smells(code, language))
            
            return {
                "issues": issues,
                "metrics": metrics,
                "summary": self._generate_analysis_summary(issues, metrics),
                "recommendations": self._generate_recommendations(issues, metrics)
            }
        except Exception as e:
            logger.error(f"Error in static analysis: {e}")
            return {"issues": [], "metrics": None, "summary": "", "recommendations": []}
    
    def _load_security_patterns(self) -> Dict[str, List[Dict]]:
        """Load security vulnerability patterns"""
        return {
            "python": [
                {
                    "pattern": r"subprocess\.(run|call|Popen).*shell\s*=\s*True",
                    "severity": "critical",
                    "description": "Command injection vulnerability: shell=True allows arbitrary command execution",
                    "suggestion": "Use shell=False and pass arguments as a list",
                    "rule_id": "SEC001"
                },
                {
                    "pattern": r"eval\s*\(",
                    "severity": "critical", 
                    "description": "Code injection vulnerability: eval() executes arbitrary code",
                    "suggestion": "Use ast.literal_eval() for safe evaluation or avoid eval()",
                    "rule_id": "SEC002"
                },
                {
                    "pattern": r"exec\s*\(",
                    "severity": "critical",
                    "description": "Code injection vulnerability: exec() executes arbitrary code",
                    "suggestion": "Avoid exec() or use safer alternatives",
                    "rule_id": "SEC003"
                },
                {
                    "pattern": r"pickle\.loads?\s*\(",
                    "severity": "high",
                    "description": "Deserialization vulnerability: pickle can execute arbitrary code",
                    "suggestion": "Use json or safer serialization methods",
                    "rule_id": "SEC004"
                },
                {
                    "pattern": r"(password|secret|key|token)\s*=\s*['\"][^'\"]{8,}['\"]",
                    "severity": "high",
                    "description": "Hardcoded secrets detected in source code",
                    "suggestion": "Move secrets to environment variables or secure vault",
                    "rule_id": "SEC005"
                },
                {
                    "pattern": r"random\.random\(\)|random\.choice\(",
                    "severity": "medium",
                    "description": "Weak random number generation for security purposes",
                    "suggestion": "Use secrets module for cryptographic randomness",
                    "rule_id": "SEC006"
                }
            ],
            "javascript": [
                {
                    "pattern": r"eval\s*\(",
                    "severity": "critical",
                    "description": "Code injection vulnerability: eval() executes arbitrary code",
                    "suggestion": "Use JSON.parse() or safer alternatives",
                    "rule_id": "SEC101"
                },
                {
                    "pattern": r"innerHTML\s*=.*\+",
                    "severity": "high",
                    "description": "XSS vulnerability: innerHTML with concatenation",
                    "suggestion": "Use textContent or sanitize input",
                    "rule_id": "SEC102"
                }
            ]
        }
    
    def _load_performance_patterns(self) -> Dict[str, List[Dict]]:
        """Load performance anti-patterns"""
        return {
            "python": [
                {
                    "pattern": r"for\s+\w+\s+in\s+range\(len\(",
                    "severity": "medium",
                    "description": "Inefficient iteration pattern",
                    "suggestion": "Use enumerate() or direct iteration",
                    "rule_id": "PERF001"
                },
                {
                    "pattern": r"\+\s*=.*\[.*\]",
                    "severity": "medium",
                    "description": "Inefficient list concatenation in loop",
                    "suggestion": "Use list.extend() or list comprehension",
                    "rule_id": "PERF002"
                },
                {
                    "pattern": r"\.append\(.*\)\s*\n.*for.*in.*:",
                    "severity": "low",
                    "description": "Consider using list comprehension",
                    "suggestion": "Replace with list comprehension for better performance",
                    "rule_id": "PERF003"
                }
            ]
        }
    
    def _load_quality_rules(self) -> Dict[str, List[Dict]]:
        """Load code quality rules"""
        return {
            "python": [
                {
                    "pattern": r"def\s+\w+\([^)]*\):\s*\n(?:\s*#.*\n)*\s*[^\"']",
                    "severity": "low",
                    "description": "Function missing docstring",
                    "suggestion": "Add descriptive docstring to function",
                    "rule_id": "QUAL001"
                },
                {
                    "pattern": r"class\s+\w+[^:]*:\s*\n(?:\s*#.*\n)*\s*[^\"']",
                    "severity": "low", 
                    "description": "Class missing docstring",
                    "suggestion": "Add descriptive docstring to class",
                    "rule_id": "QUAL002"
                },
                {
                    "pattern": r"except\s*:",
                    "severity": "medium",
                    "description": "Bare except clause catches all exceptions",
                    "suggestion": "Catch specific exceptions instead of using bare except",
                    "rule_id": "QUAL003"
                }
            ]
        }
    
    def _check_security_vulnerabilities(self, code: str, language: str) -> List[CodeIssue]:
        """Check for security vulnerabilities"""
        issues = []
        patterns = self.security_patterns.get(language, [])
        
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            for pattern_info in patterns:
                if re.search(pattern_info["pattern"], line, re.IGNORECASE):
                    issues.append(CodeIssue(
                        line_number=i,
                        severity=pattern_info["severity"],
                        category="security",
                        issue_type="vulnerability",
                        description=pattern_info["description"],
                        suggestion=pattern_info["suggestion"],
                        confidence=0.9,
                        rule_id=pattern_info["rule_id"]
                    ))
        
        return issues
    
    def _check_performance_issues(self, code: str, language: str) -> List[CodeIssue]:
        """Check for performance issues"""
        issues = []
        patterns = self.performance_patterns.get(language, [])
        
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            for pattern_info in patterns:
                if re.search(pattern_info["pattern"], line):
                    issues.append(CodeIssue(
                        line_number=i,
                        severity=pattern_info["severity"],
                        category="performance",
                        issue_type="inefficiency",
                        description=pattern_info["description"],
                        suggestion=pattern_info["suggestion"],
                        confidence=0.8,
                        rule_id=pattern_info["rule_id"]
                    ))
        
        return issues
    
    def _check_code_quality(self, code: str, language: str) -> List[CodeIssue]:
        """Check code quality issues"""
        issues = []
        patterns = self.quality_rules.get(language, [])
        
        for pattern_info in patterns:
            matches = list(re.finditer(pattern_info["pattern"], code, re.MULTILINE))
            for match in matches:
                line_number = code[:match.start()].count('\n') + 1
                issues.append(CodeIssue(
                    line_number=line_number,
                    severity=pattern_info["severity"],
                    category="quality",
                    issue_type="maintainability",
                    description=pattern_info["description"],
                    suggestion=pattern_info["suggestion"],
                    confidence=0.7,
                    rule_id=pattern_info["rule_id"]
                ))
        
        return issues
    
    def _check_style_compliance(self, code: str, language: str) -> List[CodeIssue]:
        """Check style and formatting compliance"""
        issues = []
        
        if language == "python":
            lines = code.split('\n')
            for i, line in enumerate(lines, 1):
                # Check line length
                if len(line) > 120:
                    issues.append(CodeIssue(
                        line_number=i,
                        severity="low",
                        category="style",
                        issue_type="formatting",
                        description=f"Line too long ({len(line)} > 120 characters)",
                        suggestion="Break long lines for better readability",
                        confidence=1.0,
                        rule_id="STYLE001"
                    ))
                
                # Check trailing whitespace
                if line.endswith(' ') or line.endswith('\t'):
                    issues.append(CodeIssue(
                        line_number=i,
                        severity="low",
                        category="style",
                        issue_type="formatting",
                        description="Trailing whitespace",
                        suggestion="Remove trailing whitespace",
                        confidence=1.0,
                        rule_id="STYLE002"
                    ))
        
        return issues
    
    def _check_complexity(self, code: str, language: str) -> List[CodeIssue]:
        """Check code complexity"""
        issues = []
        
        if language == "python":
            try:
                tree = ast.parse(code)
                complexity_analyzer = CyclomaticComplexityAnalyzer()
                complexity_analyzer.visit(tree)
                
                for func_name, complexity in complexity_analyzer.complexities.items():
                    if complexity > 10:
                        issues.append(CodeIssue(
                            line_number=1,  # Would need AST line number extraction
                            severity="high" if complexity > 15 else "medium",
                            category="architecture",
                            issue_type="complexity",
                            description=f"Function '{func_name}' has high cyclomatic complexity ({complexity})",
                            suggestion="Consider breaking down into smaller functions",
                            confidence=0.9,
                            rule_id="COMP001"
                        ))
            except SyntaxError:
                pass  # Skip complexity analysis for invalid syntax
        
        return issues
    
    def _predict_bugs(self, code: str, language: str) -> List[CodeIssue]:
        """ML-based bug prediction"""
        issues = []
        
        # Simple heuristic-based bug prediction (would be replaced with ML model)
        bug_patterns = {
            "python": [
                {
                    "pattern": r"if\s+\w+\s*==\s*None:",
                    "description": "Potential None comparison issue",
                    "suggestion": "Use 'is None' instead of '== None'",
                    "confidence": 0.6
                },
                {
                    "pattern": r"except.*:\s*pass",
                    "description": "Silent exception handling may hide bugs",
                    "suggestion": "Log exceptions or handle them appropriately",
                    "confidence": 0.7
                }
            ]
        }
        
        patterns = bug_patterns.get(language, [])
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern_info in patterns:
                if re.search(pattern_info["pattern"], line):
                    issues.append(CodeIssue(
                        line_number=i,
                        severity="medium",
                        category="quality",
                        issue_type="bug_risk",
                        description=pattern_info["description"],
                        suggestion=pattern_info["suggestion"],
                        confidence=pattern_info["confidence"],
                        rule_id="BUG001"
                    ))
        
        return issues
    
    def _detect_code_smells(self, code: str, language: str) -> List[CodeIssue]:
        """Detect code smells"""
        issues = []
        
        # Long parameter lists
        if language == "python":
            long_param_pattern = r"def\s+\w+\s*\([^)]{50,}\):"
            matches = list(re.finditer(long_param_pattern, code))
            for match in matches:
                line_number = code[:match.start()].count('\n') + 1
                issues.append(CodeIssue(
                    line_number=line_number,
                    severity="medium",
                    category="architecture",
                    issue_type="code_smell",
                    description="Function has too many parameters",
                    suggestion="Consider using a configuration object or breaking down the function",
                    confidence=0.8,
                    rule_id="SMELL001"
                ))
        
        return issues
    
    def _calculate_metrics(self, code: str, language: str) -> CodeMetrics:
        """Calculate code metrics"""
        lines = code.split('\n')
        loc = len([line for line in lines if line.strip() and not line.strip().startswith('#')])
        
        # Simple metrics calculation (would be enhanced with proper tools)
        complexity = self._calculate_cyclomatic_complexity(code, language)
        maintainability = max(0, 100 - complexity * 2)  # Simplified calculation
        
        return CodeMetrics(
            cyclomatic_complexity=complexity,
            lines_of_code=loc,
            maintainability_index=maintainability,
            technical_debt_ratio=min(100, complexity / loc * 100) if loc > 0 else 0,
            duplication_percentage=0.0,  # Would need proper duplication analysis
            test_coverage=0.0  # Would need test analysis
        )
    
    def _calculate_cyclomatic_complexity(self, code: str, language: str) -> int:
        """Calculate cyclomatic complexity"""
        if language == "python":
            try:
                tree = ast.parse(code)
                analyzer = CyclomaticComplexityAnalyzer()
                analyzer.visit(tree)
                return max(analyzer.complexities.values()) if analyzer.complexities else 1
            except SyntaxError:
                return 1
        
        # Simple heuristic for other languages
        complexity_keywords = ['if', 'else', 'elif', 'for', 'while', 'try', 'except', 'case']
        complexity = 1  # Base complexity
        for keyword in complexity_keywords:
            complexity += len(re.findall(rf'\b{keyword}\b', code, re.IGNORECASE))
        
        return complexity
    
    def _generate_analysis_summary(self, issues: List[CodeIssue], metrics: CodeMetrics) -> str:
        """Generate analysis summary"""
        severity_counts = defaultdict(int)
        category_counts = defaultdict(int)
        
        for issue in issues:
            severity_counts[issue.severity] += 1
            category_counts[issue.category] += 1
        
        summary_parts = []
        if severity_counts['critical'] > 0:
            summary_parts.append(f"{severity_counts['critical']} critical security issues")
        if severity_counts['high'] > 0:
            summary_parts.append(f"{severity_counts['high']} high-priority issues")
        
        summary = f"Analyzed {metrics.lines_of_code} lines of code with complexity {metrics.cyclomatic_complexity}. "
        if summary_parts:
            summary += f"Found {', '.join(summary_parts)}. "
        
        summary += f"Maintainability index: {metrics.maintainability_index:.1f}/100."
        
        return summary
    
    def _generate_recommendations(self, issues: List[CodeIssue], metrics: CodeMetrics) -> List[str]:
        """Generate improvement recommendations"""
        recommendations = []
        
        critical_issues = [i for i in issues if i.severity == 'critical']
        if critical_issues:
            recommendations.append("🚨 Address critical security vulnerabilities immediately")
        
        if metrics.cyclomatic_complexity > 10:
            recommendations.append("🔧 Reduce code complexity by breaking down large functions")
        
        if metrics.maintainability_index < 50:
            recommendations.append("📚 Improve code documentation and structure")
        
        security_issues = [i for i in issues if i.category == 'security']
        if security_issues:
            recommendations.append("🔒 Review and fix security vulnerabilities")
        
        performance_issues = [i for i in issues if i.category == 'performance']
        if performance_issues:
            recommendations.append("⚡ Optimize performance bottlenecks")
        
        return recommendations

class CyclomaticComplexityAnalyzer(ast.NodeVisitor):
    """AST visitor to calculate cyclomatic complexity"""
    
    def __init__(self):
        self.complexities = {}
        self.current_function = None
        self.current_complexity = 0
    
    def visit_FunctionDef(self, node):
        old_function = self.current_function
        old_complexity = self.current_complexity
        
        self.current_function = node.name
        self.current_complexity = 1  # Base complexity
        
        self.generic_visit(node)
        
        self.complexities[self.current_function] = self.current_complexity
        
        self.current_function = old_function
        self.current_complexity = old_complexity
    
    def visit_If(self, node):
        self.current_complexity += 1
        self.generic_visit(node)
    
    def visit_For(self, node):
        self.current_complexity += 1
        self.generic_visit(node)
    
    def visit_While(self, node):
        self.current_complexity += 1
        self.generic_visit(node)
    
    def visit_Try(self, node):
        self.current_complexity += 1
        self.generic_visit(node)

class CodeDuplicationDetector:
    """Detects code duplication and similarity"""
    
    def __init__(self):
        self.similarity_threshold = 0.8
    
    def detect_duplications(self, code: str, language: str) -> List[Dict[str, Any]]:
        """Detect code duplications"""
        duplications = []
        
        # Split code into functions/blocks
        blocks = self._extract_code_blocks(code, language)
        
        # Compare blocks for similarity
        for i, block1 in enumerate(blocks):
            for j, block2 in enumerate(blocks[i+1:], i+1):
                similarity = self._calculate_similarity(block1['content'], block2['content'])
                if similarity > self.similarity_threshold:
                    duplications.append({
                        'block1': block1,
                        'block2': block2,
                        'similarity': similarity,
                        'suggestion': 'Consider extracting common code into a reusable function'
                    })
        
        return duplications
    
    def _extract_code_blocks(self, code: str, language: str) -> List[Dict[str, Any]]:
        """Extract code blocks for comparison"""
        blocks = []
        
        if language == "python":
            try:
                tree = ast.parse(code)
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                        start_line = node.lineno
                        # Simplified block extraction
                        lines = code.split('\n')
                        block_lines = []
                        indent_level = None
                        
                        for i in range(start_line - 1, len(lines)):
                            line = lines[i]
                            if line.strip():
                                if indent_level is None:
                                    indent_level = len(line) - len(line.lstrip())
                                elif len(line) - len(line.lstrip()) <= indent_level and i > start_line - 1:
                                    break
                                block_lines.append(line)
                        
                        blocks.append({
                            'type': 'function' if isinstance(node, ast.FunctionDef) else 'class',
                            'name': node.name,
                            'start_line': start_line,
                            'content': '\n'.join(block_lines)
                        })
            except SyntaxError:
                pass
        
        return blocks
    
    def _calculate_similarity(self, content1: str, content2: str) -> float:
        """Calculate similarity between two code blocks"""
        # Normalize content
        normalized1 = self._normalize_code(content1)
        normalized2 = self._normalize_code(content2)
        
        # Use difflib to calculate similarity
        similarity = difflib.SequenceMatcher(None, normalized1, normalized2).ratio()
        return similarity
    
    def _normalize_code(self, code: str) -> str:
        """Normalize code for comparison"""
        # Remove comments and normalize whitespace
        lines = []
        for line in code.split('\n'):
            line = re.sub(r'#.*', '', line)  # Remove comments
            line = line.strip()
            if line:
                lines.append(line)
        return '\n'.join(lines)

class NaturalLanguageSummarizer:
    """Generates natural language summaries of code"""
    
    def summarize_code(self, code: str, language: str, file_path: str) -> str:
        """Generate human-readable code summary"""
        try:
            if language == "python":
                return self._summarize_python_code(code, file_path)
            else:
                return self._summarize_generic_code(code, language, file_path)
        except Exception as e:
            logger.error(f"Error summarizing code: {e}")
            return f"Code analysis completed for {file_path}"
    
    def _summarize_python_code(self, code: str, file_path: str) -> str:
        """Summarize Python code"""
        try:
            tree = ast.parse(code)
            
            functions = []
            classes = []
            imports = []
            
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    functions.append(node.name)
                elif isinstance(node, ast.ClassDef):
                    classes.append(node.name)
                elif isinstance(node, (ast.Import, ast.ImportFrom)):
                    imports.extend(self._extract_import_names(node))
            
            summary_parts = []
            
            if classes:
                summary_parts.append(f"defines {len(classes)} class{'es' if len(classes) > 1 else ''} ({', '.join(classes[:3])}{'...' if len(classes) > 3 else ''})")
            
            if functions:
                summary_parts.append(f"implements {len(functions)} function{'s' if len(functions) > 1 else ''} ({', '.join(functions[:3])}{'...' if len(functions) > 3 else ''})")
            
            if imports:
                summary_parts.append(f"imports {len(set(imports))} module{'s' if len(set(imports)) > 1 else ''}")
            
            lines_count = len([line for line in code.split('\n') if line.strip()])
            
            summary = f"This Python file ({file_path}) contains {lines_count} lines of code"
            if summary_parts:
                summary += f" and {', '.join(summary_parts)}"
            summary += "."
            
            return summary
            
        except SyntaxError:
            return f"Python file {file_path} contains code with syntax issues"
    
    def _summarize_generic_code(self, code: str, language: str, file_path: str) -> str:
        """Summarize code for non-Python languages"""
        lines = [line for line in code.split('\n') if line.strip()]
        
        # Simple heuristics for different languages
        functions = len(re.findall(r'\bfunction\b|\bdef\b|\bpublic\s+\w+\s*\(', code, re.IGNORECASE))
        classes = len(re.findall(r'\bclass\b', code, re.IGNORECASE))
        
        summary = f"This {language} file ({file_path}) contains {len(lines)} lines of code"
        
        if classes > 0:
            summary += f" with {classes} class{'es' if classes > 1 else ''}"
        if functions > 0:
            summary += f" and {functions} function{'s' if functions > 1 else ''}"
        
        return summary + "."
    
    def _extract_import_names(self, node) -> List[str]:
        """Extract import names from AST node"""
        names = []
        if isinstance(node, ast.Import):
            names.extend([alias.name for alias in node.names])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                names.append(node.module)
        return names

# Main analysis orchestrator
class AdvancedCodeAnalyzer:
    """Main class that orchestrates all advanced analysis features"""
    
    def __init__(self):
        self.static_analyzer = StaticCodeAnalyzer()
        self.duplication_detector = CodeDuplicationDetector()
        self.nl_summarizer = NaturalLanguageSummarizer()
    
    def perform_comprehensive_analysis(self, code: str, language: str, file_path: str) -> Dict[str, Any]:
        """Perform comprehensive code analysis"""
        logger.info(f"Starting comprehensive analysis for {file_path}")
        
        # Static analysis
        static_results = self.static_analyzer.analyze_code(code, language, file_path)
        
        # Duplication detection
        duplications = self.duplication_detector.detect_duplications(code, language)
        
        # Natural language summary
        nl_summary = self.nl_summarizer.summarize_code(code, language, file_path)
        
        # Combine results
        all_issues = static_results["issues"]
        
        # Add duplication issues
        for dup in duplications:
            all_issues.append(CodeIssue(
                line_number=dup['block1']['start_line'],
                severity="medium",
                category="quality",
                issue_type="duplication",
                description=f"Code duplication detected (similarity: {dup['similarity']:.1%})",
                suggestion=dup['suggestion'],
                confidence=dup['similarity'],
                rule_id="DUP001"
            ))
        
        # Calculate overall scores
        scores = self._calculate_scores(all_issues, static_results["metrics"])
        
        return {
            "overall_score": scores["overall"],
            "category_scores": scores["categories"],
            "issues": all_issues,
            "metrics": static_results["metrics"],
            "duplications": duplications,
            "natural_language_summary": nl_summary,
            "recommendations": static_results["recommendations"],
            "analysis_summary": static_results["summary"]
        }
    
    def _calculate_scores(self, issues: List[CodeIssue], metrics: CodeMetrics) -> Dict[str, Any]:
        """Calculate quality scores"""
        # Base scores
        security_score = 100
        performance_score = 100
        quality_score = 100
        architecture_score = 100
        
        # Deduct points based on issues
        for issue in issues:
            deduction = {"critical": 20, "high": 10, "medium": 5, "low": 2}.get(issue.severity, 1)
            
            if issue.category == "security":
                security_score = max(0, security_score - deduction)
            elif issue.category == "performance":
                performance_score = max(0, performance_score - deduction)
            elif issue.category == "quality":
                quality_score = max(0, quality_score - deduction)
            elif issue.category == "architecture":
                architecture_score = max(0, architecture_score - deduction)
        
        # Factor in complexity
        if metrics and metrics.cyclomatic_complexity > 10:
            architecture_score = max(0, architecture_score - (metrics.cyclomatic_complexity - 10) * 2)
        
        overall_score = (security_score + performance_score + quality_score + architecture_score) / 4
        
        return {
            "overall": round(overall_score, 1),
            "categories": {
                "security": security_score,
                "performance": performance_score,
                "quality": quality_score,
                "architecture": architecture_score
            }
        } 