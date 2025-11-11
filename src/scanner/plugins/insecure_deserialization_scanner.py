"""Insecure Deserialization vulnerability scanner plugin.

This plugin detects insecure deserialization patterns and unsafe data handling.
"""
import re
from typing import List, Dict, Any


class InsecureDeserializationScanner:
    """Scan for insecure deserialization vulnerabilities.
    
    Detects:
    - Unsafe pickle/serialization usage
    - Unsafe YAML loading
    - Unsafe XML parsing (XXE)
    - Unsafe JSON deserialization
    - Unvalidated object instantiation
    - Type confusion vulnerabilities
    """

    # Unsafe serialization patterns
    UNSAFE_PICKLE_PATTERNS = {
        r"pickle\.loads\s*\(",
        r"pickle\.load\s*\(",
        r"cPickle\.loads\s*\(",
        r"dill\.loads\s*\(",
        r"marshal\.loads\s*\(",
    }

    # Unsafe YAML patterns
    UNSAFE_YAML_PATTERNS = {
        r"yaml\.load\s*\(",
        r"yaml\.load_all\s*\(",
        r"yaml\.unsafe_load\s*\(",
        r"ruamel\.yaml",
    }

    # Unsafe XML patterns
    UNSAFE_XML_PATTERNS = {
        r"xml\.etree\.ElementTree\.XMLParser\s*\(",
        r"xml\.dom\.minidom\.parse\s*\(",
        r"expat\.ParserCreate\s*\(",
        r"lxml\.etree\.XMLParser\s*\(",
        r"etree\.XMLParser\s*\(",
        r"XMLParser\s*\(",
    }

    # Unsafe JSON patterns
    UNSAFE_JSON_PATTERNS = {
        r"json\.loads\s*\(",
        r"JSON\.parse\s*\(",
    }

    # Gadget chain indicators (common dangerous classes)
    GADGET_CHAIN_PATTERNS = {
        r"CommonsCollections",
        r"TransformedMap",
        r"ChainedTransformer",
        r"ConstantTransformer",
        r"InvokerTransformer",
        r"LazyMap",
        r"TiedMapEntry",
        r"Groovy",
        r"PropertyPathFactory",
    }

    def scan(self, target=None):
        """Scan target for deserialization vulnerabilities.
        
        Args:
            target: Code content to scan, or URL to fetch
            
        Returns:
            Dict with "vulnerabilities" key containing list of findings
        """
        if not target:
            return {"vulnerabilities": []}

        # If it's a URL, fetch content
        if isinstance(target, str) and target.startswith("http"):
            from src.utils import network
            content = network.make_get_request(target)
            if not content:
                return {"vulnerabilities": [{"url": target, "issue": "unreachable", "severity": "high"}]}
        else:
            content = target

        if not content:
            return {"vulnerabilities": []}

        findings = []

        # Check for various deserialization vulnerabilities
        findings.extend(self._check_unsafe_pickle(content))
        findings.extend(self._check_unsafe_yaml(content))
        findings.extend(self._check_unsafe_xml(content))
        findings.extend(self._check_unsafe_json(content))
        findings.extend(self._check_gadget_chains(content))
        findings.extend(self._check_unsafe_eval(content))

        return {"vulnerabilities": findings}

    def _check_unsafe_pickle(self, content: str) -> List[Dict[str, Any]]:
        """Check for unsafe pickle usage."""
        findings = []

        for pattern in self.UNSAFE_PICKLE_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                # Check if it's loading user input
                line_start = content.rfind("\n", 0, match.start()) + 1
                line_end = content.find("\n", match.end())
                line_content = content[line_start:line_end]

                severity = "critical"
                if any(indicator in line_content.lower() for indicator in ["request", "input", "user", "post", "get"]):
                    description = "Unsafe pickle.loads() on user input - remote code execution risk"
                else:
                    description = "Unsafe pickle usage detected"

                findings.append({
                    "url": "inline",
                    "issue": "unsafe_pickle",
                    "severity": severity,
                    "description": description,
                    "pattern": match.group(0),
                    "line": content[:match.start()].count("\n") + 1,
                })

        return findings

    def _check_unsafe_yaml(self, content: str) -> List[Dict[str, Any]]:
        """Check for unsafe YAML loading."""
        findings = []

        for pattern in self.UNSAFE_YAML_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                # Check if using safe_load
                safe_load = re.search(r"yaml\.safe_load", content[max(0, match.start()-200):match.end()+200], re.IGNORECASE)

                if not safe_load:
                    findings.append({
                        "url": "inline",
                        "issue": "unsafe_yaml_load",
                        "severity": "critical",
                        "description": "Unsafe YAML loading detected - use yaml.safe_load() instead",
                        "pattern": match.group(0),
                        "line": content[:match.start()].count("\n") + 1,
                    })

        return findings

    def _check_unsafe_xml(self, content: str) -> List[Dict[str, Any]]:
        """Check for unsafe XML parsing (XXE vulnerability)."""
        findings = []

        for pattern in self.UNSAFE_XML_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                # Check for XXE protection
                xxe_protected = re.search(r"(?:resolve_entities|feature_external_ges)\s*[:=]\s*False", content, re.IGNORECASE)

                findings.append({
                    "url": "inline",
                    "issue": "unsafe_xml_parsing",
                    "severity": "high",
                    "description": "Unsafe XML parser configured - XXE (XML External Entity) injection risk",
                    "pattern": match.group(0),
                    "line": content[:match.start()].count("\n") + 1,
                })

        return findings

    def _check_unsafe_json(self, content: str) -> List[Dict[str, Any]]:
        """Check for unsafe JSON deserialization."""
        findings = []

        # In Python, json.loads() is generally safe, but check for object_hook misuse
        object_hook_matches = re.finditer(
            r"(?:json|JSON)\.(?:parse|loads)\s*\([^)]*object_hook\s*=",
            content,
            re.IGNORECASE | re.DOTALL
        )

        for match in object_hook_matches:
            findings.append({
                "url": "inline",
                "issue": "unsafe_json_deserialization",
                "severity": "critical",
                "description": "JSON deserialization with object_hook - verify handler does not execute code",
                "pattern": match.group(0)[:80],
                "line": content[:match.start()].count("\n") + 1,
            })

        # Check for custom JSON decoders
        custom_decoder_matches = re.finditer(
            r"(?:JSONDecoder|json\.decoder)\s*\(\s*object_hook\s*[:=]",
            content,
            re.IGNORECASE
        )

        for match in custom_decoder_matches:
            findings.append({
                "url": "inline",
                "issue": "custom_json_decoder",
                "severity": "medium",
                "description": "Custom JSON decoder used - verify it safely handles untrusted input",
                "pattern": match.group(0),
                "line": content[:match.start()].count("\n") + 1,
            })

        return findings

    def _check_gadget_chains(self, content: str) -> List[Dict[str, Any]]:
        """Check for known gadget chain indicators (Java deserialization)."""
        findings = []

        for gadget in self.GADGET_CHAIN_PATTERNS:
            if gadget.lower() in content.lower():
                findings.append({
                    "url": "inline",
                    "issue": "gadget_chain_indicators",
                    "severity": "high",
                    "description": f"Gadget chain indicator detected: {gadget} - vulnerable to object instantiation exploits",
                })
                break

        # Check for ObjectInputStream usage
        if re.search(r"ObjectInputStream", content, re.IGNORECASE):
            findings.append({
                "url": "inline",
                "issue": "unsafe_java_deserialization",
                "severity": "critical",
                "description": "ObjectInputStream used - susceptible to deserialization attacks",
            })

        return findings

    def _check_unsafe_eval(self, content: str) -> List[Dict[str, Any]]:
        """Check for eval-like operations that could deserialize code."""
        findings = []

        eval_patterns = [
            r"eval\s*\(",
            r"exec\s*\(",
            r"compile\s*\(",
            r"__import__\s*\(",
            r"getattr\s*\(\s*__builtin__",
        ]

        for pattern in eval_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                findings.append({
                    "url": "inline",
                    "issue": "unsafe_eval",
                    "severity": "critical",
                    "description": f"Unsafe {match.group(0).strip()}() detected - allows arbitrary code execution",
                    "pattern": match.group(0),
                    "line": content[:match.start()].count("\n") + 1,
                })
                break

        return findings
