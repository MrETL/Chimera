"""Paper Monitor - Track AI Security Research from arXiv.

Monitors arXiv and other sources for new AI security papers,
extracts attack techniques, and flags papers for implementation.
Uses the arXiv MCP server when available, falls back to HTTP API.
"""

from typing import List, Dict, Any, Optional
import logging
import json
import time
import re
import urllib.request
import urllib.parse
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)


class Paper:
    """Represents a research paper."""

    def __init__(self, arxiv_id: str, title: str, abstract: str,
                 authors: List[str], published: str, url: str):
        self.arxiv_id = arxiv_id
        self.title = title
        self.abstract = abstract
        self.authors = authors
        self.published = published
        self.url = url
        self.relevance_score: float = 0.0
        self.attack_techniques: List[str] = []
        self.implementation_status: str = "unreviewed"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "arxiv_id": self.arxiv_id,
            "title": self.title,
            "abstract": self.abstract[:300],
            "authors": self.authors[:3],
            "published": self.published,
            "url": self.url,
            "relevance_score": self.relevance_score,
            "attack_techniques": self.attack_techniques,
            "implementation_status": self.implementation_status,
        }


class PaperMonitor:
    """Monitor arXiv for AI security research papers.
    
    Searches for papers on:
    - LLM jailbreaks and prompt injection
    - Adversarial attacks on ML models
    - AI agent security
    - Red teaming techniques
    - Safety evaluation methods
    """

    SEARCH_QUERIES = [
        "LLM jailbreak attack",
        "prompt injection large language model",
        "adversarial attack language model",
        "AI agent security vulnerability",
        "red teaming language model",
        "safety alignment bypass",
        "multimodal adversarial attack",
        "reward hacking language model",
    ]

    # Keywords that indicate high relevance
    HIGH_RELEVANCE_KEYWORDS = [
        "jailbreak", "prompt injection", "adversarial", "bypass",
        "attack", "vulnerability", "exploit", "red team",
        "safety", "alignment", "harmful", "malicious",
        "agent", "tool use", "memory", "reward hacking",
    ]

    # Keywords that indicate an implementable attack
    ATTACK_TECHNIQUE_PATTERNS = [
        r"we propose (\w+(?:\s+\w+){0,3}) attack",
        r"introduce (\w+(?:\s+\w+){0,3}),? a (?:novel |new )?(?:attack|method|technique)",
        r"(\w+(?:\s+\w+){0,2}) jailbreak",
        r"method (?:called|named) (\w+(?:\s+\w+){0,2})",
        r"(\w+) \((\w+)\),? (?:a |an )?(?:new |novel )?attack",
    ]

    ARXIV_API = "https://export.arxiv.org/api/query"

    def __init__(self, max_results: int = 20):
        self.max_results = max_results
        self.tracked_papers: List[Paper] = []

    def _fetch_arxiv(self, query: str, max_results: int = 10) -> List[Paper]:
        """Fetch papers from arXiv API."""
        params = urllib.parse.urlencode({
            "search_query": f"all:{query}",
            "start": 0,
            "max_results": max_results,
            "sortBy": "submittedDate",
            "sortOrder": "descending",
        })
        url = f"{self.ARXIV_API}?{params}"

        try:
            with urllib.request.urlopen(url, timeout=10) as resp:
                xml_data = resp.read().decode("utf-8")
        except Exception as e:
            logger.warning(f"arXiv fetch failed for '{query}': {e}")
            return []

        return self._parse_arxiv_xml(xml_data)

    def _parse_arxiv_xml(self, xml_data: str) -> List[Paper]:
        """Parse arXiv Atom XML response."""
        papers = []
        try:
            ns = {"atom": "http://www.w3.org/2005/Atom"}
            root = ET.fromstring(xml_data)

            for entry in root.findall("atom:entry", ns):
                arxiv_id = entry.find("atom:id", ns)
                title = entry.find("atom:title", ns)
                abstract = entry.find("atom:summary", ns)
                published = entry.find("atom:published", ns)

                authors = [
                    a.find("atom:name", ns).text
                    for a in entry.findall("atom:author", ns)
                    if a.find("atom:name", ns) is not None
                ]

                if all(x is not None for x in [arxiv_id, title, abstract]):
                    paper = Paper(
                        arxiv_id=arxiv_id.text.split("/")[-1],
                        title=title.text.strip().replace("\n", " "),
                        abstract=abstract.text.strip().replace("\n", " "),
                        authors=authors,
                        published=published.text[:10] if published is not None else "",
                        url=arxiv_id.text,
                    )
                    papers.append(paper)
        except Exception as e:
            logger.warning(f"XML parse failed: {e}")

        return papers

    def _score_relevance(self, paper: Paper) -> float:
        """Score paper relevance to AI security attacks."""
        text = (paper.title + " " + paper.abstract).lower()
        score = 0.0

        for keyword in self.HIGH_RELEVANCE_KEYWORDS:
            if keyword in text:
                score += 0.08

        # Bonus for attack-specific terms
        attack_terms = ["jailbreak", "prompt injection", "adversarial attack",
                        "red team", "bypass safety", "safety bypass",
                        "harmful", "attack llm", "llm attack", "jailbreaking"]
        for term in attack_terms:
            if term in text:
                score += 0.15

        # Title match is worth more
        title_lower = paper.title.lower()
        for keyword in self.HIGH_RELEVANCE_KEYWORDS:
            if keyword in title_lower:
                score += 0.1

        return min(1.0, score)

    def _extract_attack_techniques(self, paper: Paper) -> List[str]:
        """Extract named attack techniques from abstract."""
        techniques = []
        text = paper.title + " " + paper.abstract

        for pattern in self.ATTACK_TECHNIQUE_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    techniques.extend([m for m in match if m])
                else:
                    techniques.append(match)

        # Clean and deduplicate
        cleaned = list(set(t.strip().lower() for t in techniques if len(t) > 2))
        return cleaned[:5]

    def search(self, query: str = None, max_results: int = None) -> List[Paper]:
        """Search for relevant papers."""
        queries = [query] if query else self.SEARCH_QUERIES[:3]
        max_r = max_results or self.max_results
        all_papers: Dict[str, Paper] = {}

        for q in queries:
            papers = self._fetch_arxiv(q, max_results=max_r // len(queries))
            for paper in papers:
                if paper.arxiv_id not in all_papers:
                    paper.relevance_score = self._score_relevance(paper)
                    paper.attack_techniques = self._extract_attack_techniques(paper)
                    all_papers[paper.arxiv_id] = paper

        # Sort by relevance
        sorted_papers = sorted(all_papers.values(),
                                key=lambda p: p.relevance_score, reverse=True)
        self.tracked_papers.extend(sorted_papers)
        return sorted_papers

    def get_high_priority(self, min_score: float = 0.5) -> List[Paper]:
        """Get papers with high relevance scores."""
        return [p for p in self.tracked_papers if p.relevance_score >= min_score]

    def get_implementable(self) -> List[Paper]:
        """Get papers that have extractable attack techniques."""
        return [p for p in self.tracked_papers if p.attack_techniques]

    def generate_digest(self) -> Dict[str, Any]:
        """Generate a digest of tracked papers."""
        high_priority = self.get_high_priority()
        implementable = self.get_implementable()

        return {
            "total_tracked": len(self.tracked_papers),
            "high_priority": len(high_priority),
            "implementable": len(implementable),
            "top_papers": [p.to_dict() for p in high_priority[:5]],
            "attack_techniques_found": list(set(
                t for p in implementable for t in p.attack_techniques
            ))[:20],
        }
