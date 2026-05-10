"""Research Database - Track Papers and Implementation Status.

Persistent storage for tracked papers, implementation status,
and attack technique mappings using SQLite.
"""

from typing import List, Dict, Any, Optional
import sqlite3
import json
import logging
import os

logger = logging.getLogger(__name__)


class ResearchDatabase:
    """SQLite-backed database for research paper tracking.
    
    Tracks:
    - Papers (metadata, relevance, techniques)
    - Implementation status per paper
    - Attack technique → paper mappings
    - Implementation notes and code references
    """

    def __init__(self, db_path: str = "research.db"):
        self.db_path = db_path
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Initialize database schema."""
        with self._get_conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS papers (
                    arxiv_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    abstract TEXT,
                    authors TEXT,
                    published TEXT,
                    url TEXT,
                    relevance_score REAL DEFAULT 0.0,
                    attack_techniques TEXT,
                    implementation_status TEXT DEFAULT 'unreviewed',
                    notes TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS implementations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    arxiv_id TEXT REFERENCES papers(arxiv_id),
                    attack_name TEXT NOT NULL,
                    file_path TEXT,
                    status TEXT DEFAULT 'planned',
                    quality_score REAL DEFAULT 0.0,
                    notes TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS techniques (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    category TEXT,
                    description TEXT,
                    arxiv_ids TEXT,
                    implemented BOOLEAN DEFAULT 0,
                    chimera_attack_name TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_papers_relevance
                    ON papers(relevance_score DESC);
                CREATE INDEX IF NOT EXISTS idx_papers_status
                    ON papers(implementation_status);
            """)
        logger.info(f"Research database initialized: {self.db_path}")

    def add_paper(self, paper_dict: Dict[str, Any]) -> bool:
        """Add or update a paper in the database."""
        try:
            with self._get_conn() as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO papers
                    (arxiv_id, title, abstract, authors, published, url,
                     relevance_score, attack_techniques, implementation_status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    paper_dict.get("arxiv_id"),
                    paper_dict.get("title"),
                    paper_dict.get("abstract"),
                    json.dumps(paper_dict.get("authors", [])),
                    paper_dict.get("published"),
                    paper_dict.get("url"),
                    paper_dict.get("relevance_score", 0.0),
                    json.dumps(paper_dict.get("attack_techniques", [])),
                    paper_dict.get("implementation_status", "unreviewed"),
                ))
            return True
        except Exception as e:
            logger.error(f"Failed to add paper: {e}")
            return False

    def add_papers_bulk(self, papers: List[Dict[str, Any]]) -> int:
        """Add multiple papers, return count added."""
        count = 0
        for paper in papers:
            if self.add_paper(paper):
                count += 1
        return count

    def get_paper(self, arxiv_id: str) -> Optional[Dict[str, Any]]:
        """Get a paper by arXiv ID."""
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM papers WHERE arxiv_id = ?", (arxiv_id,)
            ).fetchone()
            if row:
                d = dict(row)
                d["authors"] = json.loads(d.get("authors") or "[]")
                d["attack_techniques"] = json.loads(d.get("attack_techniques") or "[]")
                return d
        return None

    def get_high_priority(self, min_score: float = 0.5,
                           limit: int = 20) -> List[Dict[str, Any]]:
        """Get high-priority papers sorted by relevance."""
        with self._get_conn() as conn:
            rows = conn.execute("""
                SELECT * FROM papers
                WHERE relevance_score >= ?
                ORDER BY relevance_score DESC
                LIMIT ?
            """, (min_score, limit)).fetchall()
            return [dict(r) for r in rows]

    def update_status(self, arxiv_id: str, status: str,
                       notes: str = None) -> bool:
        """Update implementation status of a paper."""
        try:
            with self._get_conn() as conn:
                conn.execute("""
                    UPDATE papers
                    SET implementation_status = ?, notes = ?
                    WHERE arxiv_id = ?
                """, (status, notes, arxiv_id))
            return True
        except Exception as e:
            logger.error(f"Status update failed: {e}")
            return False

    def add_implementation(self, arxiv_id: str, attack_name: str,
                            file_path: str, status: str = "complete",
                            quality_score: float = 1.0) -> bool:
        """Record an attack implementation linked to a paper."""
        try:
            with self._get_conn() as conn:
                conn.execute("""
                    INSERT INTO implementations
                    (arxiv_id, attack_name, file_path, status, quality_score)
                    VALUES (?, ?, ?, ?, ?)
                """, (arxiv_id, attack_name, file_path, status, quality_score))
                conn.execute("""
                    UPDATE papers SET implementation_status = 'implemented'
                    WHERE arxiv_id = ?
                """, (arxiv_id,))
            return True
        except Exception as e:
            logger.error(f"Implementation record failed: {e}")
            return False

    def get_stats(self) -> Dict[str, Any]:
        """Get database statistics."""
        with self._get_conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM papers").fetchone()[0]
            implemented = conn.execute(
                "SELECT COUNT(*) FROM papers WHERE implementation_status = 'implemented'"
            ).fetchone()[0]
            high_priority = conn.execute(
                "SELECT COUNT(*) FROM papers WHERE relevance_score >= 0.5"
            ).fetchone()[0]
            impl_count = conn.execute("SELECT COUNT(*) FROM implementations").fetchone()[0]

        return {
            "total_papers": total,
            "implemented": implemented,
            "high_priority": high_priority,
            "total_implementations": impl_count,
            "implementation_rate": implemented / max(total, 1),
        }

    def seed_with_known_papers(self) -> int:
        """Seed database with known important AI security papers."""
        known_papers = [
            {
                "arxiv_id": "2310.08419",
                "title": "Jailbreaking Black Box Large Language Models in Twenty Queries",
                "abstract": "PAIR: Prompt Automatic Iterative Refinement for automated jailbreaking.",
                "authors": ["Patrick Chao", "Alexander Robey"],
                "published": "2023-10-12",
                "url": "https://arxiv.org/abs/2310.08419",
                "relevance_score": 0.95,
                "attack_techniques": ["PAIR", "iterative refinement"],
                "implementation_status": "implemented",
            },
            {
                "arxiv_id": "2312.02119",
                "title": "Tree of Attacks with Pruning: Jailbreaking Black-Box LLMs",
                "abstract": "TAP: automated jailbreak using tree search with pruning.",
                "authors": ["Anay Mehrotra"],
                "published": "2023-12-04",
                "url": "https://arxiv.org/abs/2312.02119",
                "relevance_score": 0.95,
                "attack_techniques": ["TAP", "tree search", "pruning"],
                "implementation_status": "implemented",
            },
            {
                "arxiv_id": "2402.16717",
                "title": "CodeChameleon: Personalized Encryption Framework for Jailbreaking LLMs",
                "abstract": "Code-based obfuscation to bypass safety filters.",
                "authors": ["Huijie Lv"],
                "published": "2024-02-26",
                "url": "https://arxiv.org/abs/2402.16717",
                "relevance_score": 0.90,
                "attack_techniques": ["CodeChameleon", "code obfuscation"],
                "implementation_status": "implemented",
            },
            {
                "arxiv_id": "2302.12173",
                "title": "Not What You've Signed Up For: Indirect Prompt Injections",
                "abstract": "Indirect prompt injection attacks on LLM-integrated applications.",
                "authors": ["Kai Greshake"],
                "published": "2023-02-23",
                "url": "https://arxiv.org/abs/2302.12173",
                "relevance_score": 0.92,
                "attack_techniques": ["indirect injection", "RAG poisoning"],
                "implementation_status": "implemented",
            },
            {
                "arxiv_id": "2406.14598",
                "title": "ArtPrompt: ASCII Art-based Jailbreak Attacks",
                "abstract": "Using ASCII art to bypass text-based safety filters in LLMs.",
                "authors": ["Fengqing Jiang"],
                "published": "2024-06-20",
                "url": "https://arxiv.org/abs/2406.14598",
                "relevance_score": 0.88,
                "attack_techniques": ["ArtPrompt", "ASCII art", "visual obfuscation"],
                "implementation_status": "implemented",
            },
        ]
        return self.add_papers_bulk(known_papers)
