"""
Second Brain - NLP Utilities
=============================
Text processing, embedding generation, and semantic similarity functions.
"""

import re
import math
from typing import List, Dict, Tuple, Set, Optional
from dataclasses import dataclass
from collections import Counter

# ============================================================================
# TEXT PREPROCESSING
# ============================================================================

class TextProcessor:
    """Text cleaning and preprocessing utilities"""
    
    # Common academic/research stopwords to filter
    ACADEMIC_STOPWORDS = {
        'research', 'study', 'work', 'project', 'experience', 'interested',
        'opportunity', 'learn', 'develop', 'skills', 'knowledge', 'team',
        'collaborate', 'contribute', 'understand', 'analyze', 'data'
    }
    
    @staticmethod
    def clean_text(text: str) -> str:
        """Basic text cleaning"""
        # Lowercase
        text = text.lower()
        # Remove special characters but keep hyphens in compound words
        text = re.sub(r'[^\w\s\-]', ' ', text)
        # Normalize whitespace
        text = ' '.join(text.split())
        return text
    
    @staticmethod
    def extract_keywords(text: str, min_length: int = 3) -> List[str]:
        """Extract meaningful keywords from text"""
        cleaned = TextProcessor.clean_text(text)
        words = cleaned.split()
        
        # Filter short words and stopwords
        keywords = [
            w for w in words 
            if len(w) >= min_length 
            and w not in TextProcessor.ACADEMIC_STOPWORDS
        ]
        return keywords
    
    @staticmethod
    def extract_ngrams(text: str, n: int = 2) -> List[str]:
        """Extract n-grams from text"""
        words = TextProcessor.clean_text(text).split()
        if len(words) < n:
            return []
        return [' '.join(words[i:i+n]) for i in range(len(words) - n + 1)]
    
    @staticmethod
    def calculate_keyword_density(text: str, keywords: List[str]) -> Dict[str, float]:
        """Calculate density of specific keywords in text"""
        cleaned = TextProcessor.clean_text(text)
        word_count = len(cleaned.split())
        if word_count == 0:
            return {}
        
        densities = {}
        for kw in keywords:
            count = cleaned.count(kw.lower())
            densities[kw] = count / word_count
        return densities

# ============================================================================
# SIMPLE EMBEDDING SYSTEM (No external dependencies)
# ============================================================================

class SimpleEmbedding:
    """
    Lightweight embedding system using TF-IDF vectors.
    In production, replace with sentence-transformers or OpenAI embeddings.
    """
    
    def __init__(self, vocabulary: Optional[Set[str]] = None):
        self.vocabulary = vocabulary or set()
        self.idf_scores: Dict[str, float] = {}
        self.documents: List[str] = []
    
    def fit(self, documents: List[str]):
        """Build vocabulary and IDF scores from corpus"""
        self.documents = documents
        
        # Build vocabulary
        for doc in documents:
            words = TextProcessor.extract_keywords(doc)
            self.vocabulary.update(words)
        
        # Calculate IDF scores
        num_docs = len(documents)
        doc_freq = Counter()
        
        for doc in documents:
            words = set(TextProcessor.extract_keywords(doc))
            for word in words:
                doc_freq[word] += 1
        
        for word, freq in doc_freq.items():
            self.idf_scores[word] = math.log(num_docs / (1 + freq))
    
    def embed(self, text: str) -> Dict[str, float]:
        """Generate TF-IDF vector for text"""
        words = TextProcessor.extract_keywords(text)
        word_counts = Counter(words)
        total_words = len(words) if words else 1
        
        vector = {}
        for word in self.vocabulary:
            tf = word_counts.get(word, 0) / total_words
            idf = self.idf_scores.get(word, 0)
            vector[word] = tf * idf
        
        return vector
    
    def cosine_similarity(self, vec1: Dict[str, float], vec2: Dict[str, float]) -> float:
        """Calculate cosine similarity between two vectors"""
        # Get all keys
        all_keys = set(vec1.keys()) | set(vec2.keys())
        
        dot_product = sum(vec1.get(k, 0) * vec2.get(k, 0) for k in all_keys)
        norm1 = math.sqrt(sum(v ** 2 for v in vec1.values()))
        norm2 = math.sqrt(sum(v ** 2 for v in vec2.values()))
        
        if norm1 == 0 or norm2 == 0:
            return 0.0
        
        return dot_product / (norm1 * norm2)
    
    def similarity(self, text1: str, text2: str) -> float:
        """Calculate semantic similarity between two texts"""
        vec1 = self.embed(text1)
        vec2 = self.embed(text2)
        return self.cosine_similarity(vec1, vec2)

# ============================================================================
# SKILL EXTRACTION AND MATCHING
# ============================================================================

class SkillExtractor:
    """Extract and match skills from text"""
    
    # Comprehensive skill taxonomy for research
    SKILL_TAXONOMY = {
        'programming': {
            'python': ['python', 'py', 'pandas', 'numpy', 'scipy', 'pytorch', 'tensorflow'],
            'r': ['r programming', 'r studio', 'rstudio', 'tidyverse', 'ggplot'],
            'matlab': ['matlab', 'simulink'],
            'java': ['java', 'jvm', 'spring'],
            'cpp': ['c++', 'cpp', 'c programming'],
            'sql': ['sql', 'mysql', 'postgresql', 'sqlite', 'database'],
            'javascript': ['javascript', 'js', 'node', 'react', 'typescript'],
        },
        'data_science': {
            'machine_learning': ['machine learning', 'ml', 'deep learning', 'neural network', 'ai'],
            'statistics': ['statistics', 'statistical analysis', 'regression', 'hypothesis testing'],
            'data_analysis': ['data analysis', 'data analytics', 'exploratory analysis'],
            'visualization': ['visualization', 'tableau', 'matplotlib', 'seaborn', 'plotting'],
        },
        'lab_techniques': {
            'pcr': ['pcr', 'qpcr', 'rt-pcr', 'polymerase chain reaction'],
            'gel_electrophoresis': ['gel electrophoresis', 'western blot', 'southern blot'],
            'cell_culture': ['cell culture', 'tissue culture', 'mammalian cells'],
            'microscopy': ['microscopy', 'confocal', 'fluorescence', 'imaging'],
            'spectroscopy': ['spectroscopy', 'nmr', 'mass spec', 'chromatography', 'hplc'],
        },
        'research_methods': {
            'literature_review': ['literature review', 'systematic review', 'meta-analysis'],
            'experimental_design': ['experimental design', 'study design', 'methodology'],
            'qualitative': ['qualitative', 'interviews', 'ethnography', 'focus groups'],
            'quantitative': ['quantitative', 'survey', 'questionnaire'],
        },
        'soft_skills': {
            'communication': ['communication', 'presentation', 'writing', 'public speaking'],
            'teamwork': ['teamwork', 'collaboration', 'team player'],
            'leadership': ['leadership', 'mentoring', 'supervising'],
            'problem_solving': ['problem solving', 'critical thinking', 'analytical'],
        }
    }
    
    @classmethod
    def extract_skills(cls, text: str) -> Dict[str, List[str]]:
        """Extract skills from text organized by category"""
        text_lower = text.lower()
        found_skills = {}
        
        for category, skills in cls.SKILL_TAXONOMY.items():
            found_skills[category] = []
            for skill_name, keywords in skills.items():
                if any(kw in text_lower for kw in keywords):
                    found_skills[category].append(skill_name)
        
        # Remove empty categories
        return {k: v for k, v in found_skills.items() if v}
    
    @classmethod
    def flatten_skills(cls, text: str) -> List[str]:
        """Get flat list of all skills found"""
        skills_by_category = cls.extract_skills(text)
        return [skill for skills in skills_by_category.values() for skill in skills]
    
    @classmethod
    def calculate_skill_match(
        cls, 
        candidate_skills: List[str], 
        required_skills: List[str],
        preferred_skills: List[str]
    ) -> Tuple[float, List[str], List[str]]:
        """
        Calculate skill match score.
        Returns: (score, matched_skills, missing_required)
        """
        candidate_set = set(s.lower() for s in candidate_skills)
        required_set = set(s.lower() for s in required_skills)
        preferred_set = set(s.lower() for s in preferred_skills)
        
        # Check required skills
        matched_required = candidate_set & required_set
        missing_required = required_set - candidate_set
        
        # Check preferred skills
        matched_preferred = candidate_set & preferred_set
        
        # Calculate score (required skills weighted more heavily)
        if required_set:
            required_score = len(matched_required) / len(required_set) * 60
        else:
            required_score = 60  # No requirements = full points
            
        if preferred_set:
            preferred_score = len(matched_preferred) / len(preferred_set) * 40
        else:
            preferred_score = 20  # Partial credit if no preferences specified
        
        total_score = required_score + preferred_score
        matched = list(matched_required | matched_preferred)
        
        return total_score, matched, list(missing_required)

# ============================================================================
# GAMING DETECTION
# ============================================================================

class GamingDetector:
    """Detect attempts to game the matching algorithm"""
    
    # Thresholds for flagging
    KEYWORD_DENSITY_THRESHOLD = 0.15  # Flag if >15% of words are keywords
    SIMILARITY_THRESHOLD = 0.85  # Flag if essay is >85% similar to lab website
    NATURALNESS_MIN = 0.3  # Flag if text naturalness score < 30%
    
    @staticmethod
    def check_keyword_stuffing(text: str, target_keywords: List[str]) -> Tuple[bool, float, str]:
        """
        Check if text has suspicious keyword density.
        Returns: (is_suspicious, density, explanation)
        """
        densities = TextProcessor.calculate_keyword_density(text, target_keywords)
        
        if not densities:
            return False, 0.0, "No keywords found"
        
        avg_density = sum(densities.values()) / len(densities)
        max_density = max(densities.values())
        
        # Check for suspicious patterns
        if max_density > GamingDetector.KEYWORD_DENSITY_THRESHOLD:
            suspicious_kw = max(densities.items(), key=lambda x: x[1])
            return True, max_density, f"Excessive use of '{suspicious_kw[0]}' ({suspicious_kw[1]:.1%})"
        
        # Check for unnaturally even distribution (copy-paste behavior)
        if len(set(round(d, 2) for d in densities.values())) == 1 and len(densities) > 3:
            return True, avg_density, "Suspiciously uniform keyword distribution"
        
        return False, avg_density, "Normal keyword usage"
    
    @staticmethod
    def check_essay_originality(
        essay: str, 
        lab_website: str, 
        embedding_system: SimpleEmbedding
    ) -> Tuple[bool, float, str]:
        """
        Check if essay is too similar to lab website (indicates copying).
        Returns: (is_suspicious, similarity, explanation)
        """
        similarity = embedding_system.similarity(essay, lab_website)
        
        if similarity > GamingDetector.SIMILARITY_THRESHOLD:
            return True, similarity, f"Essay is {similarity:.0%} similar to lab website content"
        elif similarity > 0.7:
            return False, similarity, "Essay shows familiarity with lab (positive signal)"
        else:
            return False, similarity, "Essay appears original"
    
    @staticmethod
    def check_text_naturalness(text: str) -> Tuple[float, str]:
        """
        Estimate how natural/human the text reads.
        Returns: (naturalness_score, explanation)
        """
        words = text.split()
        if len(words) < 20:
            return 0.5, "Text too short to evaluate"
        
        # Check for variety in sentence length
        sentences = re.split(r'[.!?]+', text)
        sentences = [s.strip() for s in sentences if s.strip()]
        
        if not sentences:
            return 0.3, "No complete sentences found"
        
        sentence_lengths = [len(s.split()) for s in sentences]
        avg_length = sum(sentence_lengths) / len(sentence_lengths)
        variance = sum((l - avg_length) ** 2 for l in sentence_lengths) / len(sentence_lengths)
        
        # Natural text has varied sentence lengths
        # Stuffed text often has very uniform or very erratic patterns
        naturalness = min(1.0, variance / 50)  # Normalize
        
        # Check for repeated phrases (copy-paste indicator)
        bigrams = TextProcessor.extract_ngrams(text, 2)
        bigram_counts = Counter(bigrams)
        repeated_bigrams = sum(1 for _, count in bigram_counts.items() if count > 2)
        
        if repeated_bigrams > len(bigrams) * 0.1:
            naturalness *= 0.7
            return naturalness, f"High repetition detected ({repeated_bigrams} repeated phrases)"
        
        if naturalness < GamingDetector.NATURALNESS_MIN:
            return naturalness, "Text structure appears unnatural"
        
        return naturalness, "Text appears natural"
    
    @classmethod
    def full_gaming_check(
        cls,
        candidate_essay: str,
        lab_keywords: List[str],
        lab_website: str,
        embedding_system: SimpleEmbedding
    ) -> Dict[str, any]:
        """
        Run all gaming detection checks.
        Returns comprehensive report.
        """
        report = {
            'is_flagged': False,
            'flags': [],
            'scores': {},
            'recommendation': 'proceed'
        }
        
        # Check keyword stuffing
        kw_suspicious, kw_density, kw_explanation = cls.check_keyword_stuffing(
            candidate_essay, lab_keywords
        )
        report['scores']['keyword_density'] = kw_density
        if kw_suspicious:
            report['flags'].append(f"KEYWORD STUFFING: {kw_explanation}")
        
        # Check essay originality
        orig_suspicious, orig_sim, orig_explanation = cls.check_essay_originality(
            candidate_essay, lab_website, embedding_system
        )
        report['scores']['website_similarity'] = orig_sim
        if orig_suspicious:
            report['flags'].append(f"LOW ORIGINALITY: {orig_explanation}")
        
        # Check naturalness
        nat_score, nat_explanation = cls.check_text_naturalness(candidate_essay)
        report['scores']['naturalness'] = nat_score
        if nat_score < cls.NATURALNESS_MIN:
            report['flags'].append(f"UNNATURAL TEXT: {nat_explanation}")
        
        # Determine overall flag status
        if len(report['flags']) >= 2:
            report['is_flagged'] = True
            report['recommendation'] = 'manual_review'
        elif len(report['flags']) == 1:
            report['recommendation'] = 'flag_for_review'
        
        return report

# ============================================================================
# AFFIRMATIVE FILTERING UTILITIES
# ============================================================================

class AffirmativeFilter:
    """
    Implements affirmative (positive) filtering instead of negative elimination.
    Scores what candidates HAVE rather than penalizing for what they LACK.
    """
    
    @staticmethod
    def score_present_skills(
        candidate_skills: List[str],
        desired_skills: List[str],
        weights: Optional[Dict[str, float]] = None
    ) -> Tuple[float, Dict[str, float]]:
        """
        Score based on skills present, not missing.
        Returns: (total_score, skill_contributions)
        """
        if not desired_skills:
            return 100.0, {}
        
        weights = weights or {skill: 1.0 for skill in desired_skills}
        total_weight = sum(weights.values())
        
        contributions = {}
        score = 0.0
        
        for skill in desired_skills:
            skill_lower = skill.lower()
            weight = weights.get(skill, 1.0)
            
            if skill_lower in [s.lower() for s in candidate_skills]:
                skill_score = (weight / total_weight) * 100
                contributions[skill] = skill_score
                score += skill_score
            else:
                contributions[skill] = 0.0
        
        return score, contributions
    
    @staticmethod
    def calculate_trainability_bonus(
        candidate_gpa: float,
        gpa_trajectory: float,
        research_experience_months: float,
        has_relevant_coursework: bool
    ) -> float:
        """
        Calculate bonus points for trainable candidates.
        Rewards potential, not just current state.
        """
        bonus = 0.0
        
        # Strong academic foundation suggests trainability
        if candidate_gpa >= 3.5:
            bonus += 10
        elif candidate_gpa >= 3.2:
            bonus += 5
        
        # Improving trajectory is a positive signal
        if gpa_trajectory > 0.2:
            bonus += 8
        elif gpa_trajectory > 0.1:
            bonus += 4
        
        # Some research experience (any) shows commitment
        if 0 < research_experience_months <= 6:
            bonus += 5  # New to research but engaged
        elif research_experience_months > 6:
            bonus += 3  # Has experience (less "trainability" bonus needed)
        
        # Relevant coursework shows foundational knowledge
        if has_relevant_coursework:
            bonus += 5
        
        return min(bonus, 25)  # Cap at 25 bonus points
