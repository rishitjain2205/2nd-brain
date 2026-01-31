"""
Second Brain - Data Models and Configuration
==============================================
Core data structures for the research lab matching system.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
from enum import Enum
from datetime import datetime

# ============================================================================
# ENUMS AND CONSTANTS
# ============================================================================

class ExperienceLevel(Enum):
    FRESHMAN = 1
    SOPHOMORE = 2
    JUNIOR = 3
    SENIOR = 4
    GRAD_STUDENT = 5

class MatchTier(Enum):
    STRONG_MATCH = "strong"      # 80-100% fit
    GOOD_MATCH = "good"          # 60-79% fit
    POTENTIAL_MATCH = "potential" # 40-59% fit - trainable
    STRETCH_MATCH = "stretch"    # 30-39% fit - growth opportunity
    WEAK_MATCH = "weak"          # <30% fit

class MentorshipStyle(Enum):
    HANDS_ON = "hands_on"        # Close guidance, frequent check-ins
    COLLABORATIVE = "collaborative"  # Regular meetings, joint work
    INDEPENDENT = "independent"  # Minimal oversight, self-directed

class ResearchOrientation(Enum):
    THEORETICAL = "theoretical"
    APPLIED = "applied"
    MIXED = "mixed"

# ============================================================================
# CANDIDATE DATA MODELS
# ============================================================================

@dataclass
class Course:
    """Individual course from transcript"""
    name: str
    code: str
    grade: str
    credits: float
    semester: str  # e.g., "Fall 2024"
    is_graduate_level: bool = False
    is_honors: bool = False
    
    @property
    def grade_points(self) -> float:
        """Convert letter grade to points"""
        grade_map = {
            'A+': 4.0, 'A': 4.0, 'A-': 3.7,
            'B+': 3.3, 'B': 3.0, 'B-': 2.7,
            'C+': 2.3, 'C': 2.0, 'C-': 1.7,
            'D+': 1.3, 'D': 1.0, 'D-': 0.7,
            'F': 0.0, 'P': None, 'NP': None
        }
        return grade_map.get(self.grade.upper(), 0.0)

@dataclass
class ResearchExperience:
    """Past research experience entry"""
    lab_name: str
    institution: str
    pi_name: str
    role: str
    description: str
    start_date: datetime
    end_date: Optional[datetime]
    hours_per_week: float
    skills_used: List[str]
    outputs: List[str]  # publications, posters, presentations
    
    @property
    def duration_months(self) -> float:
        end = self.end_date or datetime.now()
        return (end - self.start_date).days / 30

@dataclass
class Transcript:
    """Full transcript data"""
    courses: List[Course]
    cumulative_gpa: float
    major_gpa: Optional[float]
    institution: str
    institution_tier: int = 1  # 1-5, for normalization
    
    def get_relevant_courses(self, keywords: List[str]) -> List[Course]:
        """Find courses matching research area keywords"""
        relevant = []
        for course in self.courses:
            name_lower = course.name.lower()
            if any(kw.lower() in name_lower for kw in keywords):
                relevant.append(course)
        return relevant
    
    def calculate_trajectory(self) -> float:
        """Calculate GPA trajectory (positive = improving)"""
        if len(self.courses) < 4:
            return 0.0
        
        # Split courses by time, compare first half to second half
        sorted_courses = sorted(self.courses, key=lambda c: c.semester)
        mid = len(sorted_courses) // 2
        
        first_half = [c for c in sorted_courses[:mid] if c.grade_points is not None]
        second_half = [c for c in sorted_courses[mid:] if c.grade_points is not None]
        
        if not first_half or not second_half:
            return 0.0
            
        first_avg = sum(c.grade_points for c in first_half) / len(first_half)
        second_avg = sum(c.grade_points for c in second_half) / len(second_half)
        
        return second_avg - first_avg

@dataclass
class Candidate:
    """Complete candidate profile"""
    id: str
    name: str
    email: str
    
    # Core materials
    resume_text: str
    transcript: Transcript
    personal_essay: str
    why_lab_essays: Dict[str, str]  # lab_id -> essay text
    
    # Extracted/Computed
    skills: List[str] = field(default_factory=list)
    research_experiences: List[ResearchExperience] = field(default_factory=list)
    
    # Demographics (optional, for bias auditing only)
    is_first_gen: Optional[bool] = None
    is_transfer: Optional[bool] = None
    is_underrepresented: Optional[bool] = None
    
    # Preferences (for candidate-side matching)
    preferred_mentorship: Optional[MentorshipStyle] = None
    preferred_orientation: Optional[ResearchOrientation] = None
    hours_available: float = 10.0
    career_goals: List[str] = field(default_factory=list)
    
    # Metadata
    year: ExperienceLevel = ExperienceLevel.SOPHOMORE
    graduation_date: Optional[datetime] = None
    
    @property
    def total_research_months(self) -> float:
        return sum(exp.duration_months for exp in self.research_experiences)
    
    @property
    def has_publications(self) -> bool:
        for exp in self.research_experiences:
            if any('pub' in o.lower() or 'paper' in o.lower() for o in exp.outputs):
                return True
        return False

# ============================================================================
# LAB DATA MODELS
# ============================================================================

@dataclass 
class LabRequirement:
    """A single requirement with priority level"""
    description: str
    keywords: List[str]
    is_required: bool = False  # True = must-have, False = nice-to-have
    weight: float = 1.0

@dataclass
class Lab:
    """Research lab profile"""
    id: str
    name: str
    pi_name: str
    pi_email: str
    department: str
    institution: str
    
    # Research description
    description: str
    research_areas: List[str]
    current_projects: List[str]
    recent_publications: List[str]
    website_text: str  # For detecting essay copying
    
    # Requirements
    requirements: List[LabRequirement] = field(default_factory=list)
    required_skills: List[str] = field(default_factory=list)
    preferred_skills: List[str] = field(default_factory=list)
    
    # Team and culture
    current_team_size: int = 5
    team_skills: List[str] = field(default_factory=list)  # For complementary matching
    mentorship_style: MentorshipStyle = MentorshipStyle.COLLABORATIVE
    research_orientation: ResearchOrientation = ResearchOrientation.MIXED
    
    # Capacity
    positions_available: int = 1
    min_hours_per_week: float = 10.0
    min_commitment_months: int = 6
    
    # Preferences
    preferred_year_min: ExperienceLevel = ExperienceLevel.FRESHMAN
    preferred_year_max: ExperienceLevel = ExperienceLevel.SENIOR
    accepts_training: bool = True  # Will train students without prior experience
    
    # Success profiles (for learning from past matches)
    successful_ra_profiles: List[str] = field(default_factory=list)

# ============================================================================
# MATCHING RESULT MODELS
# ============================================================================

@dataclass
class ScoreComponent:
    """Individual scoring component with explanation"""
    name: str
    score: float  # 0-100
    weight: float
    explanation: str
    flags: List[str] = field(default_factory=list)  # Warnings or highlights

@dataclass
class MatchResult:
    """Complete match result with explainability"""
    candidate_id: str
    lab_id: str
    
    # Overall scores
    total_score: float
    tier: MatchTier
    
    # Component breakdown
    components: List[ScoreComponent]
    
    # Explainability
    strengths: List[str]
    gaps: List[str]
    suggested_questions: List[str]  # For interviews
    
    # Flags
    red_flags: List[str] = field(default_factory=list)
    gaming_flags: List[str] = field(default_factory=list)
    
    # For candidate view
    what_you_would_gain: List[str] = field(default_factory=list)
    what_to_emphasize: List[str] = field(default_factory=list)
    
    @property
    def is_flagged_for_gaming(self) -> bool:
        return len(self.gaming_flags) > 0

@dataclass
class LabRanking:
    """Ranked list of candidates for a lab (professor view)"""
    lab_id: str
    ranked_candidates: List[MatchResult]
    total_applicants: int
    
    def get_tier(self, tier: MatchTier) -> List[MatchResult]:
        return [m for m in self.ranked_candidates if m.tier == tier]

@dataclass
class CandidateRecommendations:
    """Lab recommendations for a candidate (student view)"""
    candidate_id: str
    recommended_labs: List[MatchResult]
    stretch_matches: List[MatchResult]  # Lower fit but growth potential
    
    def get_top_n(self, n: int = 5) -> List[MatchResult]:
        return sorted(self.recommended_labs, key=lambda m: m.total_score, reverse=True)[:n]
