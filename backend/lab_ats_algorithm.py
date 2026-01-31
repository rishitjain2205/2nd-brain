"""
Second Brain - Lab-Side ATS Algorithm (Algorithm 1)
=====================================================
Ranks and scores candidates for professors reviewing applications.

Key Design Principles:
1. AFFIRMATIVE FILTERING: Score what candidates HAVE, don't penalize for gaps
2. EXPLAINABILITY: Every score component has clear rationale
3. GAMING DETECTION: Flag suspicious patterns without auto-rejection
4. TRAINABILITY: Reward potential, not just current state
5. BIAS AWARENESS: Flag for audit, normalize across institutions
"""

from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass, field
from models import (
    Candidate, Lab, MatchResult, LabRanking, ScoreComponent,
    MatchTier, ExperienceLevel
)
from nlp_utils import (
    TextProcessor, SimpleEmbedding, SkillExtractor,
    GamingDetector, AffirmativeFilter
)

# ============================================================================
# SCORING WEIGHTS CONFIGURATION
# ============================================================================

@dataclass
class ScoringWeights:
    """Configurable weights for each scoring component"""
    
    # Core components (must sum to ~100)
    technical_fit: float = 30.0
    academic_foundation: float = 20.0
    motivation_fit: float = 30.0
    experience_depth: float = 15.0
    practical_fit: float = 5.0
    
    # Bonuses (added on top)
    trainability_bonus_max: float = 15.0
    complementary_skills_bonus: float = 10.0
    
    # Penalties (rare, only for serious issues)
    gaming_penalty: float = -20.0
    
    def validate(self) -> bool:
        """Ensure weights are reasonable"""
        core_sum = (
            self.technical_fit + self.academic_foundation + 
            self.motivation_fit + self.experience_depth + self.practical_fit
        )
        return 95 <= core_sum <= 105  # Allow small variance

DEFAULT_WEIGHTS = ScoringWeights()

# ============================================================================
# SCORING COMPONENTS
# ============================================================================

class TechnicalFitScorer:
    """Score technical/skill alignment between candidate and lab"""
    
    def __init__(self, embedding_system: SimpleEmbedding):
        self.embedding = embedding_system
    
    def score(self, candidate: Candidate, lab: Lab) -> ScoreComponent:
        """
        Calculate technical fit score using AFFIRMATIVE approach.
        """
        flags = []
        explanations = []
        
        # 1. Direct skill matching (40% of technical)
        candidate_skills = SkillExtractor.flatten_skills(candidate.resume_text)
        skill_score, matched, missing_required = SkillExtractor.calculate_skill_match(
            candidate_skills, lab.required_skills, lab.preferred_skills
        )
        
        if matched:
            explanations.append(f"Matched skills: {', '.join(matched[:5])}")
        if missing_required and len(missing_required) <= 2:
            flags.append(f"Missing {len(missing_required)} required skill(s) - may be trainable")
        
        # 2. Semantic similarity between resume and lab description (30% of technical)
        resume_embedding = self.embedding.embed(candidate.resume_text)
        lab_embedding = self.embedding.embed(lab.description + ' ' + ' '.join(lab.research_areas))
        semantic_sim = self.embedding.cosine_similarity(resume_embedding, lab_embedding)
        semantic_score = semantic_sim * 100
        
        if semantic_sim > 0.6:
            explanations.append(f"Strong research area alignment ({semantic_sim:.0%})")
        
        # 3. Relevant coursework (30% of technical)
        relevant_courses = candidate.transcript.get_relevant_courses(lab.research_areas)
        if relevant_courses:
            course_score = min(100, len(relevant_courses) * 20)  # Cap at 5 courses
            avg_grade = sum(c.grade_points for c in relevant_courses if c.grade_points) / max(len(relevant_courses), 1)
            course_score *= (avg_grade / 4.0)  # Weight by grades
            explanations.append(f"{len(relevant_courses)} relevant courses (avg grade: {avg_grade:.1f})")
        else:
            course_score = 30  # Baseline - don't heavily penalize
            flags.append("No directly relevant courses identified")
        
        # Weighted combination
        final_score = (skill_score * 0.4) + (semantic_score * 0.3) + (course_score * 0.3)
        
        return ScoreComponent(
            name="Technical Fit",
            score=final_score,
            weight=DEFAULT_WEIGHTS.technical_fit,
            explanation="; ".join(explanations) if explanations else "Limited technical overlap",
            flags=flags
        )


class AcademicFoundationScorer:
    """Score academic background with normalization and trajectory"""
    
    # Institution tier adjustments (higher tier = harder grading)
    TIER_ADJUSTMENTS = {1: 0.15, 2: 0.10, 3: 0.05, 4: 0.0, 5: -0.05}
    
    def score(self, candidate: Candidate, lab: Lab) -> ScoreComponent:
        """Calculate academic foundation score with fairness adjustments"""
        flags = []
        explanations = []
        
        # 1. GPA with institution normalization (50% of academic)
        raw_gpa = candidate.transcript.cumulative_gpa
        tier_adj = self.TIER_ADJUSTMENTS.get(candidate.transcript.institution_tier, 0)
        adjusted_gpa = min(4.0, raw_gpa + tier_adj)
        
        gpa_score = (adjusted_gpa / 4.0) * 100
        explanations.append(f"GPA: {raw_gpa:.2f}")
        if tier_adj > 0:
            explanations.append(f"(adjusted for institution rigor: +{tier_adj:.2f})")
        
        # 2. Major GPA if available (20% of academic)
        if candidate.transcript.major_gpa:
            major_score = (candidate.transcript.major_gpa / 4.0) * 100
            explanations.append(f"Major GPA: {candidate.transcript.major_gpa:.2f}")
        else:
            major_score = gpa_score  # Use cumulative if major not available
        
        # 3. Trajectory - reward improvement (30% of academic)
        trajectory = candidate.transcript.calculate_trajectory()
        if trajectory > 0.2:
            trajectory_score = 100
            explanations.append("Strong upward GPA trajectory")
        elif trajectory > 0.1:
            trajectory_score = 85
            explanations.append("Improving academic performance")
        elif trajectory > -0.1:
            trajectory_score = 70
            explanations.append("Stable academic performance")
        else:
            trajectory_score = 50
            flags.append("Declining GPA trajectory - consider discussing")
        
        # 4. Course rigor bonus
        honors_courses = [c for c in candidate.transcript.courses if c.is_honors or c.is_graduate_level]
        if honors_courses:
            rigor_bonus = min(10, len(honors_courses) * 2)
            explanations.append(f"{len(honors_courses)} advanced/honors courses")
        else:
            rigor_bonus = 0
        
        # Weighted combination
        final_score = (gpa_score * 0.5) + (major_score * 0.2) + (trajectory_score * 0.3) + rigor_bonus
        final_score = min(100, final_score)  # Cap at 100
        
        return ScoreComponent(
            name="Academic Foundation",
            score=final_score,
            weight=DEFAULT_WEIGHTS.academic_foundation,
            explanation="; ".join(explanations),
            flags=flags
        )


class MotivationFitScorer:
    """Score essays for genuine motivation and fit"""
    
    def __init__(self, embedding_system: SimpleEmbedding):
        self.embedding = embedding_system
    
    def score(self, candidate: Candidate, lab: Lab) -> ScoreComponent:
        """
        Score motivation with gaming detection.
        Key insight: Score QUALITY of fit articulation, not just keyword presence.
        """
        flags = []
        explanations = []
        
        # Get the why-lab essay for this specific lab
        why_essay = candidate.why_lab_essays.get(lab.id, "")
        personal_essay = candidate.personal_essay
        
        if not why_essay:
            return ScoreComponent(
                name="Motivation & Fit",
                score=30.0,
                weight=DEFAULT_WEIGHTS.motivation_fit,
                explanation="No lab-specific essay provided",
                flags=["Missing 'Why this lab?' essay"]
            )
        
        # 1. Gaming detection FIRST (don't auto-reject, just flag)
        gaming_report = GamingDetector.full_gaming_check(
            why_essay,
            lab.research_areas + lab.required_skills,
            lab.website_text,
            self.embedding
        )
        
        if gaming_report['is_flagged']:
            flags.extend(gaming_report['flags'])
            gaming_penalty = -15  # Reduce score but don't eliminate
        elif gaming_report['recommendation'] == 'flag_for_review':
            flags.extend(gaming_report['flags'])
            gaming_penalty = -5
        else:
            gaming_penalty = 0
        
        # 2. Specificity scoring - does essay reference actual lab work?
        specificity_indicators = [
            lab.pi_name.lower(),
            *[proj.lower()[:20] for proj in lab.current_projects],  # First 20 chars
            *[pub.split()[0].lower() for pub in lab.recent_publications[:3]]  # First word of recent pubs
        ]
        
        essay_lower = why_essay.lower()
        specific_refs = sum(1 for ind in specificity_indicators if ind in essay_lower)
        
        if specific_refs >= 3:
            specificity_score = 100
            explanations.append("Strong specific references to lab's work")
        elif specific_refs >= 1:
            specificity_score = 75
            explanations.append("Some familiarity with lab's research")
        else:
            specificity_score = 40
            flags.append("Essay lacks specific references to lab's work")
        
        # 3. Personal narrative coherence (personal essay)
        if personal_essay:
            # Check if personal essay connects to research interests
            personal_embedding = self.embedding.embed(personal_essay)
            lab_embedding = self.embedding.embed(lab.description)
            narrative_coherence = self.embedding.cosine_similarity(personal_embedding, lab_embedding)
            
            coherence_score = narrative_coherence * 100
            if narrative_coherence > 0.5:
                explanations.append("Personal narrative aligns well with lab focus")
        else:
            coherence_score = 50
        
        # 4. Essay quality metrics
        word_count = len(why_essay.split())
        if 150 <= word_count <= 500:
            length_score = 100
        elif 100 <= word_count < 150 or 500 < word_count <= 700:
            length_score = 80
        else:
            length_score = 50
            flags.append(f"Essay length ({word_count} words) outside ideal range")
        
        naturalness, nat_explanation = GamingDetector.check_text_naturalness(why_essay)
        quality_score = naturalness * 100
        
        # Weighted combination
        final_score = (
            specificity_score * 0.35 +
            coherence_score * 0.25 +
            quality_score * 0.25 +
            length_score * 0.15 +
            gaming_penalty
        )
        final_score = max(0, min(100, final_score))
        
        return ScoreComponent(
            name="Motivation & Fit",
            score=final_score,
            weight=DEFAULT_WEIGHTS.motivation_fit,
            explanation="; ".join(explanations) if explanations else "Standard motivation indicators",
            flags=flags
        )


class ExperienceDepthScorer:
    """Score research and relevant experience"""
    
    def score(self, candidate: Candidate, lab: Lab) -> ScoreComponent:
        """
        Score experience with AFFIRMATIVE approach.
        Key: Reward what exists, provide trainability path for gaps.
        """
        flags = []
        explanations = []
        
        experiences = candidate.research_experiences
        
        if not experiences:
            # No experience is NOT a disqualifier - apply trainability lens
            if lab.accepts_training:
                return ScoreComponent(
                    name="Experience Depth",
                    score=40.0,  # Base score for trainable candidates
                    weight=DEFAULT_WEIGHTS.experience_depth,
                    explanation="No prior research experience - candidate is trainable",
                    flags=["New to research - evaluate coursework and motivation more heavily"]
                )
            else:
                return ScoreComponent(
                    name="Experience Depth",
                    score=20.0,
                    weight=DEFAULT_WEIGHTS.experience_depth,
                    explanation="No prior research experience",
                    flags=["Lab prefers experienced candidates"]
                )
        
        # 1. Duration and depth (40% of experience)
        total_months = candidate.total_research_months
        if total_months >= 18:
            duration_score = 100
            explanations.append(f"Extensive research experience ({total_months:.0f} months)")
        elif total_months >= 12:
            duration_score = 85
            explanations.append(f"Solid research experience ({total_months:.0f} months)")
        elif total_months >= 6:
            duration_score = 70
            explanations.append(f"Some research experience ({total_months:.0f} months)")
        else:
            duration_score = 50
            explanations.append(f"Limited research experience ({total_months:.0f} months)")
        
        # 2. Outputs - publications, presentations (30% of experience)
        all_outputs = []
        for exp in experiences:
            all_outputs.extend(exp.outputs)
        
        if candidate.has_publications:
            output_score = 100
            explanations.append("Has research publications")
        elif any('poster' in o.lower() or 'presentation' in o.lower() for o in all_outputs):
            output_score = 75
            explanations.append("Has presented research")
        elif all_outputs:
            output_score = 60
            explanations.append(f"Has {len(all_outputs)} research outputs")
        else:
            output_score = 40
        
        # 3. Progression signal (30% of experience)
        # Did they advance from basic tasks to more responsibility?
        if len(experiences) >= 2:
            # Multiple experiences suggest commitment
            progression_score = 80
            explanations.append(f"Research experience across {len(experiences)} positions")
        elif experiences and experiences[0].duration_months > 12:
            # Long single experience suggests depth
            progression_score = 85
            explanations.append("Sustained commitment to single research position")
        else:
            progression_score = 60
        
        # Weighted combination
        final_score = (duration_score * 0.4) + (output_score * 0.3) + (progression_score * 0.3)
        
        return ScoreComponent(
            name="Experience Depth",
            score=final_score,
            weight=DEFAULT_WEIGHTS.experience_depth,
            explanation="; ".join(explanations),
            flags=flags
        )


class PracticalFitScorer:
    """Score practical/logistical fit"""
    
    def score(self, candidate: Candidate, lab: Lab) -> ScoreComponent:
        """Check practical alignment - availability, timeline, etc."""
        flags = []
        explanations = []
        score = 100.0  # Start at 100, deduct for mismatches
        
        # 1. Availability
        if candidate.hours_available < lab.min_hours_per_week:
            deduction = min(30, (lab.min_hours_per_week - candidate.hours_available) * 3)
            score -= deduction
            flags.append(f"Available {candidate.hours_available}h/wk vs required {lab.min_hours_per_week}h/wk")
        else:
            explanations.append(f"Availability meets requirements ({candidate.hours_available}h/wk)")
        
        # 2. Year/level appropriateness
        if candidate.year.value < lab.preferred_year_min.value:
            score -= 15
            flags.append("Below preferred experience level")
        elif candidate.year.value > lab.preferred_year_max.value:
            score -= 10
            flags.append("Above preferred experience level (may be overqualified)")
        else:
            explanations.append("Appropriate experience level")
        
        # 3. Timeline (graduation date vs commitment)
        if candidate.graduation_date:
            from datetime import datetime
            months_until_graduation = (candidate.graduation_date - datetime.now()).days / 30
            if months_until_graduation < lab.min_commitment_months:
                score -= 20
                flags.append(f"Graduating soon ({months_until_graduation:.0f} months) vs {lab.min_commitment_months} month commitment")
        
        # 4. Style preferences (if specified)
        if candidate.preferred_mentorship and candidate.preferred_mentorship != lab.mentorship_style:
            score -= 5
            flags.append("Mentorship style preference mismatch")
        
        if candidate.preferred_orientation and candidate.preferred_orientation != lab.research_orientation:
            score -= 5
            flags.append("Research orientation preference mismatch")
        
        final_score = max(0, score)
        
        return ScoreComponent(
            name="Practical Fit",
            score=final_score,
            weight=DEFAULT_WEIGHTS.practical_fit,
            explanation="; ".join(explanations) if explanations else "Practical alignment unclear",
            flags=flags
        )


# ============================================================================
# MAIN ATS ALGORITHM
# ============================================================================

class LabATSAlgorithm:
    """
    Main ATS algorithm for ranking candidates.
    
    Design principles:
    - Affirmative filtering (score presence, not absence)
    - Full explainability
    - Gaming detection without auto-rejection
    - Trainability bonuses for high-potential candidates
    - Complementary skill matching for team building
    """
    
    def __init__(self, weights: ScoringWeights = DEFAULT_WEIGHTS):
        self.weights = weights
        self.embedding = SimpleEmbedding()
        self._trained = False
    
    def train(self, all_documents: List[str]):
        """Train embedding system on corpus of all documents"""
        self.embedding.fit(all_documents)
        self._trained = True
    
    def _ensure_trained(self, candidate: Candidate, lab: Lab):
        """Auto-train on available documents if not trained"""
        if not self._trained:
            docs = [
                candidate.resume_text,
                candidate.personal_essay,
                lab.description,
                lab.website_text,
                ' '.join(lab.research_areas)
            ]
            docs.extend(candidate.why_lab_essays.values())
            self.train([d for d in docs if d])
    
    def score_candidate(self, candidate: Candidate, lab: Lab) -> MatchResult:
        """
        Score a single candidate for a specific lab.
        Returns fully explainable MatchResult.
        """
        self._ensure_trained(candidate, lab)
        
        # Initialize scorers
        technical_scorer = TechnicalFitScorer(self.embedding)
        academic_scorer = AcademicFoundationScorer()
        motivation_scorer = MotivationFitScorer(self.embedding)
        experience_scorer = ExperienceDepthScorer()
        practical_scorer = PracticalFitScorer()
        
        # Calculate all components
        components = [
            technical_scorer.score(candidate, lab),
            academic_scorer.score(candidate, lab),
            motivation_scorer.score(candidate, lab),
            experience_scorer.score(candidate, lab),
            practical_scorer.score(candidate, lab)
        ]
        
        # Calculate weighted total
        weighted_sum = sum(c.score * (c.weight / 100) for c in components)
        
        # Apply trainability bonus for candidates with gaps but high potential
        trainability_bonus = self._calculate_trainability_bonus(candidate, lab, components)
        
        # Apply complementary skills bonus (fills team gaps)
        complementary_bonus = self._calculate_complementary_bonus(candidate, lab)
        
        total_score = weighted_sum + trainability_bonus + complementary_bonus
        total_score = min(100, max(0, total_score))
        
        # Determine tier
        tier = self._determine_tier(total_score, components)
        
        # Compile strengths, gaps, and interview questions
        strengths, gaps = self._extract_strengths_and_gaps(components)
        questions = self._generate_interview_questions(components, gaps)
        
        # Collect flags
        all_flags = []
        gaming_flags = []
        for c in components:
            for flag in c.flags:
                if 'KEYWORD' in flag or 'ORIGINALITY' in flag or 'UNNATURAL' in flag:
                    gaming_flags.append(flag)
                else:
                    all_flags.append(flag)
        
        return MatchResult(
            candidate_id=candidate.id,
            lab_id=lab.id,
            total_score=total_score,
            tier=tier,
            components=components,
            strengths=strengths,
            gaps=gaps,
            suggested_questions=questions,
            red_flags=all_flags,
            gaming_flags=gaming_flags
        )
    
    def _calculate_trainability_bonus(
        self, 
        candidate: Candidate, 
        lab: Lab, 
        components: List[ScoreComponent]
    ) -> float:
        """Calculate bonus for trainable candidates"""
        if not lab.accepts_training:
            return 0.0
        
        # Find if there are skill/experience gaps
        has_gaps = any(
            c.name in ['Technical Fit', 'Experience Depth'] and c.score < 60
            for c in components
        )
        
        if not has_gaps:
            return 0.0  # No bonus needed
        
        # Calculate trainability based on academic strength and trajectory
        has_relevant_courses = bool(candidate.transcript.get_relevant_courses(lab.research_areas))
        
        bonus = AffirmativeFilter.calculate_trainability_bonus(
            candidate.transcript.cumulative_gpa,
            candidate.transcript.calculate_trajectory(),
            candidate.total_research_months,
            has_relevant_courses
        )
        
        return min(bonus, self.weights.trainability_bonus_max)
    
    def _calculate_complementary_bonus(self, candidate: Candidate, lab: Lab) -> float:
        """Bonus for skills that fill gaps in existing team"""
        if not lab.team_skills:
            return 0.0
        
        candidate_skills = set(SkillExtractor.flatten_skills(candidate.resume_text))
        team_skills = set(s.lower() for s in lab.team_skills)
        
        # Skills candidate has that team lacks
        unique_skills = candidate_skills - team_skills
        
        if unique_skills:
            # Cap bonus based on number of unique skills
            return min(len(unique_skills) * 3, self.weights.complementary_skills_bonus)
        
        return 0.0
    
    def _determine_tier(self, total_score: float, components: List[ScoreComponent]) -> MatchTier:
        """Determine match tier based on score and component analysis"""
        # Check for any critical failures
        critical_components = ['Technical Fit', 'Motivation & Fit']
        has_critical_failure = any(
            c.score < 30 for c in components if c.name in critical_components
        )
        
        if has_critical_failure and total_score >= 60:
            # Downgrade if strong overall but critical failure
            total_score = min(total_score, 59)
        
        if total_score >= 80:
            return MatchTier.STRONG_MATCH
        elif total_score >= 60:
            return MatchTier.GOOD_MATCH
        elif total_score >= 40:
            return MatchTier.POTENTIAL_MATCH
        elif total_score >= 30:
            return MatchTier.STRETCH_MATCH
        else:
            return MatchTier.WEAK_MATCH
    
    def _extract_strengths_and_gaps(
        self, 
        components: List[ScoreComponent]
    ) -> Tuple[List[str], List[str]]:
        """Extract key strengths and gaps for summary"""
        strengths = []
        gaps = []
        
        for c in components:
            if c.score >= 75:
                strengths.append(f"{c.name}: {c.explanation}")
            elif c.score < 50:
                gaps.append(f"{c.name}: {c.explanation}")
        
        return strengths[:3], gaps[:3]  # Top 3 each
    
    def _generate_interview_questions(
        self, 
        components: List[ScoreComponent],
        gaps: List[str]
    ) -> List[str]:
        """Generate suggested interview questions based on gaps"""
        questions = []
        
        for c in components:
            if c.score < 60:
                if 'Technical' in c.name:
                    questions.append("Can you walk me through a technical project where you learned a new skill quickly?")
                elif 'Experience' in c.name:
                    questions.append("What draws you to research, and how do you plan to develop your skills?")
                elif 'Motivation' in c.name:
                    questions.append("What specifically about our lab's research excites you most?")
        
        # Add questions for flags
        for c in components:
            for flag in c.flags:
                if 'trajectory' in flag.lower():
                    questions.append("Can you tell me about any challenges you faced academically and how you addressed them?")
                if 'availability' in flag.lower():
                    questions.append("How do you plan to balance your research commitment with other obligations?")
        
        return questions[:5]  # Max 5 questions
    
    def rank_candidates(self, candidates: List[Candidate], lab: Lab) -> LabRanking:
        """
        Rank all candidates for a lab.
        Returns sorted ranking with full explainability.
        """
        results = [self.score_candidate(c, lab) for c in candidates]
        
        # Sort by score descending
        results.sort(key=lambda r: r.total_score, reverse=True)
        
        return LabRanking(
            lab_id=lab.id,
            ranked_candidates=results,
            total_applicants=len(candidates)
        )


# ============================================================================
# BIAS AUDITING
# ============================================================================

class BiasAuditor:
    """
    Audit algorithm outputs for potential bias.
    Does NOT use demographics in scoring - only for post-hoc analysis.
    """
    
    @staticmethod
    def audit_ranking(ranking: LabRanking, candidates: List[Candidate]) -> Dict:
        """
        Audit a ranking for potential disparate impact.
        Returns audit report with recommendations.
        """
        # Build candidate lookup
        candidate_map = {c.id: c for c in candidates}
        
        report = {
            'total_candidates': len(ranking.ranked_candidates),
            'demographic_breakdown': {},
            'tier_analysis': {},
            'potential_issues': [],
            'recommendations': []
        }
        
        # Analyze by demographic groups (if data available)
        groups = {
            'first_gen': {'total': 0, 'strong_match': 0},
            'transfer': {'total': 0, 'strong_match': 0},
            'underrepresented': {'total': 0, 'strong_match': 0}
        }
        
        for result in ranking.ranked_candidates:
            candidate = candidate_map.get(result.candidate_id)
            if not candidate:
                continue
            
            if candidate.is_first_gen:
                groups['first_gen']['total'] += 1
                if result.tier in [MatchTier.STRONG_MATCH, MatchTier.GOOD_MATCH]:
                    groups['first_gen']['strong_match'] += 1
            
            if candidate.is_transfer:
                groups['transfer']['total'] += 1
                if result.tier in [MatchTier.STRONG_MATCH, MatchTier.GOOD_MATCH]:
                    groups['transfer']['strong_match'] += 1
            
            if candidate.is_underrepresented:
                groups['underrepresented']['total'] += 1
                if result.tier in [MatchTier.STRONG_MATCH, MatchTier.GOOD_MATCH]:
                    groups['underrepresented']['strong_match'] += 1
        
        # Calculate pass rates and check for disparate impact
        overall_pass_rate = sum(
            1 for r in ranking.ranked_candidates 
            if r.tier in [MatchTier.STRONG_MATCH, MatchTier.GOOD_MATCH]
        ) / max(len(ranking.ranked_candidates), 1)
        
        for group_name, data in groups.items():
            if data['total'] > 0:
                group_rate = data['strong_match'] / data['total']
                report['demographic_breakdown'][group_name] = {
                    'total': data['total'],
                    'strong_matches': data['strong_match'],
                    'rate': group_rate
                }
                
                # Check for 80% rule (disparate impact)
                if overall_pass_rate > 0 and group_rate / overall_pass_rate < 0.8:
                    report['potential_issues'].append(
                        f"{group_name} candidates have {group_rate/overall_pass_rate:.0%} of the overall pass rate"
                    )
                    report['recommendations'].append(
                        f"Review criteria that may disadvantage {group_name} students"
                    )
        
        return report


# ============================================================================
# USAGE EXAMPLE
# ============================================================================

def example_usage():
    """Demonstrate algorithm usage"""
    
    # This would be populated from your actual data
    from datetime import datetime
    
    # Create sample candidate
    candidate = Candidate(
        id="c001",
        name="Sample Student",
        email="student@university.edu",
        resume_text="Python programming, machine learning, data analysis...",
        transcript=Transcript(
            courses=[
                Course("Machine Learning", "CS229", "A", 4.0, "Fall 2024"),
                Course("Statistics", "STATS101", "A-", 4.0, "Spring 2024"),
            ],
            cumulative_gpa=3.7,
            major_gpa=3.8,
            institution="UCLA",
            institution_tier=1
        ),
        personal_essay="I am passionate about using data science for social good...",
        why_lab_essays={"lab001": "I am excited about Professor Smith's work on..."},
        year=ExperienceLevel.JUNIOR
    )
    
    # Create sample lab
    lab = Lab(
        id="lab001",
        name="Smith Lab",
        pi_name="Dr. Jane Smith",
        pi_email="smith@university.edu",
        department="Computer Science",
        institution="UCLA",
        description="We study machine learning applications in healthcare...",
        research_areas=["machine learning", "healthcare", "neural networks"],
        current_projects=["COVID prediction models", "Medical image analysis"],
        recent_publications=["Smith et al. 2024 - Deep Learning for Diagnosis"],
        website_text="The Smith Lab focuses on...",
        required_skills=["python", "machine_learning"],
        preferred_skills=["pytorch", "statistics"],
        accepts_training=True
    )
    
    # Run algorithm
    algorithm = LabATSAlgorithm()
    result = algorithm.score_candidate(candidate, lab)
    
    print(f"Total Score: {result.total_score:.1f}")
    print(f"Tier: {result.tier.value}")
    print(f"\nStrengths: {result.strengths}")
    print(f"Gaps: {result.gaps}")
    print(f"\nSuggested Questions: {result.suggested_questions}")
    
    if result.gaming_flags:
        print(f"\n⚠️ Gaming Flags: {result.gaming_flags}")


if __name__ == "__main__":
    example_usage()
