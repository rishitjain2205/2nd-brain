"""
Second Brain - Candidate-Side Matching Algorithm (Algorithm 2)
===============================================================
Recommends labs to candidates based on interests, skills, and growth potential.

Key Design Principles:
1. TWO-WAY MATCHING: Consider both what candidate wants AND what labs need
2. GROWTH OPPORTUNITIES: Include "stretch" matches for skill development
3. INFERRED PREFERENCES: Use behavior (coursework, past projects) not just stated preferences
4. EXPLAINABILITY: Tell candidates WHY each lab is recommended
5. SERENDIPITY: Prevent filter bubbles by including adjacent-field matches
"""

from typing import List, Dict, Tuple, Optional, Set
from dataclasses import dataclass, field
from collections import defaultdict
import math

from models import (
    Candidate, Lab, MatchResult, CandidateRecommendations, ScoreComponent,
    MatchTier, ExperienceLevel, MentorshipStyle, ResearchOrientation
)
from nlp_utils import (
    TextProcessor, SimpleEmbedding, SkillExtractor,
    GamingDetector, AffirmativeFilter
)

# ============================================================================
# PREFERENCE INFERENCE ENGINE
# ============================================================================

class PreferenceInferencer:
    """
    Infer candidate preferences from behavior rather than just stated preferences.
    This prevents gaming where candidates say what they think labs want to hear.
    """
    
    def __init__(self, embedding_system: SimpleEmbedding):
        self.embedding = embedding_system
    
    def infer_research_interests(self, candidate: Candidate) -> Dict[str, float]:
        """
        Infer research interests from coursework, essays, and experience.
        Returns weighted interest scores by topic.
        """
        interest_signals = defaultdict(float)
        
        # 1. From coursework (strongest signal - they invested time)
        for course in candidate.transcript.courses:
            keywords = TextProcessor.extract_keywords(course.name)
            grade_weight = (course.grade_points or 3.0) / 4.0 if course.grade_points else 0.75
            
            for kw in keywords:
                interest_signals[kw] += 2.0 * grade_weight
        
        # 2. From research experience (second strongest - they chose to do this)
        for exp in candidate.research_experiences:
            keywords = TextProcessor.extract_keywords(exp.description)
            duration_weight = min(1.0, exp.duration_months / 12)
            
            for kw in keywords:
                interest_signals[kw] += 1.5 * duration_weight
        
        # 3. From personal essay (stated interests, but may be aspirational)
        essay_keywords = TextProcessor.extract_keywords(candidate.personal_essay)
        for kw in essay_keywords:
            interest_signals[kw] += 0.5
        
        # 4. From stated career goals
        for goal in candidate.career_goals:
            goal_keywords = TextProcessor.extract_keywords(goal)
            for kw in goal_keywords:
                interest_signals[kw] += 0.75
        
        # Normalize scores
        if interest_signals:
            max_score = max(interest_signals.values())
            interest_signals = {k: v / max_score for k, v in interest_signals.items()}
        
        return dict(interest_signals)
    
    def infer_mentorship_preference(self, candidate: Candidate) -> MentorshipStyle:
        """Infer preferred mentorship style from behavior patterns."""
        if candidate.preferred_mentorship:
            return candidate.preferred_mentorship
        
        if candidate.research_experiences:
            avg_hours = sum(e.hours_per_week for e in candidate.research_experiences) / len(candidate.research_experiences)
            avg_duration = sum(e.duration_months for e in candidate.research_experiences) / len(candidate.research_experiences)
            
            if avg_hours >= 15 and avg_duration >= 9:
                return MentorshipStyle.INDEPENDENT
            elif avg_hours >= 8:
                return MentorshipStyle.COLLABORATIVE
        
        return MentorshipStyle.HANDS_ON
    
    def infer_research_orientation(self, candidate: Candidate) -> ResearchOrientation:
        """Infer theoretical vs applied preference from coursework and essays."""
        if candidate.preferred_orientation:
            return candidate.preferred_orientation
        
        theoretical_keywords = {'theory', 'theoretical', 'mathematical', 'proof', 'abstract', 'foundational'}
        applied_keywords = {'applied', 'practical', 'implementation', 'real-world', 'application', 'system'}
        
        course_text = ' '.join(c.name.lower() for c in candidate.transcript.courses)
        theoretical_count = sum(1 for kw in theoretical_keywords if kw in course_text)
        applied_count = sum(1 for kw in applied_keywords if kw in course_text)
        
        essay_text = candidate.personal_essay.lower()
        theoretical_count += sum(1 for kw in theoretical_keywords if kw in essay_text)
        applied_count += sum(1 for kw in applied_keywords if kw in essay_text)
        
        if theoretical_count > applied_count * 1.5:
            return ResearchOrientation.THEORETICAL
        elif applied_count > theoretical_count * 1.5:
            return ResearchOrientation.APPLIED
        return ResearchOrientation.MIXED
    
    def get_full_preference_profile(self, candidate: Candidate) -> Dict:
        """Get complete inferred preference profile"""
        return {
            'interests': self.infer_research_interests(candidate),
            'mentorship': self.infer_mentorship_preference(candidate),
            'orientation': self.infer_research_orientation(candidate),
            'stated_career_goals': candidate.career_goals,
            'hours_available': candidate.hours_available,
            'experience_level': candidate.year
        }


# ============================================================================
# MATCH SCORING COMPONENTS (CANDIDATE PERSPECTIVE)
# ============================================================================

class InterestAlignmentScorer:
    """Score how well lab aligns with candidate's interests"""
    
    def __init__(self, embedding_system: SimpleEmbedding):
        self.embedding = embedding_system
    
    def score(self, candidate: Candidate, lab: Lab, inferred_interests: Dict[str, float]) -> ScoreComponent:
        """Score interest alignment from candidate's perspective"""
        explanations = []
        
        lab_keywords = set(TextProcessor.extract_keywords(
            lab.description + ' ' + ' '.join(lab.research_areas)
        ))
        
        interest_overlap = 0.0
        matching_interests = []
        for interest, weight in inferred_interests.items():
            if interest in lab_keywords:
                interest_overlap += weight
                matching_interests.append(interest)
        
        top_interests = sorted(inferred_interests.values(), reverse=True)[:10]
        max_possible = sum(top_interests) if top_interests else 1
        keyword_score = (interest_overlap / max_possible) * 100 if max_possible else 0
        
        if matching_interests:
            explanations.append(f"Aligns with your interests: {', '.join(matching_interests[:5])}")
        
        candidate_text = candidate.personal_essay + ' ' + candidate.resume_text
        lab_text = lab.description + ' ' + ' '.join(lab.research_areas)
        semantic_sim = self.embedding.similarity(candidate_text, lab_text)
        semantic_score = semantic_sim * 100
        
        if semantic_sim > 0.6:
            explanations.append("Strong alignment with your background")
        elif semantic_sim > 0.4:
            explanations.append("Good alignment with your academic focus")
        
        career_score = 50
        if candidate.career_goals:
            goal_text = ' '.join(candidate.career_goals)
            goal_sim = self.embedding.similarity(goal_text, lab_text)
            career_score = goal_sim * 100
            if goal_sim > 0.5:
                explanations.append("Supports your career goals")
        
        final_score = (keyword_score * 0.4) + (semantic_score * 0.4) + (career_score * 0.2)
        
        return ScoreComponent(
            name="Interest Alignment",
            score=final_score,
            weight=35.0,
            explanation="; ".join(explanations) if explanations else "Moderate interest alignment",
            flags=[]
        )


class SkillDevelopmentScorer:
    """Score what skills candidate would gain from this lab"""
    
    def score(self, candidate: Candidate, lab: Lab) -> ScoreComponent:
        """Two-way skill analysis: contribute vs learn"""
        explanations = []
        flags = []
        
        candidate_skills = set(SkillExtractor.flatten_skills(candidate.resume_text))
        lab_skills = set(s.lower() for s in lab.required_skills + lab.preferred_skills)
        
        contribution_skills = candidate_skills & lab_skills
        learning_skills = lab_skills - candidate_skills
        
        if contribution_skills:
            contribution_score = min(100, len(contribution_skills) * 20)
            explanations.append(f"You can contribute: {', '.join(list(contribution_skills)[:3])}")
        else:
            contribution_score = 20
            flags.append("Limited immediate skill contribution")
        
        if learning_skills:
            learning_score = min(100, len(learning_skills) * 15)
            explanations.append(f"You would learn: {', '.join(list(learning_skills)[:3])}")
        else:
            learning_score = 30
        
        final_score = (contribution_score * 0.4) + (learning_score * 0.6)
        
        return ScoreComponent(
            name="Skill Development",
            score=final_score,
            weight=25.0,
            explanation="; ".join(explanations),
            flags=flags
        )


class CultureFitScorer:
    """Score mentorship and culture alignment"""
    
    def score(self, candidate: Candidate, lab: Lab, inferred_mentorship: MentorshipStyle,
              inferred_orientation: ResearchOrientation) -> ScoreComponent:
        """Score culture and style fit"""
        explanations = []
        flags = []
        score = 100.0
        
        if inferred_mentorship == lab.mentorship_style:
            explanations.append(f"Matches your preferred {lab.mentorship_style.value} style")
        elif (inferred_mentorship == MentorshipStyle.HANDS_ON and 
              lab.mentorship_style == MentorshipStyle.INDEPENDENT):
            score -= 25
            flags.append("Lab offers less guidance than you may prefer")
        elif (inferred_mentorship == MentorshipStyle.INDEPENDENT and 
              lab.mentorship_style == MentorshipStyle.HANDS_ON):
            score -= 15
            flags.append("Lab has more oversight than you may prefer")
        else:
            score -= 10
        
        if inferred_orientation == lab.research_orientation:
            explanations.append(f"Matches your {lab.research_orientation.value} preference")
        elif inferred_orientation != ResearchOrientation.MIXED and lab.research_orientation != ResearchOrientation.MIXED:
            score -= 15
            flags.append(f"Lab is more {lab.research_orientation.value}")
        
        if lab.current_team_size <= 3:
            explanations.append("Small, close-knit team")
        elif lab.current_team_size >= 10:
            explanations.append("Large, diverse research group")
        
        return ScoreComponent(
            name="Culture & Style Fit",
            score=max(0, score),
            weight=20.0,
            explanation="; ".join(explanations) if explanations else "Moderate culture fit",
            flags=flags
        )


class PracticalViabilityScorer:
    """Score practical factors from candidate's perspective"""
    
    def score(self, candidate: Candidate, lab: Lab) -> ScoreComponent:
        """Check if this lab is practically viable"""
        explanations = []
        flags = []
        score = 100.0
        
        if candidate.hours_available >= lab.min_hours_per_week:
            explanations.append(f"Your availability ({candidate.hours_available}h/wk) meets requirements")
        else:
            shortfall = lab.min_hours_per_week - candidate.hours_available
            score -= min(40, shortfall * 5)
            flags.append(f"Lab requires {lab.min_hours_per_week}h/wk")
        
        if lab.preferred_year_min.value <= candidate.year.value <= lab.preferred_year_max.value:
            explanations.append("Your experience level matches")
        elif candidate.year.value < lab.preferred_year_min.value:
            if lab.accepts_training:
                score -= 10
                explanations.append("Lab accepts students at your level")
            else:
                score -= 30
                flags.append("Lab prefers more experienced students")
        else:
            score -= 10
            flags.append("You may be overqualified")
        
        if candidate.graduation_date:
            from datetime import datetime
            months_available = (candidate.graduation_date - datetime.now()).days / 30
            if months_available < lab.min_commitment_months:
                score -= 30
                flags.append(f"Lab needs {lab.min_commitment_months}+ month commitment")
        
        if lab.positions_available > 1:
            explanations.append(f"{lab.positions_available} positions available")
        elif lab.positions_available == 1:
            flags.append("Only 1 position - competitive")
        else:
            score -= 50
            flags.append("No current openings")
        
        return ScoreComponent(
            name="Practical Viability",
            score=max(0, score),
            weight=20.0,
            explanation="; ".join(explanations) if explanations else "Check requirements",
            flags=flags
        )


# ============================================================================
# MAIN CANDIDATE MATCHING ALGORITHM
# ============================================================================

class CandidateMatchingAlgorithm:
    """
    Main algorithm for recommending labs to candidates.
    """
    
    def __init__(self):
        self.embedding = SimpleEmbedding()
        self.preference_inferencer = PreferenceInferencer(self.embedding)
        self._trained = False
    
    def train(self, all_documents: List[str]):
        """Train embedding system on corpus"""
        self.embedding.fit(all_documents)
        self._trained = True
    
    def _ensure_trained(self, candidate: Candidate, labs: List[Lab]):
        """Auto-train if needed"""
        if not self._trained:
            docs = [candidate.resume_text, candidate.personal_essay]
            for lab in labs:
                docs.extend([lab.description, lab.website_text])
            self.train([d for d in docs if d])
    
    def score_lab_for_candidate(self, candidate: Candidate, lab: Lab,
                                 preference_profile: Dict) -> MatchResult:
        """Score a single lab from candidate's perspective."""
        interest_scorer = InterestAlignmentScorer(self.embedding)
        skill_scorer = SkillDevelopmentScorer()
        culture_scorer = CultureFitScorer()
        practical_scorer = PracticalViabilityScorer()
        
        components = [
            interest_scorer.score(candidate, lab, preference_profile['interests']),
            skill_scorer.score(candidate, lab),
            culture_scorer.score(candidate, lab, preference_profile['mentorship'],
                                preference_profile['orientation']),
            practical_scorer.score(candidate, lab)
        ]
        
        weighted_sum = sum(c.score * (c.weight / 100) for c in components)
        tier = self._determine_tier(weighted_sum, components)
        
        what_you_gain = self._generate_gain_insights(components)
        what_to_emphasize = self._generate_application_tips(candidate, lab, components)
        
        strengths = [c.explanation for c in components if c.score >= 70][:3]
        gaps = [f for c in components for f in c.flags][:3]
        
        return MatchResult(
            candidate_id=candidate.id,
            lab_id=lab.id,
            total_score=weighted_sum,
            tier=tier,
            components=components,
            strengths=strengths,
            gaps=gaps,
            suggested_questions=[],
            what_you_would_gain=what_you_gain,
            what_to_emphasize=what_to_emphasize
        )
    
    def _determine_tier(self, score: float, components: List[ScoreComponent]) -> MatchTier:
        """Determine match tier"""
        practical = next((c for c in components if c.name == "Practical Viability"), None)
        if practical and practical.score < 40:
            return MatchTier.WEAK_MATCH
        
        if score >= 75:
            return MatchTier.STRONG_MATCH
        elif score >= 55:
            return MatchTier.GOOD_MATCH
        elif score >= 40:
            return MatchTier.POTENTIAL_MATCH
        elif score >= 25:
            return MatchTier.STRETCH_MATCH
        return MatchTier.WEAK_MATCH
    
    def _generate_gain_insights(self, components: List[ScoreComponent]) -> List[str]:
        """What would candidate gain from this lab?"""
        insights = []
        
        skill_component = next((c for c in components if c.name == "Skill Development"), None)
        if skill_component and "would learn" in skill_component.explanation:
            insights.append(skill_component.explanation.split(";")[0])
        
        culture_component = next((c for c in components if c.name == "Culture & Style Fit"), None)
        if culture_component and culture_component.score >= 70:
            insights.append(f"Good fit: {culture_component.explanation.split(';')[0]}")
        
        interest_component = next((c for c in components if c.name == "Interest Alignment"), None)
        if interest_component and "career" in interest_component.explanation.lower():
            insights.append("Supports your career development")
        
        return insights[:4]
    
    def _generate_application_tips(self, candidate: Candidate, lab: Lab,
                                    components: List[ScoreComponent]) -> List[str]:
        """Generate tips for applying to this lab"""
        tips = []
        
        skill_component = next((c for c in components if c.name == "Skill Development"), None)
        if skill_component and "contribute:" in skill_component.explanation:
            contrib_text = skill_component.explanation.split("contribute:")[1].split(";")[0]
            tips.append(f"Highlight your experience with{contrib_text}")
        
        for comp in components:
            for flag in comp.flags:
                if "guidance" in flag:
                    tips.append("Mention your ability to work independently")
                if "experience level" in flag.lower():
                    tips.append("Emphasize eagerness to learn")
        
        if lab.recent_publications:
            tips.append(f"Reference their work: '{lab.recent_publications[0][:40]}...'")
        
        if lab.current_projects:
            tips.append(f"Show interest in: '{lab.current_projects[0][:35]}...'")
        
        return tips[:4]
    
    def get_recommendations(self, candidate: Candidate, labs: List[Lab],
                            include_stretch: bool = True,
                            max_recommendations: int = 10) -> CandidateRecommendations:
        """Get lab recommendations for a candidate."""
        self._ensure_trained(candidate, labs)
        
        preference_profile = self.preference_inferencer.get_full_preference_profile(candidate)
        
        all_results = []
        for lab in labs:
            result = self.score_lab_for_candidate(candidate, lab, preference_profile)
            all_results.append(result)
        
        all_results.sort(key=lambda r: r.total_score, reverse=True)
        
        main_recommendations = [
            r for r in all_results 
            if r.tier in [MatchTier.STRONG_MATCH, MatchTier.GOOD_MATCH, MatchTier.POTENTIAL_MATCH]
        ][:max_recommendations]
        
        stretch_matches = []
        if include_stretch:
            stretch_matches = [r for r in all_results if r.tier == MatchTier.STRETCH_MATCH][:5]
            serendipity = self._find_serendipitous_matches(all_results, main_recommendations, labs)
            stretch_matches.extend(serendipity)
        
        return CandidateRecommendations(
            candidate_id=candidate.id,
            recommended_labs=main_recommendations,
            stretch_matches=stretch_matches[:5]
        )
    
    def _find_serendipitous_matches(self, all_results: List[MatchResult],
                                     main_recs: List[MatchResult],
                                     labs: List[Lab]) -> List[MatchResult]:
        """Find labs with exceptional strength in one area despite lower overall."""
        serendipitous = []
        main_lab_ids = {r.lab_id for r in main_recs}
        
        for result in all_results:
            if result.lab_id in main_lab_ids or result.tier == MatchTier.WEAK_MATCH:
                continue
            
            for comp in result.components:
                if comp.score >= 85:
                    result.what_you_would_gain.append(f"STRETCH: Exceptional {comp.name.lower()}")
                    serendipitous.append(result)
                    break
        
        return serendipitous[:3]


# ============================================================================
# STABLE MATCHING ENGINE (OPTIONAL)
# ============================================================================

class StableMatchingEngine:
    """
    Gale-Shapley stable matching for coordinated assignment.
    Candidate-proposing: Strategy-proof for candidates.
    """
    
    def __init__(self, candidate_algorithm: CandidateMatchingAlgorithm, lab_algorithm):
        self.candidate_algo = candidate_algorithm
        self.lab_algo = lab_algorithm
    
    def compute_stable_matching(self, candidates: List[Candidate], labs: List[Lab],
                                 lab_capacities: Dict[str, int]) -> Dict[str, str]:
        """Compute stable matching using deferred acceptance."""
        candidate_prefs = {}
        lab_prefs = {}
        
        for candidate in candidates:
            recommendations = self.candidate_algo.get_recommendations(candidate, labs)
            prefs = [r.lab_id for r in recommendations.recommended_labs]
            prefs.extend([r.lab_id for r in recommendations.stretch_matches])
            candidate_prefs[candidate.id] = prefs
        
        for lab in labs:
            ranking = self.lab_algo.rank_candidates(candidates, lab)
            lab_prefs[lab.id] = [r.candidate_id for r in ranking.ranked_candidates]
        
        free_candidates = set(candidate_prefs.keys())
        current_proposals = {c_id: 0 for c_id in candidate_prefs}
        lab_matches = {lab.id: [] for lab in labs}
        candidate_matches = {}
        
        while free_candidates:
            candidate_id = free_candidates.pop()
            
            proposal_idx = current_proposals[candidate_id]
            if proposal_idx >= len(candidate_prefs.get(candidate_id, [])):
                continue
            
            lab_id = candidate_prefs[candidate_id][proposal_idx]
            current_proposals[candidate_id] += 1
            
            capacity = lab_capacities.get(lab_id, 1)
            current_matches = lab_matches[lab_id]
            
            if len(current_matches) < capacity:
                current_matches.append(candidate_id)
                candidate_matches[candidate_id] = lab_id
            else:
                lab_pref_list = lab_prefs.get(lab_id, [])
                new_rank = lab_pref_list.index(candidate_id) if candidate_id in lab_pref_list else float('inf')
                
                worst_current = max(
                    current_matches,
                    key=lambda c: lab_pref_list.index(c) if c in lab_pref_list else float('inf')
                )
                worst_rank = lab_pref_list.index(worst_current) if worst_current in lab_pref_list else float('inf')
                
                if new_rank < worst_rank:
                    current_matches.remove(worst_current)
                    current_matches.append(candidate_id)
                    candidate_matches[candidate_id] = lab_id
                    del candidate_matches[worst_current]
                    free_candidates.add(worst_current)
                else:
                    free_candidates.add(candidate_id)
        
        return candidate_matches


# ============================================================================
# USAGE EXAMPLE
# ============================================================================

def example_usage():
    """Demonstrate candidate matching algorithm"""
    from datetime import datetime
    from models import Course, Transcript
    
    candidate = Candidate(
        id="c001",
        name="Sample Student",
        email="student@university.edu",
        resume_text="""
        Python programming, data analysis, machine learning basics.
        Coursework in statistics and computer science.
        Interested in applying ML to social impact problems.
        """,
        transcript=Transcript(
            courses=[
                Course("Intro to Machine Learning", "CS229", "A", 4.0, "Fall 2024"),
                Course("Statistics for Data Science", "STATS101", "A-", 4.0, "Spring 2024"),
            ],
            cumulative_gpa=3.6,
            major_gpa=3.7,
            institution="UCLA",
            institution_tier=2
        ),
        personal_essay="I am passionate about applying data science to solve real-world problems...",
        why_lab_essays={},
        year=ExperienceLevel.JUNIOR,
        career_goals=["PhD in Computer Science", "Research Scientist"],
        hours_available=15.0
    )
    
    labs = [
        Lab(
            id="lab001",
            name="Smith ML Lab",
            pi_name="Dr. Jane Smith",
            pi_email="smith@university.edu",
            department="Computer Science",
            institution="UCLA",
            description="Machine learning applications in healthcare and social good...",
            research_areas=["machine learning", "healthcare", "social impact"],
            current_projects=["COVID prediction", "Health equity AI"],
            recent_publications=["Smith et al. 2024 - ML for Social Good"],
            website_text="The Smith Lab focuses on...",
            required_skills=["python", "machine_learning"],
            preferred_skills=["pytorch", "statistics"],
            accepts_training=True,
            mentorship_style=MentorshipStyle.COLLABORATIVE,
            research_orientation=ResearchOrientation.APPLIED,
            positions_available=2
        ),
        Lab(
            id="lab002",
            name="Theory Group",
            pi_name="Dr. John Theory",
            pi_email="theory@university.edu",
            department="Computer Science",
            institution="UCLA",
            description="Theoretical foundations of machine learning...",
            research_areas=["theory", "optimization", "algorithms"],
            current_projects=["Convergence proofs", "Complexity bounds"],
            recent_publications=["Theory et al. 2024 - On Convergence"],
            website_text="We prove things...",
            required_skills=["mathematics", "proofs"],
            preferred_skills=["optimization"],
            accepts_training=True,
            mentorship_style=MentorshipStyle.INDEPENDENT,
            research_orientation=ResearchOrientation.THEORETICAL,
            positions_available=1
        )
    ]
    
    algorithm = CandidateMatchingAlgorithm()
    recommendations = algorithm.get_recommendations(candidate, labs)
    
    print("=== Lab Recommendations ===\n")
    for i, rec in enumerate(recommendations.recommended_labs):
        print(f"{i+1}. {rec.lab_id}")
        print(f"   Score: {rec.total_score:.0f} ({rec.tier.value})")
        print(f"   Strengths: {rec.strengths[:2]}")
        print(f"   What you'd gain: {rec.what_you_would_gain[:2]}")
        print()
    
    if recommendations.stretch_matches:
        print("=== Stretch Matches ===\n")
        for rec in recommendations.stretch_matches:
            print(f"• {rec.lab_id}: {rec.what_you_would_gain}")


if __name__ == "__main__":
    example_usage()
