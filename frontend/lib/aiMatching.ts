// AI-powered lab fit analysis utilities

interface StudentProfile {
  major: string
  gpa: string
  skills: string
  coverLetter?: string
  graduationDate?: string
}

interface LabRequirements {
  title: string
  department: string
  requiredSkills?: string[]
  description?: string
}

interface MatchResult {
  score: number // 0-100
  reasoning: string
}

/**
 * Calculate AI match score between student profile and lab requirements
 * This is a simplified algorithm - can be enhanced with Claude API for production
 */
export function calculateMatchScore(
  student: StudentProfile,
  lab: LabRequirements
): MatchResult {
  let score = 0
  const reasoningPoints: string[] = []

  // 1. Major alignment (30 points)
  const majorScore = calculateMajorAlignment(student.major, lab.department, lab.title)
  score += majorScore
  if (majorScore >= 25) {
    reasoningPoints.push(`Major (${student.major}) aligns well with ${lab.department}`)
  } else if (majorScore >= 15) {
    reasoningPoints.push(`Major (${student.major}) has some relevance to ${lab.department}`)
  }

  // 2. GPA (20 points)
  const gpaScore = calculateGPAScore(student.gpa)
  score += gpaScore
  if (parseFloat(student.gpa) >= 3.8) {
    reasoningPoints.push('Excellent GPA demonstrates strong academic performance')
  } else if (parseFloat(student.gpa) >= 3.5) {
    reasoningPoints.push('Strong GPA indicates solid academic foundation')
  }

  // 3. Skills match (40 points)
  if (lab.requiredSkills && student.skills) {
    const skillScore = calculateSkillsMatch(
      student.skills.toLowerCase(),
      lab.requiredSkills.map(s => s.toLowerCase())
    )
    score += skillScore

    if (skillScore >= 30) {
      reasoningPoints.push('Highly relevant technical skills for this position')
    } else if (skillScore >= 20) {
      reasoningPoints.push('Good skill set with some relevant experience')
    } else if (skillScore >= 10) {
      reasoningPoints.push('Some transferable skills present')
    }
  }

  // 4. Cover letter quality (10 points)
  if (student.coverLetter) {
    const letterScore = calculateCoverLetterScore(student.coverLetter, lab.title)
    score += letterScore
    if (letterScore >= 8) {
      reasoningPoints.push('Strong statement of interest shows genuine motivation')
    }
  }

  // Generate reasoning
  let reasoning = ''
  if (score >= 90) {
    reasoning = 'Excellent match: '
  } else if (score >= 80) {
    reasoning = 'Strong match: '
  } else if (score >= 70) {
    reasoning = 'Good match: '
  } else if (score >= 60) {
    reasoning = 'Moderate match: '
  } else {
    reasoning = 'Potential match: '
  }

  reasoning += reasoningPoints.join('. ') + '.'

  return {
    score: Math.min(100, Math.round(score)),
    reasoning
  }
}

function calculateMajorAlignment(major: string, department: string, labTitle: string): number {
  const majorLower = major.toLowerCase()
  const deptLower = department.toLowerCase()
  const titleLower = labTitle.toLowerCase()

  // Direct match
  if (majorLower.includes(deptLower) || deptLower.includes(majorLower)) {
    return 30
  }

  // Related fields
  const relatedFields: { [key: string]: string[] } = {
    'computer science': ['data science', 'software engineering', 'artificial intelligence', 'machine learning'],
    'biology': ['molecular biology', 'biochemistry', 'bioinformatics', 'neuroscience'],
    'chemistry': ['biochemistry', 'chemical engineering', 'materials science'],
    'physics': ['engineering', 'materials science', 'astronomy'],
    'mathematics': ['statistics', 'data science', 'computer science'],
    'engineering': ['computer science', 'physics', 'mathematics']
  }

  for (const [field, related] of Object.entries(relatedFields)) {
    if (majorLower.includes(field) || field.includes(majorLower)) {
      if (related.some(r => deptLower.includes(r) || titleLower.includes(r))) {
        return 20
      }
    }
  }

  // Partial relevance
  if (titleLower.includes(majorLower.split(' ')[0]) || majorLower.includes(deptLower.split(' ')[0])) {
    return 15
  }

  return 5
}

function calculateGPAScore(gpa: string): number {
  const gpaNum = parseFloat(gpa)
  if (isNaN(gpaNum)) return 0

  if (gpaNum >= 3.9) return 20
  if (gpaNum >= 3.7) return 18
  if (gpaNum >= 3.5) return 15
  if (gpaNum >= 3.3) return 12
  if (gpaNum >= 3.0) return 10
  return 5
}

function calculateSkillsMatch(studentSkills: string, requiredSkills: string[]): number {
  if (!requiredSkills.length) return 20 // Default score if no required skills specified

  let matchCount = 0
  const totalRequired = requiredSkills.length

  for (const skill of requiredSkills) {
    if (studentSkills.includes(skill)) {
      matchCount++
    }
  }

  const matchPercentage = matchCount / totalRequired
  return Math.round(matchPercentage * 40)
}

function calculateCoverLetterScore(coverLetter: string, labTitle: string): number {
  let score = 5 // Base score for having a cover letter

  const letterLower = coverLetter.toLowerCase()
  const titleWords = labTitle.toLowerCase().split(' ')

  // Check for specific keywords
  const passionKeywords = ['passionate', 'excited', 'interested', 'eager', 'motivated']
  const experienceKeywords = ['experience', 'worked', 'completed', 'developed', 'research']

  if (passionKeywords.some(keyword => letterLower.includes(keyword))) {
    score += 2
  }

  if (experienceKeywords.some(keyword => letterLower.includes(keyword))) {
    score += 2
  }

  // Check if cover letter mentions lab-specific terms
  if (titleWords.some(word => word.length > 4 && letterLower.includes(word))) {
    score += 1
  }

  return score
}

/**
 * Generate AI match score using Claude API (for production)
 * This requires backend API integration
 */
export async function generateAIMatchScore(
  student: StudentProfile,
  lab: LabRequirements
): Promise<MatchResult> {
  // TODO: Implement Claude API integration
  // For now, use the simple algorithm
  return calculateMatchScore(student, lab)
}
