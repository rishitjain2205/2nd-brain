'use client'

import React, { useState } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'

interface Application {
  id: string
  studentName: string
  email: string
  labName: string
  major: string
  gpa: string
  graduationDate: string
  appliedDate: string
  status: 'pending' | 'under_review' | 'accepted' | 'rejected'
  resumeUrl?: string
  resumeData?: string // base64 encoded resume
  resumeFileName?: string
  coverLetter: string
  skills?: string
  aiMatchScore?: number // 0-100 match score from AI analysis
  aiMatchReasoning?: string // AI reasoning for the match
}

// Mock application data
const mockApplications: Application[] = [
  {
    id: '1',
    studentName: 'Sarah Chen',
    email: 'sarah.chen@ucla.edu',
    labName: 'Machine Learning for Healthcare Research',
    major: 'Computer Science',
    gpa: '3.9',
    graduationDate: 'June 2025',
    appliedDate: '2024-01-20',
    status: 'pending',
    coverLetter: 'I am very interested in machine learning applications in healthcare. I have experience with Python, TensorFlow, and have completed coursework in AI and data structures.',
    skills: 'Python, TensorFlow, PyTorch, Machine Learning, Data Analysis',
    resumeFileName: 'sarah_chen_resume.pdf',
    aiMatchScore: 92,
    aiMatchReasoning: 'Strong match: CS major with relevant ML and Python experience. Coursework in AI aligns perfectly with healthcare ML research requirements. High GPA demonstrates academic excellence.'
  },
  {
    id: '2',
    studentName: 'Michael Rodriguez',
    email: 'mrodriguez@ucla.edu',
    labName: 'Machine Learning for Healthcare Research',
    major: 'Data Science',
    gpa: '3.7',
    graduationDate: 'June 2026',
    appliedDate: '2024-01-18',
    status: 'under_review',
    coverLetter: 'I have a strong background in statistics and programming. I am passionate about using data science to improve patient outcomes.',
    skills: 'Statistics, R, Python, Data Visualization, SQL',
    resumeFileName: 'michael_rodriguez_resume.pdf',
    aiMatchScore: 85,
    aiMatchReasoning: 'Good match: Data Science background with strong statistics foundation. Programming skills and passion for healthcare applications align well. Solid GPA and relevant skill set.'
  },
  {
    id: '3',
    studentName: 'Emily Watson',
    email: 'ewatson@g.ucla.edu',
    labName: 'Molecular Biology Lab Assistant',
    major: 'Molecular Biology',
    gpa: '3.85',
    graduationDate: 'June 2025',
    appliedDate: '2024-01-15',
    status: 'pending',
    coverLetter: 'I have completed several biology lab courses and am eager to gain research experience in molecular biology.',
    skills: 'Lab Techniques, PCR, DNA Extraction, Gel Electrophoresis, Cell Culture',
    resumeFileName: 'emily_watson_resume.pdf',
    aiMatchScore: 88,
    aiMatchReasoning: 'Excellent match: Major directly aligns with research area. Demonstrated lab coursework and practical skills. High GPA indicates strong academic performance. Shows genuine interest in molecular biology research.'
  }
]

export default function ProfessorApplications() {
  const router = useRouter()
  const searchParams = useSearchParams()
  const labFilter = searchParams.get('lab')

  const [applications, setApplications] = useState<Application[]>(mockApplications)
  const [selectedApplication, setSelectedApplication] = useState<Application | null>(mockApplications[0])
  const [filterStatus, setFilterStatus] = useState<string>('all')

  const handleSignOut = () => {
    if (typeof window !== 'undefined') {
      localStorage.removeItem('isAuthenticated')
      localStorage.removeItem('userType')
      localStorage.removeItem('userEmail')
    }
    router.push('/login')
  }

  const updateApplicationStatus = (appId: string, status: Application['status']) => {
    setApplications(apps => apps.map(app =>
      app.id === appId ? { ...app, status } : app
    ))
    if (selectedApplication?.id === appId) {
      setSelectedApplication({ ...selectedApplication, status })
    }
  }

  const handleViewResume = (app: Application) => {
    if (app.resumeData) {
      // If we have base64 data, create a blob and download
      const byteCharacters = atob(app.resumeData)
      const byteNumbers = new Array(byteCharacters.length)
      for (let i = 0; i < byteCharacters.length; i++) {
        byteNumbers[i] = byteCharacters.charCodeAt(i)
      }
      const byteArray = new Uint8Array(byteNumbers)
      const blob = new Blob([byteArray], { type: 'application/pdf' })
      const url = window.URL.createObjectURL(blob)
      window.open(url, '_blank')
    } else if (app.resumeFileName) {
      // Show placeholder message for demo
      alert(`Resume: ${app.resumeFileName}\n\nIn production, this would open the actual PDF file.\n\nTo enable full functionality:\n1. Store resume files when students apply\n2. Use file storage (S3, Cloudinary, etc.)\n3. Generate secure download URLs`)
    }
  }

  const getMatchScoreColor = (score?: number) => {
    if (!score) return { bg: '#F3F4F6', text: '#6B7280' }
    if (score >= 90) return { bg: '#D1FAE5', text: '#065F46' }
    if (score >= 80) return { bg: '#DBEAFE', text: '#1E40AF' }
    if (score >= 70) return { bg: '#FEF3C7', text: '#92400E' }
    return { bg: '#FEE2E2', text: '#991B1B' }
  }

  const filteredApplications = applications.filter(app => {
    if (filterStatus !== 'all' && app.status !== filterStatus) return false
    if (labFilter && app.labName !== decodeURIComponent(labFilter)) return false
    return true
  })

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'pending':
        return { bg: '#FEF3C7', text: '#92400E', label: 'Pending' }
      case 'under_review':
        return { bg: '#DBEAFE', text: '#1E40AF', label: 'Under Review' }
      case 'accepted':
        return { bg: '#D1FAE5', text: '#065F46', label: 'Accepted' }
      case 'rejected':
        return { bg: '#FEE2E2', text: '#991B1B', label: 'Rejected' }
      default:
        return { bg: '#F3F4F6', text: '#6B7280', label: 'Unknown' }
    }
  }

  return (
    <div style={{ display: 'flex', width: '100vw', height: '100vh', backgroundColor: '#A8A8A8' }}>
      {/* Left Sidebar */}
      <div
        style={{
          width: '250px',
          backgroundColor: '#FFFFFF',
          borderRight: '1px solid #E2E8F0',
          display: 'flex',
          flexDirection: 'column',
          padding: '24px 0'
        }}
      >
        {/* Logo */}
        <div style={{ padding: '0 24px', marginBottom: '40px' }}>
          <h1
            style={{
              fontSize: '28px',
              fontWeight: 700,
              color: '#000000',
              fontFamily: '"Work Sans", sans-serif',
              marginBottom: '4px'
            }}
          >
            Catalyst
          </h1>
          <p
            style={{
              fontSize: '14px',
              color: '#64748B',
              fontFamily: '"Work Sans", sans-serif'
            }}
          >
            Professor Dashboard
          </p>
        </div>

        {/* Navigation */}
        <nav style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
          <button
            onClick={() => router.push('/professor/dashboard')}
            style={{
              padding: '12px 24px',
              backgroundColor: 'transparent',
              color: '#000000',
              fontFamily: '"Work Sans", sans-serif',
              fontSize: '15px',
              fontWeight: 400,
              border: 'none',
              textAlign: 'left',
              cursor: 'pointer',
              marginBottom: '4px'
            }}
          >
            My Labs
          </button>
          <button
            onClick={() => router.push('/create-lab')}
            style={{
              padding: '12px 24px',
              backgroundColor: 'transparent',
              color: '#000000',
              fontFamily: '"Work Sans", sans-serif',
              fontSize: '15px',
              fontWeight: 400,
              border: 'none',
              textAlign: 'left',
              cursor: 'pointer',
              marginBottom: '4px'
            }}
          >
            Create New Lab
          </button>
          <button
            style={{
              padding: '12px 24px',
              backgroundColor: '#C4A574',
              color: '#000000',
              fontFamily: '"Work Sans", sans-serif',
              fontSize: '15px',
              fontWeight: 500,
              border: 'none',
              textAlign: 'left',
              cursor: 'pointer',
              marginBottom: '4px'
            }}
          >
            Applications
          </button>
        </nav>

        {/* Sign Out Button */}
        <button
          onClick={handleSignOut}
          style={{
            margin: '0 24px',
            padding: '12px',
            backgroundColor: 'transparent',
            color: '#000000',
            fontFamily: '"Work Sans", sans-serif',
            fontSize: '15px',
            fontWeight: 500,
            border: '1px solid #E2E8F0',
            borderRadius: '8px',
            cursor: 'pointer'
          }}
        >
          Sign Out
        </button>
      </div>

      {/* Main Content Area */}
      <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
        {/* Applications List */}
        <div
          style={{
            width: '400px',
            backgroundColor: '#F5F5F5',
            borderRight: '1px solid #E2E8F0',
            display: 'flex',
            flexDirection: 'column',
            overflow: 'hidden'
          }}
        >
          {/* Header */}
          <div style={{ padding: '24px', borderBottom: '1px solid #E2E8F0', backgroundColor: '#FFFFFF' }}>
            <h2
              style={{
                fontSize: '24px',
                fontWeight: 600,
                color: '#000000',
                fontFamily: '"Work Sans", sans-serif',
                marginBottom: '16px'
              }}
            >
              Student Applications
            </h2>

            {/* Filter */}
            <select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
              style={{
                width: '100%',
                padding: '10px 16px',
                borderRadius: '8px',
                border: '1px solid #E2E8F0',
                fontSize: '14px',
                fontFamily: '"Work Sans", sans-serif',
                outline: 'none',
                backgroundColor: '#FFFFFF'
              }}
            >
              <option value="all">All Applications</option>
              <option value="pending">Pending</option>
              <option value="under_review">Under Review</option>
              <option value="accepted">Accepted</option>
              <option value="rejected">Rejected</option>
            </select>
          </div>

          {/* Applications Count */}
          <div style={{ padding: '12px 24px', backgroundColor: '#FFFFFF' }}>
            <p
              style={{
                fontSize: '14px',
                color: '#64748B',
                fontFamily: '"Work Sans", sans-serif'
              }}
            >
              {filteredApplications.length} applications
            </p>
          </div>

          {/* Applications List */}
          <div style={{ flex: 1, overflow: 'auto', padding: '16px' }}>
            {filteredApplications.map(app => {
              const statusInfo = getStatusColor(app.status)
              return (
                <div
                  key={app.id}
                  onClick={() => setSelectedApplication(app)}
                  style={{
                    backgroundColor: '#FFFFFF',
                    border: selectedApplication?.id === app.id ? '2px solid #C4A574' : '1px solid #E2E8F0',
                    borderRadius: '8px',
                    padding: '16px',
                    marginBottom: '12px',
                    cursor: 'pointer',
                    transition: 'all 0.2s'
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', marginBottom: '8px' }}>
                    <h3
                      style={{
                        fontSize: '16px',
                        fontWeight: 600,
                        color: '#000000',
                        fontFamily: '"Work Sans", sans-serif'
                      }}
                    >
                      {app.studentName}
                    </h3>
                    <span
                      style={{
                        padding: '4px 8px',
                        backgroundColor: statusInfo.bg,
                        color: statusInfo.text,
                        borderRadius: '12px',
                        fontSize: '11px',
                        fontFamily: '"Work Sans", sans-serif',
                        fontWeight: 600
                      }}
                    >
                      {statusInfo.label}
                    </span>
                  </div>
                  <p
                    style={{
                      fontSize: '13px',
                      color: '#64748B',
                      fontFamily: '"Work Sans", sans-serif',
                      marginBottom: '4px'
                    }}
                  >
                    {app.major} • GPA: {app.gpa}
                  </p>
                  <p
                    style={{
                      fontSize: '13px',
                      color: '#64748B',
                      fontFamily: '"Work Sans", sans-serif',
                      marginBottom: '8px'
                    }}
                  >
                    {app.labName}
                  </p>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <p
                      style={{
                        fontSize: '12px',
                        color: '#9CA3AF',
                        fontFamily: '"Work Sans", sans-serif'
                      }}
                    >
                      Applied: {new Date(app.appliedDate).toLocaleDateString()}
                    </p>
                    {app.aiMatchScore && (
                      <div
                        style={{
                          padding: '4px 10px',
                          backgroundColor: getMatchScoreColor(app.aiMatchScore).bg,
                          color: getMatchScoreColor(app.aiMatchScore).text,
                          borderRadius: '12px',
                          fontSize: '12px',
                          fontFamily: '"Work Sans", sans-serif',
                          fontWeight: 700
                        }}
                      >
                        {app.aiMatchScore}% Match
                      </div>
                    )}
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        {/* Right Panel - Application Details */}
        {selectedApplication && (
          <div
            style={{
              flex: 1,
              backgroundColor: '#FFFFFF',
              overflow: 'auto',
              padding: '32px'
            }}
          >
            <div style={{ marginBottom: '24px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', marginBottom: '16px' }}>
                <div>
                  <h2
                    style={{
                      fontSize: '32px',
                      fontWeight: 700,
                      color: '#000000',
                      fontFamily: '"Work Sans", sans-serif',
                      marginBottom: '8px'
                    }}
                  >
                    {selectedApplication.studentName}
                  </h2>
                  <p
                    style={{
                      fontSize: '16px',
                      color: '#64748B',
                      fontFamily: '"Work Sans", sans-serif'
                    }}
                  >
                    {selectedApplication.email}
                  </p>
                </div>
                <span
                  style={{
                    padding: '6px 16px',
                    backgroundColor: getStatusColor(selectedApplication.status).bg,
                    color: getStatusColor(selectedApplication.status).text,
                    borderRadius: '14px',
                    fontSize: '14px',
                    fontFamily: '"Work Sans", sans-serif',
                    fontWeight: 600
                  }}
                >
                  {getStatusColor(selectedApplication.status).label}
                </span>
              </div>
            </div>

            {/* AI Match Score Section */}
            {selectedApplication.aiMatchScore && (
              <div
                style={{
                  backgroundColor: getMatchScoreColor(selectedApplication.aiMatchScore).bg,
                  border: `2px solid ${getMatchScoreColor(selectedApplication.aiMatchScore).text}`,
                  borderRadius: '12px',
                  padding: '20px',
                  marginBottom: '24px'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '16px', marginBottom: '12px' }}>
                  <div
                    style={{
                      fontSize: '36px',
                      fontWeight: 700,
                      color: getMatchScoreColor(selectedApplication.aiMatchScore).text,
                      fontFamily: '"Work Sans", sans-serif'
                    }}
                  >
                    {selectedApplication.aiMatchScore}%
                  </div>
                  <div>
                    <h3
                      style={{
                        fontSize: '18px',
                        fontWeight: 600,
                        color: getMatchScoreColor(selectedApplication.aiMatchScore).text,
                        fontFamily: '"Work Sans", sans-serif',
                        marginBottom: '4px'
                      }}
                    >
                      AI Match Score
                    </h3>
                    <p
                      style={{
                        fontSize: '13px',
                        color: getMatchScoreColor(selectedApplication.aiMatchScore).text,
                        fontFamily: '"Work Sans", sans-serif',
                        opacity: 0.8
                      }}
                    >
                      Based on skills, experience, and lab requirements
                    </p>
                  </div>
                </div>
                {selectedApplication.aiMatchReasoning && (
                  <p
                    style={{
                      fontSize: '14px',
                      color: getMatchScoreColor(selectedApplication.aiMatchScore).text,
                      fontFamily: '"Work Sans", sans-serif',
                      lineHeight: '1.6',
                      opacity: 0.9
                    }}
                  >
                    {selectedApplication.aiMatchReasoning}
                  </p>
                )}
              </div>
            )}

            {/* Resume Button */}
            {selectedApplication.resumeFileName && (
              <button
                onClick={() => handleViewResume(selectedApplication)}
                style={{
                  width: '100%',
                  padding: '14px 20px',
                  borderRadius: '8px',
                  backgroundColor: '#FFFFFF',
                  color: '#1E1E1E',
                  fontFamily: '"Work Sans", sans-serif',
                  fontSize: '15px',
                  fontWeight: 600,
                  border: '2px solid #1E1E1E',
                  cursor: 'pointer',
                  marginBottom: '32px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: '8px',
                  transition: 'all 0.2s'
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.backgroundColor = '#1E1E1E'
                  e.currentTarget.style.color = '#FFFFFF'
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.backgroundColor = '#FFFFFF'
                  e.currentTarget.style.color = '#1E1E1E'
                }}
              >
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                  <polyline points="14 2 14 8 20 8"></polyline>
                  <line x1="12" y1="18" x2="12" y2="12"></line>
                  <line x1="9" y1="15" x2="15" y2="15"></line>
                </svg>
                View Resume ({selectedApplication.resumeFileName})
              </button>
            )}

            {/* Student Info */}
            <div style={{ marginBottom: '32px' }}>
              <h3
                style={{
                  fontSize: '18px',
                  fontWeight: 600,
                  color: '#000000',
                  fontFamily: '"Work Sans", sans-serif',
                  marginBottom: '16px',
                  paddingBottom: '8px',
                  borderBottom: '2px solid #E2E8F0'
                }}
              >
                Student Information
              </h3>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
                <div>
                  <p style={{ fontSize: '13px', color: '#64748B', fontFamily: '"Work Sans", sans-serif', marginBottom: '4px' }}>
                    Major
                  </p>
                  <p style={{ fontSize: '15px', color: '#000000', fontFamily: '"Work Sans", sans-serif', fontWeight: 500 }}>
                    {selectedApplication.major}
                  </p>
                </div>
                <div>
                  <p style={{ fontSize: '13px', color: '#64748B', fontFamily: '"Work Sans", sans-serif', marginBottom: '4px' }}>
                    GPA
                  </p>
                  <p style={{ fontSize: '15px', color: '#000000', fontFamily: '"Work Sans", sans-serif', fontWeight: 500 }}>
                    {selectedApplication.gpa}
                  </p>
                </div>
                <div>
                  <p style={{ fontSize: '13px', color: '#64748B', fontFamily: '"Work Sans", sans-serif', marginBottom: '4px' }}>
                    Graduation Date
                  </p>
                  <p style={{ fontSize: '15px', color: '#000000', fontFamily: '"Work Sans", sans-serif', fontWeight: 500 }}>
                    {selectedApplication.graduationDate}
                  </p>
                </div>
                <div>
                  <p style={{ fontSize: '13px', color: '#64748B', fontFamily: '"Work Sans", sans-serif', marginBottom: '4px' }}>
                    Applied Date
                  </p>
                  <p style={{ fontSize: '15px', color: '#000000', fontFamily: '"Work Sans", sans-serif', fontWeight: 500 }}>
                    {new Date(selectedApplication.appliedDate).toLocaleDateString()}
                  </p>
                </div>
              </div>

              {/* Skills */}
              {selectedApplication.skills && (
                <div style={{ marginTop: '20px' }}>
                  <p style={{ fontSize: '13px', color: '#64748B', fontFamily: '"Work Sans", sans-serif', marginBottom: '8px' }}>
                    Skills
                  </p>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                    {selectedApplication.skills.split(',').map((skill, index) => (
                      <span
                        key={index}
                        style={{
                          padding: '6px 12px',
                          backgroundColor: '#F3F4F6',
                          color: '#1F2937',
                          borderRadius: '6px',
                          fontSize: '13px',
                          fontFamily: '"Work Sans", sans-serif',
                          fontWeight: 500
                        }}
                      >
                        {skill.trim()}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Cover Letter */}
            <div style={{ marginBottom: '32px' }}>
              <h3
                style={{
                  fontSize: '18px',
                  fontWeight: 600,
                  color: '#000000',
                  fontFamily: '"Work Sans", sans-serif',
                  marginBottom: '16px',
                  paddingBottom: '8px',
                  borderBottom: '2px solid #E2E8F0'
                }}
              >
                Statement of Interest
              </h3>
              <p
                style={{
                  fontSize: '15px',
                  color: '#334155',
                  fontFamily: '"Work Sans", sans-serif',
                  lineHeight: '1.6'
                }}
              >
                {selectedApplication.coverLetter}
              </p>
            </div>

            {/* Action Buttons */}
            <div style={{ display: 'flex', gap: '12px' }}>
              <button
                onClick={() => updateApplicationStatus(selectedApplication.id, 'accepted')}
                disabled={selectedApplication.status === 'accepted'}
                style={{
                  padding: '12px 24px',
                  borderRadius: '8px',
                  backgroundColor: selectedApplication.status === 'accepted' ? '#9CA3AF' : '#059669',
                  color: '#FFFFFF',
                  fontFamily: '"Work Sans", sans-serif',
                  fontSize: '15px',
                  fontWeight: 600,
                  border: 'none',
                  cursor: selectedApplication.status === 'accepted' ? 'not-allowed' : 'pointer',
                  transition: 'background-color 0.2s'
                }}
              >
                Accept
              </button>
              <button
                onClick={() => updateApplicationStatus(selectedApplication.id, 'under_review')}
                disabled={selectedApplication.status === 'under_review'}
                style={{
                  padding: '12px 24px',
                  borderRadius: '8px',
                  backgroundColor: selectedApplication.status === 'under_review' ? '#9CA3AF' : '#1E1E1E',
                  color: '#FFFFFF',
                  fontFamily: '"Work Sans", sans-serif',
                  fontSize: '15px',
                  fontWeight: 600,
                  border: 'none',
                  cursor: selectedApplication.status === 'under_review' ? 'not-allowed' : 'pointer'
                }}
              >
                Move to Review
              </button>
              <button
                onClick={() => updateApplicationStatus(selectedApplication.id, 'rejected')}
                disabled={selectedApplication.status === 'rejected'}
                style={{
                  padding: '12px 24px',
                  borderRadius: '8px',
                  backgroundColor: 'transparent',
                  color: '#DC2626',
                  fontFamily: '"Work Sans", sans-serif',
                  fontSize: '15px',
                  fontWeight: 500,
                  border: '1px solid #FCA5A5',
                  cursor: selectedApplication.status === 'rejected' ? 'not-allowed' : 'pointer',
                  opacity: selectedApplication.status === 'rejected' ? 0.5 : 1
                }}
              >
                Reject
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
