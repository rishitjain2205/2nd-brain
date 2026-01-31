'use client'

import React, { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'

interface Lab {
  id: string
  name: string
  pi: string
  department: string
  researchAreas: string[]
  description: string
  website: string
  frequency: string
}

// Mock lab data
const mockLabs: Lab[] = [
  {
    id: '1',
    name: 'Shahan Lab',
    pi: 'Dr Shahan',
    department: 'Molecular Biology',
    researchAreas: ['Research', 'Science'],
    description: 'Our lab focuses on molecular mechanisms of gene regulation and cellular signaling pathways. We use cutting-edge techniques including CRISPR gene editing, single-cell RNA sequencing, and advanced microscopy to understand how cells make decisions.',
    website: 'https://www.lifesci.ucla.edu/mcdb-shahan/',
    frequency: 'Weekly lab meetings, flexible research hours'
  }
]

export default function StudentDashboard() {
  const router = useRouter()
  const [searchQuery, setSearchQuery] = useState('')
  const [labs, setLabs] = useState<Lab[]>(mockLabs)
  const [selectedLab, setSelectedLab] = useState<Lab | null>(mockLabs[0])
  const [showApplicationModal, setShowApplicationModal] = useState(false)
  const [showSuccessMessage, setShowSuccessMessage] = useState(false)

  // Application form state
  const [fullName, setFullName] = useState('')
  const [email, setEmail] = useState('')
  const [phone, setPhone] = useState('')
  const [university, setUniversity] = useState('UCLA')
  const [major, setMajor] = useState('')
  const [gpa, setGpa] = useState('')
  const [graduationDate, setGraduationDate] = useState('')
  const [resumeFile, setResumeFile] = useState<File | null>(null)
  const [transcriptFile, setTranscriptFile] = useState<File | null>(null)
  const [coverLetter, setCoverLetter] = useState('')
  const [availability, setAvailability] = useState<string[]>([])
  const [skills, setSkills] = useState('')
  const [references, setReferences] = useState('')

  const filteredLabs = labs.filter(lab =>
    lab.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    lab.pi.toLowerCase().includes(searchQuery.toLowerCase()) ||
    lab.department.toLowerCase().includes(searchQuery.toLowerCase())
  )

  const handleApplyClick = () => {
    // Navigate to apply page with lab name
    router.push(`/apply?lab=${encodeURIComponent(selectedLab?.name || '')}`)
  }

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>, type: 'resume' | 'transcript') => {
    const file = e.target.files?.[0]
    if (file) {
      // Check file size (5MB limit)
      if (file.size > 5 * 1024 * 1024) {
        return
      }
      if (type === 'resume') {
        setResumeFile(file)
      } else {
        setTranscriptFile(file)
      }
    }
  }

  const toggleAvailability = (day: string) => {
    if (availability.includes(day)) {
      setAvailability(availability.filter(d => d !== day))
    } else {
      setAvailability([...availability, day])
    }
  }

  const resetForm = () => {
    setFullName('')
    setEmail('')
    setPhone('')
    setMajor('')
    setGpa('')
    setGraduationDate('')
    setResumeFile(null)
    setTranscriptFile(null)
    setCoverLetter('')
    setAvailability([])
    setSkills('')
    setReferences('')
  }

  const handleSubmitApplication = () => {
    // Submit application logic here
    setShowApplicationModal(false)
    setShowSuccessMessage(true)
    resetForm()

    // Hide success message after 3 seconds
    setTimeout(() => {
      setShowSuccessMessage(false)
    }, 3000)
  }

  const handleSignOut = () => {
    // Clear auth and redirect to login
    if (typeof window !== 'undefined') {
      localStorage.removeItem('isAuthenticated')
      localStorage.removeItem('userType')
    }
    router.push('/login')
  }

  const isFormValid = () => {
    return fullName.trim() && email.trim() && phone.trim() && major.trim() &&
           gpa.trim() && graduationDate.trim() && resumeFile && coverLetter.trim() &&
           availability.length > 0 && skills.trim()
  }

  return (
    <div style={{ display: 'flex', width: '100vw', height: '100vh', backgroundColor: '#A8A8A8' }}>
      {/* Success Message */}
      {showSuccessMessage && (
        <div
          style={{
            position: 'fixed',
            top: '24px',
            right: '24px',
            backgroundColor: '#10B981',
            color: '#FFFFFF',
            padding: '16px 24px',
            borderRadius: '8px',
            boxShadow: '0 4px 6px rgba(0, 0, 0, 0.1)',
            zIndex: 2000,
            fontFamily: '"Work Sans", sans-serif',
            fontSize: '15px',
            fontWeight: 500
          }}
        >
          Application submitted successfully!
        </div>
      )}

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
            Student Dashboard
          </p>
        </div>

        {/* Navigation */}
        <nav style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
          <button
            onClick={() => router.push('/student/dashboard')}
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
            Explore Labs
          </button>
          <button
            onClick={() => router.push('/my-applications')}
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
            My Applications
          </button>
          <button
            onClick={() => router.push('/profile')}
            style={{
              padding: '12px 24px',
              backgroundColor: 'transparent',
              color: '#000000',
              fontFamily: '"Work Sans", sans-serif',
              fontSize: '15px',
              fontWeight: 400,
              border: 'none',
              textAlign: 'left',
              cursor: 'pointer'
            }}
          >
            Profile
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
        {/* Labs List */}
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
              Research Labs
            </h2>
            <input
              type="text"
              placeholder="Search labs..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{
                width: '100%',
                padding: '10px 16px',
                border: '1px solid #E2E8F0',
                borderRadius: '6px',
                fontSize: '14px',
                fontFamily: '"Work Sans", sans-serif',
                outline: 'none'
              }}
            />
          </div>

          {/* Labs Count */}
          <div style={{ padding: '12px 24px', backgroundColor: '#FFFFFF' }}>
            <p
              style={{
                fontSize: '14px',
                color: '#64748B',
                fontFamily: '"Work Sans", sans-serif'
              }}
            >
              {filteredLabs.length} labs found
            </p>
          </div>

          {/* Labs List */}
          <div style={{ flex: 1, overflow: 'auto', padding: '16px' }}>
            {filteredLabs.map(lab => (
              <div
                key={lab.id}
                onClick={() => setSelectedLab(lab)}
                style={{
                  backgroundColor: selectedLab?.id === lab.id ? '#FFFFFF' : '#FFFFFF',
                  border: selectedLab?.id === lab.id ? '2px solid #C4A574' : '1px solid #E2E8F0',
                  borderRadius: '8px',
                  padding: '16px',
                  marginBottom: '12px',
                  cursor: 'pointer',
                  transition: 'all 0.2s'
                }}
              >
                <h3
                  style={{
                    fontSize: '18px',
                    fontWeight: 600,
                    color: '#000000',
                    fontFamily: '"Work Sans", sans-serif',
                    marginBottom: '8px'
                  }}
                >
                  {lab.name}
                </h3>
                <p
                  style={{
                    fontSize: '14px',
                    color: '#64748B',
                    fontFamily: '"Work Sans", sans-serif',
                    marginBottom: '4px'
                  }}
                >
                  PI: {lab.pi}
                </p>
                <p
                  style={{
                    fontSize: '14px',
                    color: '#64748B',
                    fontFamily: '"Work Sans", sans-serif',
                    marginBottom: '8px'
                  }}
                >
                  {lab.department}
                </p>
                <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                  {lab.researchAreas.map((area, idx) => (
                    <span
                      key={idx}
                      style={{
                        padding: '4px 12px',
                        backgroundColor: '#C4A574',
                        color: '#000000',
                        borderRadius: '12px',
                        fontSize: '12px',
                        fontFamily: '"Work Sans", sans-serif'
                      }}
                    >
                      {area}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Right Panel - Lab Details */}
        {selectedLab && (
          <div
            style={{
              flex: 1,
              backgroundColor: '#FFFFFF',
              overflow: 'auto',
              padding: '32px'
            }}
          >
            <h2
              style={{
                fontSize: '32px',
                fontWeight: 700,
                color: '#000000',
                fontFamily: '"Work Sans", sans-serif',
                marginBottom: '16px'
              }}
            >
              {selectedLab.name}
            </h2>

            <div style={{ marginBottom: '24px' }}>
              <p
                style={{
                  fontSize: '16px',
                  color: '#000000',
                  fontFamily: '"Work Sans", sans-serif',
                  marginBottom: '8px'
                }}
              >
                <strong>Principal Investigator:</strong> {selectedLab.pi}
              </p>
              <p
                style={{
                  fontSize: '16px',
                  color: '#000000',
                  fontFamily: '"Work Sans", sans-serif',
                  marginBottom: '16px'
                }}
              >
                {selectedLab.department}
              </p>

              <h3
                style={{
                  fontSize: '18px',
                  fontWeight: 600,
                  color: '#000000',
                  fontFamily: '"Work Sans", sans-serif',
                  marginBottom: '12px'
                }}
              >
                Research Areas
              </h3>
              <div style={{ display: 'flex', gap: '8px', marginBottom: '24px' }}>
                {selectedLab.researchAreas.map((area, idx) => (
                  <span
                    key={idx}
                    style={{
                      padding: '6px 16px',
                      backgroundColor: '#C4A574',
                      color: '#000000',
                      borderRadius: '14px',
                      fontSize: '14px',
                      fontFamily: '"Work Sans", sans-serif'
                    }}
                  >
                    {area}
                  </span>
                ))}
              </div>

              <h3
                style={{
                  fontSize: '18px',
                  fontWeight: 600,
                  color: '#000000',
                  fontFamily: '"Work Sans", sans-serif',
                  marginBottom: '12px'
                }}
              >
                About the Lab
              </h3>
              <p
                style={{
                  fontSize: '15px',
                  color: '#334155',
                  fontFamily: '"Work Sans", sans-serif',
                  lineHeight: '1.6',
                  marginBottom: '24px'
                }}
              >
                {selectedLab.description}
              </p>

              <h3
                style={{
                  fontSize: '18px',
                  fontWeight: 600,
                  color: '#000000',
                  fontFamily: '"Work Sans", sans-serif',
                  marginBottom: '12px'
                }}
              >
                Website
              </h3>
              <a
                href={selectedLab.website}
                target="_blank"
                rel="noopener noreferrer"
                style={{
                  fontSize: '15px',
                  color: '#2563EB',
                  fontFamily: '"Work Sans", sans-serif',
                  textDecoration: 'underline',
                  marginBottom: '24px',
                  display: 'block'
                }}
              >
                {selectedLab.website} →
              </a>

              <h3
                style={{
                  fontSize: '18px',
                  fontWeight: 600,
                  color: '#000000',
                  fontFamily: '"Work Sans", sans-serif',
                  marginBottom: '12px'
                }}
              >
                Frequency
              </h3>
              <p
                style={{
                  fontSize: '15px',
                  color: '#334155',
                  fontFamily: '"Work Sans", sans-serif',
                  marginBottom: '32px'
                }}
              >
                {selectedLab.frequency}
              </p>

              <button
                onClick={handleApplyClick}
                style={{
                  width: '100%',
                  padding: '14px',
                  backgroundColor: '#1E1E1E',
                  color: '#FFFFFF',
                  fontFamily: '"Work Sans", sans-serif',
                  fontSize: '16px',
                  fontWeight: 600,
                  border: 'none',
                  borderRadius: '8px',
                  cursor: 'pointer',
                  transition: 'background-color 0.2s'
                }}
                onMouseEnter={(e) => e.currentTarget.style.backgroundColor = '#000000'}
                onMouseLeave={(e) => e.currentTarget.style.backgroundColor = '#1E1E1E'}
              >
                Apply to Lab
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Enhanced Application Modal */}
      {showApplicationModal && (
        <div
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            backgroundColor: 'rgba(0, 0, 0, 0.5)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000
          }}
          onClick={() => setShowApplicationModal(false)}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            style={{
              backgroundColor: '#FFFFFF',
              borderRadius: '12px',
              padding: '32px',
              maxWidth: '700px',
              width: '90%',
              maxHeight: '85vh',
              overflow: 'auto'
            }}
          >
            <h2
              style={{
                fontSize: '24px',
                fontWeight: 700,
                color: '#000000',
                fontFamily: '"Work Sans", sans-serif',
                marginBottom: '24px'
              }}
            >
              Apply to {selectedLab?.name}
            </h2>

            {/* Personal Information Section */}
            <div style={{ marginBottom: '24px' }}>
              <h3
                style={{
                  fontSize: '16px',
                  fontWeight: 600,
                  color: '#000000',
                  fontFamily: '"Work Sans", sans-serif',
                  marginBottom: '16px',
                  borderBottom: '1px solid #E2E8F0',
                  paddingBottom: '8px'
                }}
              >
                Personal Information
              </h3>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginBottom: '12px' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, color: '#000000', fontFamily: '"Work Sans", sans-serif', marginBottom: '6px' }}>
                    Full Name <span style={{ color: '#EF4444' }}>*</span>
                  </label>
                  <input
                    type="text"
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                    placeholder="Jane Doe"
                    style={{ width: '100%', padding: '10px 12px', border: '1px solid #E2E8F0', borderRadius: '6px', fontSize: '14px', fontFamily: '"Work Sans", sans-serif', outline: 'none' }}
                  />
                </div>
                <div>
                  <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, color: '#000000', fontFamily: '"Work Sans", sans-serif', marginBottom: '6px' }}>
                    Email <span style={{ color: '#EF4444' }}>*</span>
                  </label>
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="jane.doe@ucla.edu"
                    style={{ width: '100%', padding: '10px 12px', border: '1px solid #E2E8F0', borderRadius: '6px', fontSize: '14px', fontFamily: '"Work Sans", sans-serif', outline: 'none' }}
                  />
                </div>
              </div>

              <div style={{ marginBottom: '12px' }}>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, color: '#000000', fontFamily: '"Work Sans", sans-serif', marginBottom: '6px' }}>
                  Phone Number <span style={{ color: '#EF4444' }}>*</span>
                </label>
                <input
                  type="tel"
                  value={phone}
                  onChange={(e) => setPhone(e.target.value)}
                  placeholder="(310) 555-0123"
                  style={{ width: '100%', padding: '10px 12px', border: '1px solid #E2E8F0', borderRadius: '6px', fontSize: '14px', fontFamily: '"Work Sans", sans-serif', outline: 'none' }}
                />
              </div>
            </div>

            {/* Education Section */}
            <div style={{ marginBottom: '24px' }}>
              <h3
                style={{
                  fontSize: '16px',
                  fontWeight: 600,
                  color: '#000000',
                  fontFamily: '"Work Sans", sans-serif',
                  marginBottom: '16px',
                  borderBottom: '1px solid #E2E8F0',
                  paddingBottom: '8px'
                }}
              >
                Education
              </h3>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginBottom: '12px' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, color: '#000000', fontFamily: '"Work Sans", sans-serif', marginBottom: '6px' }}>
                    University <span style={{ color: '#EF4444' }}>*</span>
                  </label>
                  <input
                    type="text"
                    value={university}
                    onChange={(e) => setUniversity(e.target.value)}
                    style={{ width: '100%', padding: '10px 12px', border: '1px solid #E2E8F0', borderRadius: '6px', fontSize: '14px', fontFamily: '"Work Sans", sans-serif', outline: 'none' }}
                  />
                </div>
                <div>
                  <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, color: '#000000', fontFamily: '"Work Sans", sans-serif', marginBottom: '6px' }}>
                    Major <span style={{ color: '#EF4444' }}>*</span>
                  </label>
                  <input
                    type="text"
                    value={major}
                    onChange={(e) => setMajor(e.target.value)}
                    placeholder="Computer Science"
                    style={{ width: '100%', padding: '10px 12px', border: '1px solid #E2E8F0', borderRadius: '6px', fontSize: '14px', fontFamily: '"Work Sans", sans-serif', outline: 'none' }}
                  />
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, color: '#000000', fontFamily: '"Work Sans", sans-serif', marginBottom: '6px' }}>
                    GPA <span style={{ color: '#EF4444' }}>*</span>
                  </label>
                  <input
                    type="text"
                    value={gpa}
                    onChange={(e) => setGpa(e.target.value)}
                    placeholder="3.85"
                    style={{ width: '100%', padding: '10px 12px', border: '1px solid #E2E8F0', borderRadius: '6px', fontSize: '14px', fontFamily: '"Work Sans", sans-serif', outline: 'none' }}
                  />
                </div>
                <div>
                  <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, color: '#000000', fontFamily: '"Work Sans", sans-serif', marginBottom: '6px' }}>
                    Expected Graduation <span style={{ color: '#EF4444' }}>*</span>
                  </label>
                  <input
                    type="text"
                    value={graduationDate}
                    onChange={(e) => setGraduationDate(e.target.value)}
                    placeholder="June 2026"
                    style={{ width: '100%', padding: '10px 12px', border: '1px solid #E2E8F0', borderRadius: '6px', fontSize: '14px', fontFamily: '"Work Sans", sans-serif', outline: 'none' }}
                  />
                </div>
              </div>
            </div>

            {/* Application Materials */}
            <div style={{ marginBottom: '24px' }}>
              <h3
                style={{
                  fontSize: '16px',
                  fontWeight: 600,
                  color: '#000000',
                  fontFamily: '"Work Sans", sans-serif',
                  marginBottom: '16px',
                  borderBottom: '1px solid #E2E8F0',
                  paddingBottom: '8px'
                }}
              >
                Application Materials
              </h3>

              <div style={{ marginBottom: '12px' }}>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, color: '#000000', fontFamily: '"Work Sans", sans-serif', marginBottom: '6px' }}>
                  Resume/CV <span style={{ color: '#EF4444' }}>*</span> <span style={{ color: '#64748B', fontWeight: 400 }}>(PDF, DOC, or DOCX - Max 5MB)</span>
                </label>
                <input
                  type="file"
                  accept=".pdf,.doc,.docx"
                  onChange={(e) => handleFileChange(e, 'resume')}
                  style={{ display: 'none' }}
                  id="resume-upload"
                />
                <button
                  onClick={() => document.getElementById('resume-upload')?.click()}
                  style={{
                    width: '100%',
                    padding: '10px 12px',
                    border: '1px solid #E2E8F0',
                    borderRadius: '6px',
                    backgroundColor: '#F9FAFB',
                    fontSize: '14px',
                    fontFamily: '"Work Sans", sans-serif',
                    cursor: 'pointer',
                    textAlign: 'left',
                    color: resumeFile ? '#000000' : '#64748B'
                  }}
                >
                  {resumeFile ? resumeFile.name : 'Click to upload resume'}
                </button>
              </div>

              <div style={{ marginBottom: '12px' }}>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, color: '#000000', fontFamily: '"Work Sans", sans-serif', marginBottom: '6px' }}>
                  Transcript <span style={{ color: '#64748B', fontWeight: 400 }}>(Optional - PDF, Max 5MB)</span>
                </label>
                <input
                  type="file"
                  accept=".pdf"
                  onChange={(e) => handleFileChange(e, 'transcript')}
                  style={{ display: 'none' }}
                  id="transcript-upload"
                />
                <button
                  onClick={() => document.getElementById('transcript-upload')?.click()}
                  style={{
                    width: '100%',
                    padding: '10px 12px',
                    border: '1px solid #E2E8F0',
                    borderRadius: '6px',
                    backgroundColor: '#F9FAFB',
                    fontSize: '14px',
                    fontFamily: '"Work Sans", sans-serif',
                    cursor: 'pointer',
                    textAlign: 'left',
                    color: transcriptFile ? '#000000' : '#64748B'
                  }}
                >
                  {transcriptFile ? transcriptFile.name : 'Click to upload transcript (optional)'}
                </button>
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, color: '#000000', fontFamily: '"Work Sans", sans-serif', marginBottom: '6px' }}>
                  Statement of Interest <span style={{ color: '#EF4444' }}>*</span>
                </label>
                <textarea
                  value={coverLetter}
                  onChange={(e) => setCoverLetter(e.target.value)}
                  placeholder="Explain why you're interested in this lab and what skills/experience you bring..."
                  style={{
                    width: '100%',
                    height: '120px',
                    padding: '10px 12px',
                    border: '1px solid #E2E8F0',
                    borderRadius: '6px',
                    fontSize: '14px',
                    fontFamily: '"Work Sans", sans-serif',
                    resize: 'vertical',
                    outline: 'none'
                  }}
                />
              </div>
            </div>

            {/* Availability */}
            <div style={{ marginBottom: '24px' }}>
              <h3
                style={{
                  fontSize: '16px',
                  fontWeight: 600,
                  color: '#000000',
                  fontFamily: '"Work Sans", sans-serif',
                  marginBottom: '16px',
                  borderBottom: '1px solid #E2E8F0',
                  paddingBottom: '8px'
                }}
              >
                Availability <span style={{ color: '#EF4444', fontSize: '13px', fontWeight: 400 }}>*</span>
              </h3>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '8px' }}>
                {['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'].map(day => (
                  <button
                    key={day}
                    onClick={() => toggleAvailability(day)}
                    style={{
                      padding: '10px',
                      border: `1px solid ${availability.includes(day) ? '#C4A574' : '#E2E8F0'}`,
                      borderRadius: '6px',
                      backgroundColor: availability.includes(day) ? '#C4A574' : '#FFFFFF',
                      color: '#000000',
                      fontSize: '13px',
                      fontFamily: '"Work Sans", sans-serif',
                      cursor: 'pointer',
                      fontWeight: availability.includes(day) ? 500 : 400
                    }}
                  >
                    {day}
                  </button>
                ))}
              </div>
            </div>

            {/* Skills & Experience */}
            <div style={{ marginBottom: '24px' }}>
              <h3
                style={{
                  fontSize: '16px',
                  fontWeight: 600,
                  color: '#000000',
                  fontFamily: '"Work Sans", sans-serif',
                  marginBottom: '16px',
                  borderBottom: '1px solid #E2E8F0',
                  paddingBottom: '8px'
                }}
              >
                Skills & Experience <span style={{ color: '#EF4444', fontSize: '13px', fontWeight: 400 }}>*</span>
              </h3>

              <textarea
                value={skills}
                onChange={(e) => setSkills(e.target.value)}
                placeholder="List relevant skills, coursework, previous research experience, or technical expertise..."
                style={{
                  width: '100%',
                  height: '100px',
                  padding: '10px 12px',
                  border: '1px solid #E2E8F0',
                  borderRadius: '6px',
                  fontSize: '14px',
                  fontFamily: '"Work Sans", sans-serif',
                  resize: 'vertical',
                  outline: 'none'
                }}
              />
            </div>

            {/* References */}
            <div style={{ marginBottom: '24px' }}>
              <h3
                style={{
                  fontSize: '16px',
                  fontWeight: 600,
                  color: '#000000',
                  fontFamily: '"Work Sans", sans-serif',
                  marginBottom: '16px',
                  borderBottom: '1px solid #E2E8F0',
                  paddingBottom: '8px'
                }}
              >
                References <span style={{ color: '#64748B', fontSize: '13px', fontWeight: 400 }}>(Optional)</span>
              </h3>

              <textarea
                value={references}
                onChange={(e) => setReferences(e.target.value)}
                placeholder="List any professors or mentors who can speak to your qualifications (name, title, email)..."
                style={{
                  width: '100%',
                  height: '80px',
                  padding: '10px 12px',
                  border: '1px solid #E2E8F0',
                  borderRadius: '6px',
                  fontSize: '14px',
                  fontFamily: '"Work Sans", sans-serif',
                  resize: 'vertical',
                  outline: 'none'
                }}
              />
            </div>

            {/* Submit Buttons */}
            <div style={{ display: 'flex', gap: '12px' }}>
              <button
                onClick={handleSubmitApplication}
                disabled={!isFormValid()}
                style={{
                  flex: 1,
                  padding: '12px',
                  backgroundColor: isFormValid() ? '#64748B' : '#E2E8F0',
                  color: '#FFFFFF',
                  fontFamily: '"Work Sans", sans-serif',
                  fontSize: '16px',
                  fontWeight: 600,
                  border: 'none',
                  borderRadius: '8px',
                  cursor: isFormValid() ? 'pointer' : 'not-allowed'
                }}
              >
                Submit Application
              </button>
              <button
                onClick={() => setShowApplicationModal(false)}
                style={{
                  flex: 1,
                  padding: '12px',
                  backgroundColor: 'transparent',
                  color: '#000000',
                  fontFamily: '"Work Sans", sans-serif',
                  fontSize: '16px',
                  fontWeight: 500,
                  border: '1px solid #E2E8F0',
                  borderRadius: '8px',
                  cursor: 'pointer'
                }}
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
