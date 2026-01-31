'use client'

import React, { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'

export default function ProfilePage() {
  const router = useRouter()
  const [isEditing, setIsEditing] = useState(false)
  const [showSuccessMessage, setShowSuccessMessage] = useState(false)
  const [errorMessage, setErrorMessage] = useState('')

  // Profile state
  const [fullName, setFullName] = useState('Jane Doe')
  const [email, setEmail] = useState('jane.doe@ucla.edu')
  const [phone, setPhone] = useState('(310) 555-0123')
  const [major, setMajor] = useState('Computer Science')
  const [year, setYear] = useState('Junior')
  const [gpa, setGpa] = useState('3.85')
  const [graduationDate, setGraduationDate] = useState('June 2026')
  const [bio, setBio] = useState('Passionate about machine learning and computational biology. Seeking research opportunities to apply my technical skills.')
  const [skills, setSkills] = useState('Python, R, Machine Learning, Data Analysis, Git')
  const [interests, setInterests] = useState('Computational Biology, AI/ML, Bioinformatics')
  const [resumeFile, setResumeFile] = useState<File | null>(null)
  const [transcriptFile, setTranscriptFile] = useState<File | null>(null)
  const [savedResumeFileName, setSavedResumeFileName] = useState<string | null>(null)
  const [savedTranscriptFileName, setSavedTranscriptFileName] = useState<string | null>(null)

  // Load profile data from localStorage on mount
  useEffect(() => {
    if (typeof window !== 'undefined') {
      const saved = localStorage.getItem('profileData')
      if (saved) {
        const profile = JSON.parse(saved)
        if (profile.fullName) setFullName(profile.fullName)
        if (profile.email) setEmail(profile.email)
        if (profile.phone) setPhone(profile.phone)
        if (profile.major) setMajor(profile.major)
        if (profile.year) setYear(profile.year)
        if (profile.gpa) setGpa(profile.gpa)
        if (profile.graduationDate) setGraduationDate(profile.graduationDate)
        if (profile.bio) setBio(profile.bio)
        if (profile.skills) setSkills(profile.skills)
        if (profile.interests) setInterests(profile.interests)
        if (profile.resumeFileName) setSavedResumeFileName(profile.resumeFileName)
        if (profile.transcriptFileName) setSavedTranscriptFileName(profile.transcriptFileName)
      }
    }
  }, [])

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>, type: 'resume' | 'transcript') => {
    const file = e.target.files?.[0]
    if (file) {
      // Check file type
      if (!file.name.endsWith('.pdf')) {
        setErrorMessage('Please upload a PDF file')
        setTimeout(() => setErrorMessage(''), 3000)
        return
      }
      // Check file size (5MB limit)
      if (file.size > 5 * 1024 * 1024) {
        setErrorMessage('File size must be less than 5MB')
        setTimeout(() => setErrorMessage(''), 3000)
        return
      }
      if (type === 'resume') {
        setResumeFile(file)
      } else {
        setTranscriptFile(file)
      }
    }
  }

  const fileToBase64 = (file: File): Promise<string> => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader()
      reader.readAsDataURL(file)
      reader.onload = () => {
        const result = reader.result as string
        const base64 = result.split(',')[1]
        resolve(base64)
      }
      reader.onerror = error => reject(error)
    })
  }

  const handleSaveProfile = async () => {
    // Convert resume and transcript to base64 if they exist
    let resumeData = null
    let resumeFileName = null
    let transcriptData = null
    let transcriptFileName = null

    if (resumeFile) {
      resumeData = await fileToBase64(resumeFile)
      resumeFileName = resumeFile.name
    }

    if (transcriptFile) {
      transcriptData = await fileToBase64(transcriptFile)
      transcriptFileName = transcriptFile.name
    }

    // Save profile data to localStorage
    const profileData = {
      fullName,
      email,
      phone,
      university: 'UCLA',
      major,
      year,
      gpa,
      graduationDate,
      bio,
      skills,
      interests,
      resumeData,
      resumeFileName,
      transcriptData,
      transcriptFileName,
      lastUpdated: new Date().toISOString()
    }
    localStorage.setItem('profileData', JSON.stringify(profileData))

    setIsEditing(false)
    setShowSuccessMessage(true)

    // Hide success message after 3 seconds
    setTimeout(() => {
      setShowSuccessMessage(false)
    }, 3000)
  }

  const handleSignOut = () => {
    if (typeof window !== 'undefined') {
      localStorage.removeItem('isAuthenticated')
      localStorage.removeItem('userType')
    }
    router.push('/login')
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
          Profile updated successfully!
        </div>
      )}

      {/* Error Message */}
      {errorMessage && (
        <div
          style={{
            position: 'fixed',
            top: '24px',
            right: '24px',
            backgroundColor: '#EF4444',
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
          {errorMessage}
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
            style={{
              padding: '12px 24px',
              backgroundColor: '#C4A574',
              color: '#000000',
              fontFamily: '"Work Sans", sans-serif',
              fontSize: '15px',
              fontWeight: 500,
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

      {/* Main Content */}
      <div style={{ flex: 1, backgroundColor: '#FFFFFF', overflow: 'auto', padding: '40px' }}>
        <div style={{ maxWidth: '800px' }}>
          {/* Header */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '32px' }}>
            <h1
              style={{
                fontSize: '32px',
                fontWeight: 700,
                color: '#000000',
                fontFamily: '"Work Sans", sans-serif'
              }}
            >
              My Profile
            </h1>
            {!isEditing ? (
              <button
                onClick={() => setIsEditing(true)}
                style={{
                  padding: '12px 24px',
                  backgroundColor: '#1E1E1E',
                  color: '#FFFFFF',
                  fontFamily: '"Work Sans", sans-serif',
                  fontSize: '15px',
                  fontWeight: 500,
                  border: 'none',
                  borderRadius: '8px',
                  cursor: 'pointer'
                }}
              >
                Edit Profile
              </button>
            ) : (
              <div style={{ display: 'flex', gap: '12px' }}>
                <button
                  onClick={handleSaveProfile}
                  style={{
                    padding: '12px 24px',
                    backgroundColor: '#1E1E1E',
                    color: '#FFFFFF',
                    fontFamily: '"Work Sans", sans-serif',
                    fontSize: '15px',
                    fontWeight: 500,
                    border: 'none',
                    borderRadius: '8px',
                    cursor: 'pointer'
                  }}
                >
                  Save Changes
                </button>
                <button
                  onClick={() => setIsEditing(false)}
                  style={{
                    padding: '12px 24px',
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
                  Cancel
                </button>
              </div>
            )}
          </div>

          {/* Personal Information */}
          <div style={{ marginBottom: '32px' }}>
            <h2
              style={{
                fontSize: '20px',
                fontWeight: 600,
                color: '#000000',
                fontFamily: '"Work Sans", sans-serif',
                marginBottom: '20px',
                borderBottom: '2px solid #E2E8F0',
                paddingBottom: '12px'
              }}
            >
              Personal Information
            </h2>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px', marginBottom: '20px' }}>
              <div>
                <label style={{ display: 'block', fontSize: '14px', fontWeight: 500, color: '#64748B', fontFamily: '"Work Sans", sans-serif', marginBottom: '8px' }}>
                  Full Name
                </label>
                {isEditing ? (
                  <input
                    type="text"
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                    style={{ width: '100%', padding: '12px', border: '1px solid #E2E8F0', borderRadius: '6px', fontSize: '15px', fontFamily: '"Work Sans", sans-serif', outline: 'none' }}
                  />
                ) : (
                  <p style={{ fontSize: '16px', color: '#000000', fontFamily: '"Work Sans", sans-serif' }}>{fullName}</p>
                )}
              </div>
              <div>
                <label style={{ display: 'block', fontSize: '14px', fontWeight: 500, color: '#64748B', fontFamily: '"Work Sans", sans-serif', marginBottom: '8px' }}>
                  Email
                </label>
                {isEditing ? (
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    style={{ width: '100%', padding: '12px', border: '1px solid #E2E8F0', borderRadius: '6px', fontSize: '15px', fontFamily: '"Work Sans", sans-serif', outline: 'none' }}
                  />
                ) : (
                  <p style={{ fontSize: '16px', color: '#000000', fontFamily: '"Work Sans", sans-serif' }}>{email}</p>
                )}
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
              <div>
                <label style={{ display: 'block', fontSize: '14px', fontWeight: 500, color: '#64748B', fontFamily: '"Work Sans", sans-serif', marginBottom: '8px' }}>
                  Phone Number
                </label>
                {isEditing ? (
                  <input
                    type="tel"
                    value={phone}
                    onChange={(e) => setPhone(e.target.value)}
                    style={{ width: '100%', padding: '12px', border: '1px solid #E2E8F0', borderRadius: '6px', fontSize: '15px', fontFamily: '"Work Sans", sans-serif', outline: 'none' }}
                  />
                ) : (
                  <p style={{ fontSize: '16px', color: '#000000', fontFamily: '"Work Sans", sans-serif' }}>{phone}</p>
                )}
              </div>
            </div>
          </div>

          {/* Academic Information */}
          <div style={{ marginBottom: '32px' }}>
            <h2
              style={{
                fontSize: '20px',
                fontWeight: 600,
                color: '#000000',
                fontFamily: '"Work Sans", sans-serif',
                marginBottom: '20px',
                borderBottom: '2px solid #E2E8F0',
                paddingBottom: '12px'
              }}
            >
              Academic Information
            </h2>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px', marginBottom: '20px' }}>
              <div>
                <label style={{ display: 'block', fontSize: '14px', fontWeight: 500, color: '#64748B', fontFamily: '"Work Sans", sans-serif', marginBottom: '8px' }}>
                  Major
                </label>
                {isEditing ? (
                  <input
                    type="text"
                    value={major}
                    onChange={(e) => setMajor(e.target.value)}
                    style={{ width: '100%', padding: '12px', border: '1px solid #E2E8F0', borderRadius: '6px', fontSize: '15px', fontFamily: '"Work Sans", sans-serif', outline: 'none' }}
                  />
                ) : (
                  <p style={{ fontSize: '16px', color: '#000000', fontFamily: '"Work Sans", sans-serif' }}>{major}</p>
                )}
              </div>
              <div>
                <label style={{ display: 'block', fontSize: '14px', fontWeight: 500, color: '#64748B', fontFamily: '"Work Sans", sans-serif', marginBottom: '8px' }}>
                  Year
                </label>
                {isEditing ? (
                  <select
                    value={year}
                    onChange={(e) => setYear(e.target.value)}
                    style={{ width: '100%', padding: '12px', border: '1px solid #E2E8F0', borderRadius: '6px', fontSize: '15px', fontFamily: '"Work Sans", sans-serif', outline: 'none' }}
                  >
                    <option>Freshman</option>
                    <option>Sophomore</option>
                    <option>Junior</option>
                    <option>Senior</option>
                    <option>Graduate</option>
                  </select>
                ) : (
                  <p style={{ fontSize: '16px', color: '#000000', fontFamily: '"Work Sans", sans-serif' }}>{year}</p>
                )}
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
              <div>
                <label style={{ display: 'block', fontSize: '14px', fontWeight: 500, color: '#64748B', fontFamily: '"Work Sans", sans-serif', marginBottom: '8px' }}>
                  GPA
                </label>
                {isEditing ? (
                  <input
                    type="text"
                    value={gpa}
                    onChange={(e) => setGpa(e.target.value)}
                    style={{ width: '100%', padding: '12px', border: '1px solid #E2E8F0', borderRadius: '6px', fontSize: '15px', fontFamily: '"Work Sans", sans-serif', outline: 'none' }}
                  />
                ) : (
                  <p style={{ fontSize: '16px', color: '#000000', fontFamily: '"Work Sans", sans-serif' }}>{gpa}</p>
                )}
              </div>
              <div>
                <label style={{ display: 'block', fontSize: '14px', fontWeight: 500, color: '#64748B', fontFamily: '"Work Sans", sans-serif', marginBottom: '8px' }}>
                  Expected Graduation
                </label>
                {isEditing ? (
                  <input
                    type="text"
                    value={graduationDate}
                    onChange={(e) => setGraduationDate(e.target.value)}
                    style={{ width: '100%', padding: '12px', border: '1px solid #E2E8F0', borderRadius: '6px', fontSize: '15px', fontFamily: '"Work Sans", sans-serif', outline: 'none' }}
                  />
                ) : (
                  <p style={{ fontSize: '16px', color: '#000000', fontFamily: '"Work Sans", sans-serif' }}>{graduationDate}</p>
                )}
              </div>
            </div>
          </div>

          {/* Documents */}
          <div style={{ marginBottom: '32px' }}>
            <h2
              style={{
                fontSize: '20px',
                fontWeight: 600,
                color: '#000000',
                fontFamily: '"Work Sans", sans-serif',
                marginBottom: '20px',
                borderBottom: '2px solid #E2E8F0',
                paddingBottom: '12px'
              }}
            >
              Documents
            </h2>

            <div style={{ marginBottom: '20px' }}>
              <label style={{ display: 'block', fontSize: '14px', fontWeight: 500, color: '#64748B', fontFamily: '"Work Sans", sans-serif', marginBottom: '8px' }}>
                Resume (PDF)
              </label>
              {isEditing ? (
                <div>
                  <input
                    type="file"
                    accept=".pdf"
                    onChange={(e) => handleFileChange(e, 'resume')}
                    style={{ display: 'none' }}
                    id="resume-upload-profile"
                  />
                  <button
                    onClick={() => document.getElementById('resume-upload-profile')?.click()}
                    style={{
                      width: '100%',
                      padding: '12px',
                      border: '1px solid #E2E8F0',
                      borderRadius: '6px',
                      backgroundColor: '#F9FAFB',
                      fontSize: '15px',
                      fontFamily: '"Work Sans", sans-serif',
                      cursor: 'pointer',
                      textAlign: 'left',
                      color: resumeFile ? '#000000' : '#64748B'
                    }}
                  >
                    {resumeFile ? `📄 ${resumeFile.name}` : 'Click to upload resume (PDF, Max 5MB)'}
                  </button>
                </div>
              ) : (
                <div
                  style={{
                    padding: '12px 16px',
                    backgroundColor: '#F9FAFB',
                    border: '1px solid #E2E8F0',
                    borderRadius: '6px',
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '8px'
                  }}
                >
                  <svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path d="M9 2H4C3.46957 2 2.96086 2.21071 2.58579 2.58579C2.21071 2.96086 2 3.46957 2 4V12C2 12.5304 2.21071 13.0391 2.58579 13.4142C2.96086 13.7893 3.46957 14 4 14H12C12.5304 14 13.0391 13.7893 13.4142 13.4142C13.7893 13.0391 14 12.5304 14 12V7M13 1L8 6M13 1V4M13 1H10" stroke="#64748B" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
                  </svg>
                  <span style={{ fontSize: '15px', color: '#000000', fontFamily: '"Work Sans", sans-serif' }}>
                    {resumeFile ? resumeFile.name : 'Resume.pdf'}
                  </span>
                </div>
              )}
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '14px', fontWeight: 500, color: '#64748B', fontFamily: '"Work Sans", sans-serif', marginBottom: '8px' }}>
                Transcript (PDF) <span style={{ fontSize: '13px', fontWeight: 400 }}>- Optional</span>
              </label>
              {isEditing ? (
                <div>
                  <input
                    type="file"
                    accept=".pdf"
                    onChange={(e) => handleFileChange(e, 'transcript')}
                    style={{ display: 'none' }}
                    id="transcript-upload-profile"
                  />
                  <button
                    onClick={() => document.getElementById('transcript-upload-profile')?.click()}
                    style={{
                      width: '100%',
                      padding: '12px',
                      border: '1px solid #E2E8F0',
                      borderRadius: '6px',
                      backgroundColor: '#F9FAFB',
                      fontSize: '15px',
                      fontFamily: '"Work Sans", sans-serif',
                      cursor: 'pointer',
                      textAlign: 'left',
                      color: transcriptFile ? '#000000' : '#64748B'
                    }}
                  >
                    {transcriptFile ? `📄 ${transcriptFile.name}` : 'Click to upload transcript (PDF, Max 5MB)'}
                  </button>
                </div>
              ) : (
                <div>
                  {transcriptFile ? (
                    <div
                      style={{
                        padding: '12px 16px',
                        backgroundColor: '#F9FAFB',
                        border: '1px solid #E2E8F0',
                        borderRadius: '6px',
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '8px'
                      }}
                    >
                      <svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
                        <path d="M9 2H4C3.46957 2 2.96086 2.21071 2.58579 2.58579C2.21071 2.96086 2 3.46957 2 4V12C2 12.5304 2.21071 13.0391 2.58579 13.4142C2.96086 13.7893 3.46957 14 4 14H12C12.5304 14 13.0391 13.7893 13.4142 13.4142C13.7893 13.0391 14 12.5304 14 12V7M13 1L8 6M13 1V4M13 1H10" stroke="#64748B" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
                      </svg>
                      <span style={{ fontSize: '15px', color: '#000000', fontFamily: '"Work Sans", sans-serif' }}>
                        {transcriptFile.name}
                      </span>
                    </div>
                  ) : (
                    <p style={{ fontSize: '15px', color: '#94A3B8', fontFamily: '"Work Sans", sans-serif' }}>
                      No transcript uploaded
                    </p>
                  )}
                </div>
              )}
            </div>
          </div>

          {/* About Me */}
          <div style={{ marginBottom: '32px' }}>
            <h2
              style={{
                fontSize: '20px',
                fontWeight: 600,
                color: '#000000',
                fontFamily: '"Work Sans", sans-serif',
                marginBottom: '20px',
                borderBottom: '2px solid #E2E8F0',
                paddingBottom: '12px'
              }}
            >
              About Me
            </h2>

            <div style={{ marginBottom: '20px' }}>
              <label style={{ display: 'block', fontSize: '14px', fontWeight: 500, color: '#64748B', fontFamily: '"Work Sans", sans-serif', marginBottom: '8px' }}>
                Bio
              </label>
              {isEditing ? (
                <textarea
                  value={bio}
                  onChange={(e) => setBio(e.target.value)}
                  style={{ width: '100%', height: '100px', padding: '12px', border: '1px solid #E2E8F0', borderRadius: '6px', fontSize: '15px', fontFamily: '"Work Sans", sans-serif', resize: 'vertical', outline: 'none' }}
                />
              ) : (
                <p style={{ fontSize: '16px', color: '#000000', fontFamily: '"Work Sans", sans-serif', lineHeight: '1.6' }}>{bio}</p>
              )}
            </div>

            <div style={{ marginBottom: '20px' }}>
              <label style={{ display: 'block', fontSize: '14px', fontWeight: 500, color: '#64748B', fontFamily: '"Work Sans", sans-serif', marginBottom: '8px' }}>
                Skills
              </label>
              {isEditing ? (
                <textarea
                  value={skills}
                  onChange={(e) => setSkills(e.target.value)}
                  style={{ width: '100%', height: '80px', padding: '12px', border: '1px solid #E2E8F0', borderRadius: '6px', fontSize: '15px', fontFamily: '"Work Sans", sans-serif', resize: 'vertical', outline: 'none' }}
                />
              ) : (
                <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                  {skills.split(',').map((skill, idx) => (
                    <span
                      key={idx}
                      style={{
                        padding: '6px 14px',
                        backgroundColor: '#C4A574',
                        color: '#000000',
                        borderRadius: '14px',
                        fontSize: '14px',
                        fontFamily: '"Work Sans", sans-serif'
                      }}
                    >
                      {skill.trim()}
                    </span>
                  ))}
                </div>
              )}
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '14px', fontWeight: 500, color: '#64748B', fontFamily: '"Work Sans", sans-serif', marginBottom: '8px' }}>
                Research Interests
              </label>
              {isEditing ? (
                <textarea
                  value={interests}
                  onChange={(e) => setInterests(e.target.value)}
                  style={{ width: '100%', height: '80px', padding: '12px', border: '1px solid #E2E8F0', borderRadius: '6px', fontSize: '15px', fontFamily: '"Work Sans", sans-serif', resize: 'vertical', outline: 'none' }}
                />
              ) : (
                <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                  {interests.split(',').map((interest, idx) => (
                    <span
                      key={idx}
                      style={{
                        padding: '6px 14px',
                        backgroundColor: '#E0E7FF',
                        color: '#3730A3',
                        borderRadius: '14px',
                        fontSize: '14px',
                        fontFamily: '"Work Sans", sans-serif'
                      }}
                    >
                      {interest.trim()}
                    </span>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
