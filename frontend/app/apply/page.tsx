'use client'

import React, { useState, useEffect } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'

export default function ApplyPage() {
  const router = useRouter()
  const searchParams = useSearchParams()
  const labName = searchParams.get('lab') || 'Research Lab'

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
  const [hoursPerWeek, setHoursPerWeek] = useState('')
  const [skills, setSkills] = useState('')
  const [references, setReferences] = useState('')

  // Load profile data from localStorage
  useEffect(() => {
    if (typeof window !== 'undefined') {
      const profileData = localStorage.getItem('profileData')
      if (profileData) {
        const profile = JSON.parse(profileData)
        setFullName(profile.fullName || '')
        setEmail(profile.email || '')
        setPhone(profile.phone || '')
        setUniversity(profile.university || 'UCLA')
        setMajor(profile.major || '')
        setGpa(profile.gpa || '')
        setGraduationDate(profile.graduationDate || '')
        setSkills(profile.skills || '')
        // Note: Files can't be restored from localStorage
      }
    }
  }, [])

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>, type: 'resume' | 'transcript') => {
    const file = e.target.files?.[0]
    if (file) {
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

  const fileToBase64 = (file: File): Promise<string> => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader()
      reader.readAsDataURL(file)
      reader.onload = () => {
        const result = reader.result as string
        // Remove the data:application/pdf;base64, prefix
        const base64 = result.split(',')[1]
        resolve(base64)
      }
      reader.onerror = error => reject(error)
    })
  }

  const handleSubmitApplication = async () => {
    if (!resumeFile) return

    // Convert resume to base64
    const resumeBase64 = await fileToBase64(resumeFile)

    // Create application data
    const applicationData = {
      id: Date.now().toString(),
      studentName: fullName,
      email,
      phone,
      labName,
      major,
      gpa,
      graduationDate,
      appliedDate: new Date().toISOString(),
      status: 'pending',
      coverLetter,
      skills,
      availability,
      hoursPerWeek,
      references,
      resumeData: resumeBase64,
      resumeFileName: resumeFile.name,
      transcriptData: transcriptFile ? await fileToBase64(transcriptFile) : undefined,
      transcriptFileName: transcriptFile?.name
    }

    // Store application in localStorage
    const existingApplications = JSON.parse(localStorage.getItem('applications') || '[]')
    existingApplications.push(applicationData)
    localStorage.setItem('applications', JSON.stringify(existingApplications))

    setShowSuccessMessage(true)

    // Redirect back to dashboard after 2 seconds
    setTimeout(() => {
      router.push('/student/dashboard')
    }, 2000)
  }

  const isFormValid = () => {
    return fullName.trim() && email.trim() && phone.trim() && major.trim() &&
           gpa.trim() && graduationDate.trim() && resumeFile && coverLetter.trim() &&
           availability.length > 0 && hoursPerWeek.trim() && skills.trim()
  }

  return (
    <div style={{ display: 'flex', width: '100vw', minHeight: '100vh', backgroundColor: '#A8A8A8' }}>
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
          padding: '24px 0',
          position: 'sticky',
          top: 0,
          height: '100vh'
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

        {/* Back Button */}
        <button
          onClick={() => router.push('/student/dashboard')}
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
          ← Back to Labs
        </button>
      </div>

      {/* Main Content */}
      <div style={{ flex: 1, backgroundColor: '#FFFFFF', overflow: 'auto', padding: '40px' }}>
        <div style={{ maxWidth: '800px', margin: '0 auto' }}>
          {/* Header */}
          <h1
            style={{
              fontSize: '32px',
              fontWeight: 700,
              color: '#000000',
              fontFamily: '"Work Sans", sans-serif',
              marginBottom: '8px'
            }}
          >
            Apply to {labName}
          </h1>
          <p
            style={{
              fontSize: '16px',
              color: '#64748B',
              fontFamily: '"Work Sans", sans-serif',
              marginBottom: '32px'
            }}
          >
            Complete the application form below. Fields marked with * are required.
          </p>

          {/* Personal Information Section */}
          <div style={{ marginBottom: '32px' }}>
            <h3
              style={{
                fontSize: '18px',
                fontWeight: 600,
                color: '#000000',
                fontFamily: '"Work Sans", sans-serif',
                marginBottom: '16px',
                borderBottom: '2px solid #E2E8F0',
                paddingBottom: '8px'
              }}
            >
              Personal Information
            </h3>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginBottom: '16px' }}>
              <div>
                <label style={{ display: 'block', fontSize: '14px', fontWeight: 500, color: '#000000', fontFamily: '"Work Sans", sans-serif', marginBottom: '6px' }}>
                  Full Name <span style={{ color: '#EF4444' }}>*</span>
                </label>
                <input
                  type="text"
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  placeholder="Jane Doe"
                  style={{ width: '100%', padding: '12px', border: '1px solid #E2E8F0', borderRadius: '6px', fontSize: '15px', fontFamily: '"Work Sans", sans-serif', outline: 'none' }}
                />
              </div>
              <div>
                <label style={{ display: 'block', fontSize: '14px', fontWeight: 500, color: '#000000', fontFamily: '"Work Sans", sans-serif', marginBottom: '6px' }}>
                  Email <span style={{ color: '#EF4444' }}>*</span>
                </label>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="jane.doe@ucla.edu"
                  style={{ width: '100%', padding: '12px', border: '1px solid #E2E8F0', borderRadius: '6px', fontSize: '15px', fontFamily: '"Work Sans", sans-serif', outline: 'none' }}
                />
              </div>
            </div>

            <div style={{ marginBottom: '16px' }}>
              <label style={{ display: 'block', fontSize: '14px', fontWeight: 500, color: '#000000', fontFamily: '"Work Sans", sans-serif', marginBottom: '6px' }}>
                Phone Number <span style={{ color: '#EF4444' }}>*</span>
              </label>
              <input
                type="tel"
                value={phone}
                onChange={(e) => setPhone(e.target.value)}
                placeholder="(310) 555-0123"
                style={{ width: '100%', padding: '12px', border: '1px solid #E2E8F0', borderRadius: '6px', fontSize: '15px', fontFamily: '"Work Sans", sans-serif', outline: 'none' }}
              />
            </div>
          </div>

          {/* Education Section */}
          <div style={{ marginBottom: '32px' }}>
            <h3
              style={{
                fontSize: '18px',
                fontWeight: 600,
                color: '#000000',
                fontFamily: '"Work Sans", sans-serif',
                marginBottom: '16px',
                borderBottom: '2px solid #E2E8F0',
                paddingBottom: '8px'
              }}
            >
              Education
            </h3>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginBottom: '16px' }}>
              <div>
                <label style={{ display: 'block', fontSize: '14px', fontWeight: 500, color: '#000000', fontFamily: '"Work Sans", sans-serif', marginBottom: '6px' }}>
                  University <span style={{ color: '#EF4444' }}>*</span>
                </label>
                <input
                  type="text"
                  value={university}
                  onChange={(e) => setUniversity(e.target.value)}
                  style={{ width: '100%', padding: '12px', border: '1px solid #E2E8F0', borderRadius: '6px', fontSize: '15px', fontFamily: '"Work Sans", sans-serif', outline: 'none' }}
                />
              </div>
              <div>
                <label style={{ display: 'block', fontSize: '14px', fontWeight: 500, color: '#000000', fontFamily: '"Work Sans", sans-serif', marginBottom: '6px' }}>
                  Major <span style={{ color: '#EF4444' }}>*</span>
                </label>
                <input
                  type="text"
                  value={major}
                  onChange={(e) => setMajor(e.target.value)}
                  placeholder="Computer Science"
                  style={{ width: '100%', padding: '12px', border: '1px solid #E2E8F0', borderRadius: '6px', fontSize: '15px', fontFamily: '"Work Sans", sans-serif', outline: 'none' }}
                />
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
              <div>
                <label style={{ display: 'block', fontSize: '14px', fontWeight: 500, color: '#000000', fontFamily: '"Work Sans", sans-serif', marginBottom: '6px' }}>
                  GPA <span style={{ color: '#EF4444' }}>*</span>
                </label>
                <input
                  type="text"
                  value={gpa}
                  onChange={(e) => setGpa(e.target.value)}
                  placeholder="3.85"
                  style={{ width: '100%', padding: '12px', border: '1px solid #E2E8F0', borderRadius: '6px', fontSize: '15px', fontFamily: '"Work Sans", sans-serif', outline: 'none' }}
                />
              </div>
              <div>
                <label style={{ display: 'block', fontSize: '14px', fontWeight: 500, color: '#000000', fontFamily: '"Work Sans", sans-serif', marginBottom: '6px' }}>
                  Expected Graduation <span style={{ color: '#EF4444' }}>*</span>
                </label>
                <input
                  type="text"
                  value={graduationDate}
                  onChange={(e) => setGraduationDate(e.target.value)}
                  placeholder="June 2026"
                  style={{ width: '100%', padding: '12px', border: '1px solid #E2E8F0', borderRadius: '6px', fontSize: '15px', fontFamily: '"Work Sans", sans-serif', outline: 'none' }}
                />
              </div>
            </div>
          </div>

          {/* Application Materials */}
          <div style={{ marginBottom: '32px' }}>
            <h3
              style={{
                fontSize: '18px',
                fontWeight: 600,
                color: '#000000',
                fontFamily: '"Work Sans", sans-serif',
                marginBottom: '16px',
                borderBottom: '2px solid #E2E8F0',
                paddingBottom: '8px'
              }}
            >
              Application Materials
            </h3>

            <div style={{ marginBottom: '16px' }}>
              <label style={{ display: 'block', fontSize: '14px', fontWeight: 500, color: '#000000', fontFamily: '"Work Sans", sans-serif', marginBottom: '6px' }}>
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
                {resumeFile ? resumeFile.name : 'Click to upload resume'}
              </button>
            </div>

            <div style={{ marginBottom: '16px' }}>
              <label style={{ display: 'block', fontSize: '14px', fontWeight: 500, color: '#000000', fontFamily: '"Work Sans", sans-serif', marginBottom: '6px' }}>
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
                {transcriptFile ? transcriptFile.name : 'Click to upload transcript (optional)'}
              </button>
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '14px', fontWeight: 500, color: '#000000', fontFamily: '"Work Sans", sans-serif', marginBottom: '6px' }}>
                Statement of Interest <span style={{ color: '#EF4444' }}>*</span>
              </label>
              <textarea
                value={coverLetter}
                onChange={(e) => setCoverLetter(e.target.value)}
                placeholder="Explain why you're interested in this lab and what skills/experience you bring..."
                style={{
                  width: '100%',
                  height: '150px',
                  padding: '12px',
                  border: '1px solid #E2E8F0',
                  borderRadius: '6px',
                  fontSize: '15px',
                  fontFamily: '"Work Sans", sans-serif',
                  resize: 'vertical',
                  outline: 'none'
                }}
              />
            </div>
          </div>

          {/* Availability */}
          <div style={{ marginBottom: '32px' }}>
            <h3
              style={{
                fontSize: '18px',
                fontWeight: 600,
                color: '#000000',
                fontFamily: '"Work Sans", sans-serif',
                marginBottom: '16px',
                borderBottom: '2px solid #E2E8F0',
                paddingBottom: '8px'
              }}
            >
              Availability <span style={{ color: '#EF4444', fontSize: '14px', fontWeight: 400 }}>*</span>
            </h3>

            <div style={{ marginBottom: '20px' }}>
              <label style={{ display: 'block', fontSize: '14px', fontWeight: 500, color: '#000000', fontFamily: '"Work Sans", sans-serif', marginBottom: '8px' }}>
                Days Available
              </label>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '12px' }}>
                {['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'].map(day => (
                  <button
                    key={day}
                    onClick={() => toggleAvailability(day)}
                    style={{
                      padding: '12px',
                      border: `1px solid ${availability.includes(day) ? '#C4A574' : '#E2E8F0'}`,
                      borderRadius: '6px',
                      backgroundColor: availability.includes(day) ? '#C4A574' : '#FFFFFF',
                      color: '#000000',
                      fontSize: '14px',
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

            <div>
              <label style={{ display: 'block', fontSize: '14px', fontWeight: 500, color: '#000000', fontFamily: '"Work Sans", sans-serif', marginBottom: '6px' }}>
                Hours Available Per Week <span style={{ color: '#EF4444' }}>*</span>
              </label>
              <input
                type="number"
                value={hoursPerWeek}
                onChange={(e) => setHoursPerWeek(e.target.value)}
                placeholder="10-20 hours"
                min="1"
                max="40"
                style={{ width: '100%', padding: '12px', border: '1px solid #E2E8F0', borderRadius: '6px', fontSize: '15px', fontFamily: '"Work Sans", sans-serif', outline: 'none' }}
              />
            </div>
          </div>

          {/* Skills & Experience */}
          <div style={{ marginBottom: '32px' }}>
            <h3
              style={{
                fontSize: '18px',
                fontWeight: 600,
                color: '#000000',
                fontFamily: '"Work Sans", sans-serif',
                marginBottom: '16px',
                borderBottom: '2px solid #E2E8F0',
                paddingBottom: '8px'
              }}
            >
              Skills & Experience <span style={{ color: '#EF4444', fontSize: '14px', fontWeight: 400 }}>*</span>
            </h3>

            <textarea
              value={skills}
              onChange={(e) => setSkills(e.target.value)}
              placeholder="List relevant skills, coursework, previous research experience, or technical expertise..."
              style={{
                width: '100%',
                height: '120px',
                padding: '12px',
                border: '1px solid #E2E8F0',
                borderRadius: '6px',
                fontSize: '15px',
                fontFamily: '"Work Sans", sans-serif',
                resize: 'vertical',
                outline: 'none'
              }}
            />
          </div>

          {/* References */}
          <div style={{ marginBottom: '40px' }}>
            <h3
              style={{
                fontSize: '18px',
                fontWeight: 600,
                color: '#000000',
                fontFamily: '"Work Sans", sans-serif',
                marginBottom: '16px',
                borderBottom: '2px solid #E2E8F0',
                paddingBottom: '8px'
              }}
            >
              References <span style={{ color: '#64748B', fontSize: '14px', fontWeight: 400 }}>(Optional)</span>
            </h3>

            <textarea
              value={references}
              onChange={(e) => setReferences(e.target.value)}
              placeholder="List any professors or mentors who can speak to your qualifications (name, title, email)..."
              style={{
                width: '100%',
                height: '100px',
                padding: '12px',
                border: '1px solid #E2E8F0',
                borderRadius: '6px',
                fontSize: '15px',
                fontFamily: '"Work Sans", sans-serif',
                resize: 'vertical',
                outline: 'none'
              }}
            />
          </div>

          {/* Submit Button */}
          <div style={{ display: 'flex', gap: '16px' }}>
            <button
              onClick={handleSubmitApplication}
              disabled={!isFormValid()}
              style={{
                flex: 1,
                padding: '16px',
                backgroundColor: isFormValid() ? '#1E1E1E' : '#E2E8F0',
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
              onClick={() => router.push('/student/dashboard')}
              style={{
                padding: '16px 32px',
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
    </div>
  )
}
