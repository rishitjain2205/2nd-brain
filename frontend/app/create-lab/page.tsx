'use client'

import React, { useState } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'

export default function CreateLabPage() {
  const router = useRouter()

  // Lab Information
  const [title, setTitle] = useState('')
  const [department, setDepartment] = useState('')
  const [description, setDescription] = useState('')
  const [researchArea, setResearchArea] = useState('')

  // Requirements
  const [requirements, setRequirements] = useState<string[]>([''])
  const [skills, setSkills] = useState('')
  const [minGPA, setMinGPA] = useState('')
  const [preferredMajors, setPreferredMajors] = useState('')

  // Position Details
  const [hoursPerWeek, setHoursPerWeek] = useState('')
  const [duration, setDuration] = useState('')
  const [compensation, setCompensation] = useState('Academic Credit')
  const [location, setLocation] = useState('')
  const [isRemote, setIsRemote] = useState(false)

  // Application Details
  const [applicationDeadline, setApplicationDeadline] = useState('')
  const [maxApplicants, setMaxApplicants] = useState('')
  const [additionalInstructions, setAdditionalInstructions] = useState('')

  const [isSubmitting, setIsSubmitting] = useState(false)
  const [error, setError] = useState('')

  const addRequirement = () => {
    setRequirements([...requirements, ''])
  }

  const updateRequirement = (index: number, value: string) => {
    const newRequirements = [...requirements]
    newRequirements[index] = value
    setRequirements(newRequirements)
  }

  const removeRequirement = (index: number) => {
    setRequirements(requirements.filter((_, i) => i !== index))
  }

  const handleSubmit = async () => {
    setError('')
    setIsSubmitting(true)

    // Validation
    if (!title || !department || !description || !hoursPerWeek || !duration) {
      setError('Please fill in all required fields')
      setIsSubmitting(false)
      return
    }

    if (description.length < 100) {
      setError('Description must be at least 100 characters')
      setIsSubmitting(false)
      return
    }

    // TODO: Call backend API to create lab posting
    // For now, simulate success
    setTimeout(() => {
      // Redirect to my-labs with success message
      router.push('/my-labs?posted=true')
    }, 1500)
  }

  return (
    <div
      style={{
        width: '100vw',
        minHeight: '100vh',
        backgroundColor: '#F8FAFC'
      }}
    >
      {/* Header */}
      <div
        style={{
          backgroundColor: '#FFFFFF',
          borderBottom: '1px solid #E2E8F0',
          padding: '20px 40px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          position: 'sticky',
          top: 0,
          zIndex: 100
        }}
      >
        <h1
          style={{
            color: '#081028',
            fontFamily: '"Work Sans", sans-serif',
            fontSize: '20px',
            fontWeight: 600
          }}
        >
          Catalyst - Create Research Position
        </h1>
        <Link
          href="/my-labs"
          style={{
            color: '#64748B',
            fontFamily: '"Work Sans", sans-serif',
            fontSize: '14px',
            textDecoration: 'none'
          }}
        >
          My Positions
        </Link>
      </div>

      {/* Form */}
      <div
        style={{
          maxWidth: '900px',
          margin: '40px auto',
          backgroundColor: '#FFFFFF',
          borderRadius: '12px',
          padding: '48px',
          boxShadow: '0 1px 3px rgba(0, 0, 0, 0.1)'
        }}
      >
        <h2
          style={{
            color: '#081028',
            fontFamily: '"Work Sans", sans-serif',
            fontSize: '32px',
            fontWeight: 700,
            marginBottom: '8px'
          }}
        >
          Post a Research Position
        </h2>
        <p
          style={{
            color: '#64748B',
            fontFamily: '"Work Sans", sans-serif',
            fontSize: '16px',
            marginBottom: '40px'
          }}
        >
          Fill out the form below to create a new research opportunity for UCLA students
        </p>

        {/* Basic Information */}
        <div style={{ marginBottom: '40px' }}>
          <h3
            style={{
              color: '#081028',
              fontFamily: '"Work Sans", sans-serif',
              fontSize: '20px',
              fontWeight: 600,
              marginBottom: '20px',
              paddingBottom: '8px',
              borderBottom: '2px solid #F97316'
            }}
          >
            Basic Information
          </h3>

          <div style={{ marginBottom: '20px' }}>
            <label style={labelStyle}>Position Title *</label>
            <input
              type="text"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="e.g., Machine Learning for Healthcare Research Assistant"
              style={inputStyle}
            />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px', marginBottom: '20px' }}>
            <div>
              <label style={labelStyle}>Department *</label>
              <select
                value={department}
                onChange={(e) => setDepartment(e.target.value)}
                style={inputStyle}
              >
                <option value="">Select department</option>
                <option value="Computer Science">Computer Science</option>
                <option value="Biology">Biology</option>
                <option value="Chemistry">Chemistry</option>
                <option value="Physics">Physics</option>
                <option value="Psychology">Psychology</option>
                <option value="Engineering">Engineering</option>
                <option value="Mathematics">Mathematics</option>
                <option value="Materials Science">Materials Science</option>
                <option value="Other">Other</option>
              </select>
            </div>
            <div>
              <label style={labelStyle}>Research Area</label>
              <input
                type="text"
                value={researchArea}
                onChange={(e) => setResearchArea(e.target.value)}
                placeholder="e.g., Artificial Intelligence, Neuroscience"
                style={inputStyle}
              />
            </div>
          </div>

          <div>
            <label style={labelStyle}>Description *</label>
            <p style={{ fontSize: '14px', color: '#64748B', marginBottom: '8px' }}>
              Provide a detailed description of the research project and what the student will be doing (minimum 100 characters)
            </p>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="This research position involves..."
              style={{
                ...inputStyle,
                minHeight: '150px',
                resize: 'vertical',
                fontFamily: '"Work Sans", sans-serif'
              }}
            />
            <p style={{ fontSize: '12px', color: '#64748B', marginTop: '4px', textAlign: 'right' }}>
              {description.length} characters
            </p>
          </div>
        </div>

        {/* Requirements */}
        <div style={{ marginBottom: '40px' }}>
          <h3
            style={{
              color: '#081028',
              fontFamily: '"Work Sans", sans-serif',
              fontSize: '20px',
              fontWeight: 600,
              marginBottom: '20px',
              paddingBottom: '8px',
              borderBottom: '2px solid #F97316'
            }}
          >
            Requirements & Qualifications
          </h3>

          <div style={{ marginBottom: '20px' }}>
            <label style={labelStyle}>Requirements</label>
            <p style={{ fontSize: '14px', color: '#64748B', marginBottom: '12px' }}>
              List specific requirements or qualifications for applicants
            </p>
            {requirements.map((req, index) => (
              <div key={index} style={{ display: 'flex', gap: '12px', marginBottom: '12px' }}>
                <input
                  type="text"
                  value={req}
                  onChange={(e) => updateRequirement(index, e.target.value)}
                  placeholder="e.g., Python programming experience"
                  style={{ ...inputStyle, flex: 1 }}
                />
                {requirements.length > 1 && (
                  <button
                    onClick={() => removeRequirement(index)}
                    style={{
                      padding: '12px 16px',
                      borderRadius: '8px',
                      backgroundColor: '#FEE2E2',
                      color: '#DC2626',
                      border: 'none',
                      cursor: 'pointer',
                      fontFamily: '"Work Sans", sans-serif',
                      fontSize: '14px'
                    }}
                  >
                    Remove
                  </button>
                )}
              </div>
            ))}
            <button
              onClick={addRequirement}
              style={{
                padding: '8px 16px',
                borderRadius: '8px',
                backgroundColor: '#F0F9FF',
                color: '#0284C7',
                border: '1px solid #0284C7',
                cursor: 'pointer',
                fontFamily: '"Work Sans", sans-serif',
                fontSize: '14px',
                marginTop: '8px'
              }}
            >
              + Add Requirement
            </button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px', marginBottom: '20px' }}>
            <div>
              <label style={labelStyle}>Required Skills</label>
              <input
                type="text"
                value={skills}
                onChange={(e) => setSkills(e.target.value)}
                placeholder="e.g., Python, R, Statistics"
                style={inputStyle}
              />
            </div>
            <div>
              <label style={labelStyle}>Minimum GPA</label>
              <input
                type="text"
                value={minGPA}
                onChange={(e) => setMinGPA(e.target.value)}
                placeholder="e.g., 3.0"
                style={inputStyle}
              />
            </div>
          </div>

          <div>
            <label style={labelStyle}>Preferred Majors</label>
            <input
              type="text"
              value={preferredMajors}
              onChange={(e) => setPreferredMajors(e.target.value)}
              placeholder="e.g., Computer Science, Mathematics, Engineering"
              style={inputStyle}
            />
          </div>
        </div>

        {/* Position Details */}
        <div style={{ marginBottom: '40px' }}>
          <h3
            style={{
              color: '#081028',
              fontFamily: '"Work Sans", sans-serif',
              fontSize: '20px',
              fontWeight: 600,
              marginBottom: '20px',
              paddingBottom: '8px',
              borderBottom: '2px solid #F97316'
            }}
          >
            Position Details
          </h3>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px', marginBottom: '20px' }}>
            <div>
              <label style={labelStyle}>Hours Per Week *</label>
              <select
                value={hoursPerWeek}
                onChange={(e) => setHoursPerWeek(e.target.value)}
                style={inputStyle}
              >
                <option value="">Select hours</option>
                <option value="5-10 hours/week">5-10 hours/week</option>
                <option value="10-15 hours/week">10-15 hours/week</option>
                <option value="15-20 hours/week">15-20 hours/week</option>
                <option value="20+ hours/week">20+ hours/week</option>
              </select>
            </div>
            <div>
              <label style={labelStyle}>Duration *</label>
              <select
                value={duration}
                onChange={(e) => setDuration(e.target.value)}
                style={inputStyle}
              >
                <option value="">Select duration</option>
                <option value="1 quarter">1 quarter</option>
                <option value="2 quarters">2 quarters</option>
                <option value="1 year">1 year</option>
                <option value="Ongoing">Ongoing</option>
              </select>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px', marginBottom: '20px' }}>
            <div>
              <label style={labelStyle}>Compensation</label>
              <select
                value={compensation}
                onChange={(e) => setCompensation(e.target.value)}
                style={inputStyle}
              >
                <option value="Academic Credit">Academic Credit</option>
                <option value="Paid">Paid</option>
                <option value="Volunteer">Volunteer</option>
                <option value="Academic Credit or Paid">Academic Credit or Paid</option>
              </select>
            </div>
            <div>
              <label style={labelStyle}>Location</label>
              <input
                type="text"
                value={location}
                onChange={(e) => setLocation(e.target.value)}
                placeholder="e.g., Boelter Hall 4532"
                style={inputStyle}
              />
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <input
              type="checkbox"
              checked={isRemote}
              onChange={(e) => setIsRemote(e.target.checked)}
              id="remote"
              style={{ width: '18px', height: '18px', cursor: 'pointer' }}
            />
            <label
              htmlFor="remote"
              style={{
                color: '#081028',
                fontFamily: '"Work Sans", sans-serif',
                fontSize: '14px',
                cursor: 'pointer'
              }}
            >
              This position can be done remotely
            </label>
          </div>
        </div>

        {/* Application Settings */}
        <div style={{ marginBottom: '40px' }}>
          <h3
            style={{
              color: '#081028',
              fontFamily: '"Work Sans", sans-serif',
              fontSize: '20px',
              fontWeight: 600,
              marginBottom: '20px',
              paddingBottom: '8px',
              borderBottom: '2px solid #F97316'
            }}
          >
            Application Settings
          </h3>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px', marginBottom: '20px' }}>
            <div>
              <label style={labelStyle}>Application Deadline</label>
              <input
                type="date"
                value={applicationDeadline}
                onChange={(e) => setApplicationDeadline(e.target.value)}
                style={inputStyle}
              />
            </div>
            <div>
              <label style={labelStyle}>Maximum Number of Applicants</label>
              <input
                type="number"
                value={maxApplicants}
                onChange={(e) => setMaxApplicants(e.target.value)}
                placeholder="Leave blank for unlimited"
                style={inputStyle}
              />
            </div>
          </div>

          <div>
            <label style={labelStyle}>Additional Instructions for Applicants</label>
            <textarea
              value={additionalInstructions}
              onChange={(e) => setAdditionalInstructions(e.target.value)}
              placeholder="Any additional information or instructions for applicants..."
              style={{
                ...inputStyle,
                minHeight: '100px',
                resize: 'vertical',
                fontFamily: '"Work Sans", sans-serif'
              }}
            />
          </div>
        </div>

        {/* Error Message */}
        {error && (
          <div
            style={{
              padding: '16px',
              borderRadius: '8px',
              backgroundColor: '#FEE2E2',
              border: '1px solid #FCA5A5',
              marginBottom: '24px'
            }}
          >
            <p style={{ color: '#DC2626', fontSize: '14px', fontFamily: '"Work Sans", sans-serif' }}>
              {error}
            </p>
          </div>
        )}

        {/* Submit Buttons */}
        <div style={{ display: 'flex', gap: '16px', justifyContent: 'flex-end' }}>
          <button
            onClick={() => router.push('/my-labs')}
            style={{
              padding: '14px 32px',
              borderRadius: '8px',
              backgroundColor: '#FFFFFF',
              color: '#64748B',
              fontFamily: '"Work Sans", sans-serif',
              fontSize: '16px',
              fontWeight: 600,
              border: '1px solid #E2E8F0',
              cursor: 'pointer'
            }}
          >
            Cancel
          </button>
          <button
            onClick={handleSubmit}
            disabled={isSubmitting}
            style={{
              padding: '14px 32px',
              borderRadius: '8px',
              backgroundColor: isSubmitting ? '#9CA3AF' : '#F97316',
              color: '#FFFFFF',
              fontFamily: '"Work Sans", sans-serif',
              fontSize: '16px',
              fontWeight: 600,
              border: 'none',
              cursor: isSubmitting ? 'not-allowed' : 'pointer',
              transition: 'background-color 0.2s'
            }}
          >
            {isSubmitting ? 'Publishing...' : 'Publish Position'}
          </button>
        </div>
      </div>
    </div>
  )
}

const labelStyle: React.CSSProperties = {
  color: '#081028',
  fontFamily: '"Work Sans", sans-serif',
  fontSize: '14px',
  fontWeight: 600,
  display: 'block',
  marginBottom: '8px'
}

const inputStyle: React.CSSProperties = {
  width: '100%',
  padding: '12px',
  borderRadius: '8px',
  border: '1px solid #E2E8F0',
  fontSize: '14px',
  fontFamily: '"Work Sans", sans-serif',
  outline: 'none',
  boxSizing: 'border-box'
}
