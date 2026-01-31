'use client'

import React, { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'

interface Lab {
  id: string
  title: string
  professor: string
  department: string
  description: string
  requirements: string[]
  commitment: string
  location: string
}

// Mock data - replace with API call
const mockLabs: Lab[] = [
  {
    id: '1',
    title: 'Machine Learning for Healthcare',
    professor: 'Dr. Sarah Chen',
    department: 'Computer Science',
    description: 'Research on applying deep learning models to predict patient outcomes and optimize treatment plans.',
    requirements: ['Python programming', 'Calculus and Linear Algebra', 'Interest in healthcare applications'],
    commitment: '10-15 hours/week',
    location: 'Boelter Hall 4532'
  },
  {
    id: '2',
    title: 'Sustainable Energy Materials',
    professor: 'Dr. James Martinez',
    department: 'Materials Science',
    description: 'Developing novel materials for solar cells and energy storage systems to address climate change.',
    requirements: ['Chemistry background', 'Lab experience preferred', 'Commitment to sustainability'],
    commitment: '12-20 hours/week',
    location: 'Engineering VI 289'
  },
  {
    id: '3',
    title: 'Neuroscience of Decision Making',
    professor: 'Dr. Emily Rodriguez',
    department: 'Psychology',
    description: 'Investigating neural mechanisms underlying human decision-making using fMRI and behavioral experiments.',
    requirements: ['Statistics knowledge', 'Research methods course', 'Interest in cognitive neuroscience'],
    commitment: '8-12 hours/week',
    location: 'Franz Hall 3rd Floor'
  }
]

export default function BrowsePage() {
  const [labs, setLabs] = useState<Lab[]>(mockLabs)
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedDepartment, setSelectedDepartment] = useState('All')
  const [showSuccess, setShowSuccess] = useState(false)
  const router = useRouter()
  const searchParams = new URLSearchParams(typeof window !== 'undefined' ? window.location.search : '')

  // Check if application was submitted
  useEffect(() => {
    if (searchParams.get('submitted') === 'true') {
      setShowSuccess(true)
      // Hide success message after 5 seconds
      setTimeout(() => setShowSuccess(false), 5000)
    }
  }, [])

  const departments = ['All', 'Computer Science', 'Materials Science', 'Psychology', 'Biology', 'Chemistry']

  const filteredLabs = labs.filter(lab => {
    const matchesSearch = lab.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
                         lab.professor.toLowerCase().includes(searchQuery.toLowerCase()) ||
                         lab.description.toLowerCase().includes(searchQuery.toLowerCase())
    const matchesDepartment = selectedDepartment === 'All' || lab.department === selectedDepartment
    return matchesSearch && matchesDepartment
  })

  const handleApply = (labId: string) => {
    // Redirect to application page with lab ID
    router.push(`/apply?labId=${labId}`)
  }

  return (
    <div
      style={{
        width: '100vw',
        minHeight: '100vh',
        backgroundColor: '#FFF3E4'
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
          alignItems: 'center'
        }}
      >
        <h1
          style={{
            color: '#081028',
            fontFamily: '"Work Sans", sans-serif',
            fontSize: '24px',
            fontWeight: 600
          }}
        >
          Catalyst
        </h1>
        <div style={{ display: 'flex', gap: '16px', alignItems: 'center' }}>
          <Link
            href="/my-applications"
            style={{
              color: '#081028',
              fontFamily: '"Work Sans", sans-serif',
              fontSize: '14px',
              textDecoration: 'none'
            }}
          >
            My Applications
          </Link>
          <Link
            href="/signup"
            style={{
              padding: '10px 20px',
              borderRadius: '8px',
              backgroundColor: '#F97316',
              color: '#FFFFFF',
              fontFamily: '"Work Sans", sans-serif',
              fontSize: '14px',
              fontWeight: 500,
              textDecoration: 'none'
            }}
          >
            Sign Up
          </Link>
        </div>
      </div>

      {/* Success Message */}
      {showSuccess && (
        <div
          style={{
            backgroundColor: '#D1FAE5',
            borderBottom: '1px solid #6EE7B7',
            padding: '16px 40px',
            textAlign: 'center'
          }}
        >
          <p
            style={{
              color: '#065F46',
              fontFamily: '"Work Sans", sans-serif',
              fontSize: '16px',
              fontWeight: 500
            }}
          >
            ✓ Application submitted successfully! The professor will review your application and contact you soon.
          </p>
        </div>
      )}

      {/* Hero Section */}
      <div
        style={{
          padding: '60px 40px',
          textAlign: 'center',
          backgroundColor: '#FFFFFF',
          borderBottom: '1px solid #E2E8F0'
        }}
      >
        <h2
          style={{
            color: '#081028',
            fontFamily: '"Work Sans", sans-serif',
            fontSize: '48px',
            fontWeight: 700,
            marginBottom: '16px'
          }}
        >
          Find Your Research Opportunity
        </h2>
        <p
          style={{
            color: '#64748B',
            fontFamily: '"Work Sans", sans-serif',
            fontSize: '18px',
            marginBottom: '32px'
          }}
        >
          Connect with UCLA research labs and advance your academic career
        </p>

        {/* Search Bar */}
        <div
          style={{
            maxWidth: '600px',
            margin: '0 auto',
            display: 'flex',
            gap: '12px'
          }}
        >
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search labs, professors, or keywords..."
            style={{
              flex: 1,
              padding: '14px 20px',
              borderRadius: '8px',
              border: '1px solid #E2E8F0',
              fontSize: '16px',
              fontFamily: '"Work Sans", sans-serif',
              outline: 'none'
            }}
          />
          <button
            style={{
              padding: '14px 32px',
              borderRadius: '8px',
              backgroundColor: '#F97316',
              color: '#FFFFFF',
              fontFamily: '"Work Sans", sans-serif',
              fontSize: '16px',
              fontWeight: 600,
              border: 'none',
              cursor: 'pointer'
            }}
          >
            Search
          </button>
        </div>
      </div>

      {/* Filters and Labs */}
      <div
        style={{
          maxWidth: '1200px',
          margin: '0 auto',
          padding: '40px 20px'
        }}
      >
        {/* Department Filter */}
        <div style={{ marginBottom: '32px' }}>
          <h3
            style={{
              color: '#081028',
              fontFamily: '"Work Sans", sans-serif',
              fontSize: '16px',
              fontWeight: 600,
              marginBottom: '12px'
            }}
          >
            Filter by Department
          </h3>
          <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
            {departments.map(dept => (
              <button
                key={dept}
                onClick={() => setSelectedDepartment(dept)}
                style={{
                  padding: '8px 16px',
                  borderRadius: '20px',
                  border: `1px solid ${selectedDepartment === dept ? '#F97316' : '#E2E8F0'}`,
                  backgroundColor: selectedDepartment === dept ? '#FFF7ED' : '#FFFFFF',
                  color: selectedDepartment === dept ? '#F97316' : '#64748B',
                  fontFamily: '"Work Sans", sans-serif',
                  fontSize: '14px',
                  cursor: 'pointer',
                  transition: 'all 0.2s'
                }}
              >
                {dept}
              </button>
            ))}
          </div>
        </div>

        {/* Results Count */}
        <p
          style={{
            color: '#64748B',
            fontFamily: '"Work Sans", sans-serif',
            fontSize: '14px',
            marginBottom: '24px'
          }}
        >
          Showing {filteredLabs.length} research opportunities
        </p>

        {/* Lab Cards */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
          {filteredLabs.map(lab => (
            <div
              key={lab.id}
              style={{
                backgroundColor: '#FFFFFF',
                borderRadius: '12px',
                padding: '32px',
                boxShadow: '0 2px 8px rgba(0, 0, 0, 0.08)',
                transition: 'box-shadow 0.2s'
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start' }}>
                <div style={{ flex: 1 }}>
                  <h3
                    style={{
                      color: '#081028',
                      fontFamily: '"Work Sans", sans-serif',
                      fontSize: '24px',
                      fontWeight: 600,
                      marginBottom: '8px'
                    }}
                  >
                    {lab.title}
                  </h3>
                  <p
                    style={{
                      color: '#64748B',
                      fontFamily: '"Work Sans", sans-serif',
                      fontSize: '16px',
                      marginBottom: '4px'
                    }}
                  >
                    {lab.professor} • {lab.department}
                  </p>
                  <p
                    style={{
                      color: '#64748B',
                      fontFamily: '"Work Sans", sans-serif',
                      fontSize: '14px',
                      marginBottom: '16px'
                    }}
                  >
                    📍 {lab.location} | ⏰ {lab.commitment}
                  </p>
                  <p
                    style={{
                      color: '#334155',
                      fontFamily: '"Work Sans", sans-serif',
                      fontSize: '15px',
                      lineHeight: '1.6',
                      marginBottom: '16px'
                    }}
                  >
                    {lab.description}
                  </p>
                  <div style={{ marginBottom: '16px' }}>
                    <p
                      style={{
                        color: '#081028',
                        fontFamily: '"Work Sans", sans-serif',
                        fontSize: '14px',
                        fontWeight: 600,
                        marginBottom: '8px'
                      }}
                    >
                      Requirements:
                    </p>
                    <ul style={{ marginLeft: '20px' }}>
                      {lab.requirements.map((req, idx) => (
                        <li
                          key={idx}
                          style={{
                            color: '#64748B',
                            fontFamily: '"Work Sans", sans-serif',
                            fontSize: '14px',
                            marginBottom: '4px'
                          }}
                        >
                          {req}
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
                <button
                  onClick={() => handleApply(lab.id)}
                  style={{
                    padding: '12px 32px',
                    borderRadius: '8px',
                    backgroundColor: '#F97316',
                    color: '#FFFFFF',
                    fontFamily: '"Work Sans", sans-serif',
                    fontSize: '16px',
                    fontWeight: 600,
                    border: 'none',
                    cursor: 'pointer',
                    marginLeft: '24px',
                    whiteSpace: 'nowrap',
                    transition: 'background-color 0.2s'
                  }}
                  onMouseEnter={(e) => e.currentTarget.style.backgroundColor = '#EA580C'}
                  onMouseLeave={(e) => e.currentTarget.style.backgroundColor = '#F97316'}
                >
                  Apply
                </button>
              </div>
            </div>
          ))}
        </div>

        {/* No Results */}
        {filteredLabs.length === 0 && (
          <div
            style={{
              textAlign: 'center',
              padding: '60px 20px',
              backgroundColor: '#FFFFFF',
              borderRadius: '12px'
            }}
          >
            <p
              style={{
                color: '#64748B',
                fontFamily: '"Work Sans", sans-serif',
                fontSize: '18px'
              }}
            >
              No labs found matching your criteria. Try adjusting your filters.
            </p>
          </div>
        )}
      </div>
    </div>
  )
}
