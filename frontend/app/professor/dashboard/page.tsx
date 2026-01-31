'use client'

import React, { useState } from 'react'
import { useRouter } from 'next/navigation'

interface Lab {
  id: string
  title: string
  department: string
  applicants: number
  status: 'active' | 'closed' | 'draft'
  postedDate: string
}

// Mock lab data
const mockLabs: Lab[] = [
  {
    id: '1',
    title: 'Machine Learning for Healthcare Research',
    department: 'Computer Science',
    applicants: 12,
    status: 'active',
    postedDate: '2024-01-15'
  },
  {
    id: '2',
    title: 'Molecular Biology Lab Assistant',
    department: 'Biology',
    applicants: 8,
    status: 'active',
    postedDate: '2024-01-10'
  }
]

export default function ProfessorDashboard() {
  const router = useRouter()
  const [labs, setLabs] = useState<Lab[]>(mockLabs)
  const [selectedLab, setSelectedLab] = useState<Lab | null>(mockLabs[0])

  const handleSignOut = () => {
    if (typeof window !== 'undefined') {
      localStorage.removeItem('isAuthenticated')
      localStorage.removeItem('userType')
      localStorage.removeItem('userEmail')
    }
    router.push('/login')
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active':
        return { bg: '#D1FAE5', text: '#065F46', label: 'Active' }
      case 'closed':
        return { bg: '#FEE2E2', text: '#991B1B', label: 'Closed' }
      case 'draft':
        return { bg: '#FEF3C7', text: '#92400E', label: 'Draft' }
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
            onClick={() => router.push('/professor/applications')}
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
                marginBottom: '8px'
              }}
            >
              My Research Positions
            </h2>
            <button
              onClick={() => router.push('/create-lab')}
              style={{
                width: '100%',
                padding: '10px',
                marginTop: '12px',
                borderRadius: '8px',
                backgroundColor: '#1E1E1E',
                color: '#FFFFFF',
                fontFamily: '"Work Sans", sans-serif',
                fontSize: '14px',
                fontWeight: 600,
                border: 'none',
                cursor: 'pointer',
                transition: 'background-color 0.2s'
              }}
              onMouseEnter={(e) => e.currentTarget.style.backgroundColor = '#000000'}
              onMouseLeave={(e) => e.currentTarget.style.backgroundColor = '#1E1E1E'}
            >
              + Create New Position
            </button>
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
              {labs.length} positions posted
            </p>
          </div>

          {/* Labs List */}
          <div style={{ flex: 1, overflow: 'auto', padding: '16px' }}>
            {labs.map(lab => {
              const statusInfo = getStatusColor(lab.status)
              return (
                <div
                  key={lab.id}
                  onClick={() => setSelectedLab(lab)}
                  style={{
                    backgroundColor: '#FFFFFF',
                    border: selectedLab?.id === lab.id ? '2px solid #C4A574' : '1px solid #E2E8F0',
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
                        fontFamily: '"Work Sans", sans-serif',
                        flex: 1
                      }}
                    >
                      {lab.title}
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
                      fontSize: '14px',
                      color: '#64748B',
                      fontFamily: '"Work Sans", sans-serif',
                      marginBottom: '8px'
                    }}
                  >
                    {lab.department}
                  </p>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <p
                      style={{
                        fontSize: '13px',
                        color: '#64748B',
                        fontFamily: '"Work Sans", sans-serif'
                      }}
                    >
                      Posted: {new Date(lab.postedDate).toLocaleDateString()}
                    </p>
                    <p
                      style={{
                        fontSize: '13px',
                        color: '#000000',
                        fontFamily: '"Work Sans", sans-serif',
                        fontWeight: 600
                      }}
                    >
                      {lab.applicants} applicants
                    </p>
                  </div>
                </div>
              )
            })}
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
            <div style={{ marginBottom: '24px' }}>
              <h2
                style={{
                  fontSize: '32px',
                  fontWeight: 700,
                  color: '#000000',
                  fontFamily: '"Work Sans", sans-serif',
                  marginBottom: '12px'
                }}
              >
                {selectedLab.title}
              </h2>
              <div style={{ display: 'flex', gap: '16px', alignItems: 'center' }}>
                <p
                  style={{
                    fontSize: '16px',
                    color: '#64748B',
                    fontFamily: '"Work Sans", sans-serif'
                  }}
                >
                  {selectedLab.department}
                </p>
                <span
                  style={{
                    padding: '4px 12px',
                    backgroundColor: getStatusColor(selectedLab.status).bg,
                    color: getStatusColor(selectedLab.status).text,
                    borderRadius: '14px',
                    fontSize: '13px',
                    fontFamily: '"Work Sans", sans-serif',
                    fontWeight: 600
                  }}
                >
                  {getStatusColor(selectedLab.status).label}
                </span>
              </div>
            </div>

            {/* Stats Cards */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '16px', marginBottom: '32px' }}>
              <div
                style={{
                  padding: '20px',
                  backgroundColor: '#F9FAFB',
                  borderRadius: '8px',
                  border: '1px solid #E2E8F0'
                }}
              >
                <p style={{ fontSize: '13px', color: '#64748B', fontFamily: '"Work Sans", sans-serif', marginBottom: '4px' }}>
                  Total Applications
                </p>
                <p style={{ fontSize: '28px', fontWeight: 700, color: '#000000', fontFamily: '"Work Sans", sans-serif' }}>
                  {selectedLab.applicants}
                </p>
              </div>
              <div
                style={{
                  padding: '20px',
                  backgroundColor: '#F9FAFB',
                  borderRadius: '8px',
                  border: '1px solid #E2E8F0'
                }}
              >
                <p style={{ fontSize: '13px', color: '#64748B', fontFamily: '"Work Sans", sans-serif', marginBottom: '4px' }}>
                  Under Review
                </p>
                <p style={{ fontSize: '28px', fontWeight: 700, color: '#000000', fontFamily: '"Work Sans", sans-serif' }}>
                  8
                </p>
              </div>
              <div
                style={{
                  padding: '20px',
                  backgroundColor: '#F9FAFB',
                  borderRadius: '8px',
                  border: '1px solid #E2E8F0'
                }}
              >
                <p style={{ fontSize: '13px', color: '#64748B', fontFamily: '"Work Sans", sans-serif', marginBottom: '4px' }}>
                  Accepted
                </p>
                <p style={{ fontSize: '28px', fontWeight: 700, color: '#000000', fontFamily: '"Work Sans", sans-serif' }}>
                  2
                </p>
              </div>
            </div>

            {/* Action Buttons */}
            <div style={{ display: 'flex', gap: '12px', marginBottom: '32px' }}>
              <button
                onClick={() => router.push(`/professor/applications?lab=${selectedLab.id}`)}
                style={{
                  padding: '12px 24px',
                  borderRadius: '8px',
                  backgroundColor: '#1E1E1E',
                  color: '#FFFFFF',
                  fontFamily: '"Work Sans", sans-serif',
                  fontSize: '15px',
                  fontWeight: 600,
                  border: 'none',
                  cursor: 'pointer',
                  transition: 'background-color 0.2s'
                }}
                onMouseEnter={(e) => e.currentTarget.style.backgroundColor = '#000000'}
                onMouseLeave={(e) => e.currentTarget.style.backgroundColor = '#1E1E1E'}
              >
                View Applications
              </button>
              <button
                style={{
                  padding: '12px 24px',
                  borderRadius: '8px',
                  backgroundColor: 'transparent',
                  color: '#000000',
                  fontFamily: '"Work Sans", sans-serif',
                  fontSize: '15px',
                  fontWeight: 500,
                  border: '1px solid #E2E8F0',
                  cursor: 'pointer'
                }}
              >
                Edit Position
              </button>
              <button
                style={{
                  padding: '12px 24px',
                  borderRadius: '8px',
                  backgroundColor: 'transparent',
                  color: '#DC2626',
                  fontFamily: '"Work Sans", sans-serif',
                  fontSize: '15px',
                  fontWeight: 500,
                  border: '1px solid #FCA5A5',
                  cursor: 'pointer'
                }}
              >
                Close Position
              </button>
            </div>

            {/* Info Section */}
            <div>
              <h3
                style={{
                  fontSize: '18px',
                  fontWeight: 600,
                  color: '#000000',
                  fontFamily: '"Work Sans", sans-serif',
                  marginBottom: '12px'
                }}
              >
                Position Information
              </h3>
              <p
                style={{
                  fontSize: '15px',
                  color: '#334155',
                  fontFamily: '"Work Sans", sans-serif',
                  lineHeight: '1.6',
                  marginBottom: '16px'
                }}
              >
                Posted on {new Date(selectedLab.postedDate).toLocaleDateString('en-US', {
                  year: 'numeric',
                  month: 'long',
                  day: 'numeric'
                })}
              </p>
              <p
                style={{
                  fontSize: '15px',
                  color: '#334155',
                  fontFamily: '"Work Sans", sans-serif',
                  lineHeight: '1.6'
                }}
              >
                You have received {selectedLab.applicants} applications for this position.
                Click "View Applications" to review student submissions.
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
