'use client'

import React, { useState } from 'react'
import { useRouter } from 'next/navigation'

interface Application {
  id: string
  labName: string
  pi: string
  department: string
  appliedDate: string
  status: 'pending' | 'under_review' | 'accepted' | 'rejected'
  submittedMaterials: string[]
}

// Mock application data
const mockApplications: Application[] = [
  {
    id: '1',
    labName: 'Shahan Lab',
    pi: 'Dr Shahan',
    department: 'Molecular Biology',
    appliedDate: 'December 28, 2025',
    status: 'under_review',
    submittedMaterials: ['Resume', 'Statement of Interest', 'Transcript']
  },
  {
    id: '2',
    labName: 'Chen Lab',
    pi: 'Dr Sarah Chen',
    department: 'Computer Science',
    appliedDate: 'December 20, 2025',
    status: 'pending',
    submittedMaterials: ['Resume', 'Statement of Interest']
  },
  {
    id: '3',
    labName: 'Martinez Lab',
    pi: 'Dr Carlos Martinez',
    department: 'Neuroscience',
    appliedDate: 'December 15, 2025',
    status: 'accepted',
    submittedMaterials: ['Resume', 'Statement of Interest', 'Transcript', 'References']
  }
]

export default function MyApplicationsPage() {
  const router = useRouter()
  const [applications, setApplications] = useState<Application[]>(mockApplications)
  const [selectedApplication, setSelectedApplication] = useState<Application | null>(mockApplications[0])
  const [filterStatus, setFilterStatus] = useState<string>('all')

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'pending':
        return { bg: '#FEF3C7', text: '#92400E', label: 'Pending' }
      case 'under_review':
        return { bg: '#DBEAFE', text: '#1E40AF', label: 'Under Review' }
      case 'accepted':
        return { bg: '#D1FAE5', text: '#065F46', label: 'Accepted' }
      case 'rejected':
        return { bg: '#FEE2E2', text: '#991B1B', label: 'Not Selected' }
      default:
        return { bg: '#F3F4F6', text: '#374151', label: status }
    }
  }

  const filteredApplications = filterStatus === 'all'
    ? applications
    : applications.filter(app => app.status === filterStatus)

  const handleSignOut = () => {
    if (typeof window !== 'undefined') {
      localStorage.removeItem('isAuthenticated')
      localStorage.removeItem('userType')
    }
    router.push('/login')
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
              My Applications
            </h2>

            {/* Status Filter */}
            <select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
              style={{
                width: '100%',
                padding: '10px 16px',
                border: '1px solid #E2E8F0',
                borderRadius: '6px',
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
              <option value="rejected">Not Selected</option>
            </select>
          </div>

          {/* Application Count */}
          <div style={{ padding: '12px 24px', backgroundColor: '#FFFFFF' }}>
            <p
              style={{
                fontSize: '14px',
                color: '#64748B',
                fontFamily: '"Work Sans", sans-serif'
              }}
            >
              {filteredApplications.length} application{filteredApplications.length !== 1 ? 's' : ''}
            </p>
          </div>

          {/* Applications List */}
          <div style={{ flex: 1, overflow: 'auto', padding: '16px' }}>
            {filteredApplications.length === 0 ? (
              <div style={{ padding: '24px', textAlign: 'center' }}>
                <p style={{ fontSize: '15px', color: '#64748B', fontFamily: '"Work Sans", sans-serif' }}>
                  No applications found
                </p>
              </div>
            ) : (
              filteredApplications.map(app => {
                const statusStyle = getStatusColor(app.status)
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
                          fontSize: '18px',
                          fontWeight: 600,
                          color: '#000000',
                          fontFamily: '"Work Sans", sans-serif'
                        }}
                      >
                        {app.labName}
                      </h3>
                      <span
                        style={{
                          padding: '4px 10px',
                          backgroundColor: statusStyle.bg,
                          color: statusStyle.text,
                          borderRadius: '12px',
                          fontSize: '12px',
                          fontFamily: '"Work Sans", sans-serif',
                          fontWeight: 500
                        }}
                      >
                        {statusStyle.label}
                      </span>
                    </div>
                    <p
                      style={{
                        fontSize: '14px',
                        color: '#64748B',
                        fontFamily: '"Work Sans", sans-serif',
                        marginBottom: '4px'
                      }}
                    >
                      {app.pi} • {app.department}
                    </p>
                    <p
                      style={{
                        fontSize: '13px',
                        color: '#94A3B8',
                        fontFamily: '"Work Sans", sans-serif'
                      }}
                    >
                      Applied {app.appliedDate}
                    </p>
                  </div>
                )
              })
            )}
          </div>
        </div>

        {/* Application Details */}
        {selectedApplication ? (
          <div
            style={{
              flex: 1,
              backgroundColor: '#FFFFFF',
              overflow: 'auto',
              padding: '32px'
            }}
          >
            <div style={{ maxWidth: '700px' }}>
              {/* Header */}
              <div style={{ marginBottom: '32px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', marginBottom: '16px' }}>
                  <h2
                    style={{
                      fontSize: '32px',
                      fontWeight: 700,
                      color: '#000000',
                      fontFamily: '"Work Sans", sans-serif'
                    }}
                  >
                    {selectedApplication.labName}
                  </h2>
                  {(() => {
                    const statusStyle = getStatusColor(selectedApplication.status)
                    return (
                      <span
                        style={{
                          padding: '8px 16px',
                          backgroundColor: statusStyle.bg,
                          color: statusStyle.text,
                          borderRadius: '16px',
                          fontSize: '14px',
                          fontFamily: '"Work Sans", sans-serif',
                          fontWeight: 600
                        }}
                      >
                        {statusStyle.label}
                      </span>
                    )
                  })()}
                </div>

                <p
                  style={{
                    fontSize: '18px',
                    color: '#000000',
                    fontFamily: '"Work Sans", sans-serif',
                    marginBottom: '8px'
                  }}
                >
                  <strong>Principal Investigator:</strong> {selectedApplication.pi}
                </p>
                <p
                  style={{
                    fontSize: '16px',
                    color: '#64748B',
                    fontFamily: '"Work Sans", sans-serif'
                  }}
                >
                  {selectedApplication.department}
                </p>
              </div>

              {/* Application Timeline */}
              <div style={{ marginBottom: '32px' }}>
                <h3
                  style={{
                    fontSize: '20px',
                    fontWeight: 600,
                    color: '#000000',
                    fontFamily: '"Work Sans", sans-serif',
                    marginBottom: '16px',
                    borderBottom: '2px solid #E2E8F0',
                    paddingBottom: '12px'
                  }}
                >
                  Application Timeline
                </h3>

                <div style={{ position: 'relative', paddingLeft: '32px' }}>
                  {/* Timeline line */}
                  <div style={{ position: 'absolute', left: '7px', top: '8px', bottom: '8px', width: '2px', backgroundColor: '#E2E8F0' }}></div>

                  {/* Timeline items */}
                  <div style={{ marginBottom: '24px', position: 'relative' }}>
                    <div style={{ position: 'absolute', left: '-32px', top: '4px', width: '16px', height: '16px', borderRadius: '50%', backgroundColor: '#10B981', border: '3px solid #FFFFFF' }}></div>
                    <p style={{ fontSize: '15px', fontWeight: 600, color: '#000000', fontFamily: '"Work Sans", sans-serif', marginBottom: '4px' }}>
                      Application Submitted
                    </p>
                    <p style={{ fontSize: '14px', color: '#64748B', fontFamily: '"Work Sans", sans-serif' }}>
                      {selectedApplication.appliedDate}
                    </p>
                  </div>

                  {selectedApplication.status !== 'pending' && (
                    <div style={{ marginBottom: '24px', position: 'relative' }}>
                      <div style={{ position: 'absolute', left: '-32px', top: '4px', width: '16px', height: '16px', borderRadius: '50%', backgroundColor: '#3B82F6', border: '3px solid #FFFFFF' }}></div>
                      <p style={{ fontSize: '15px', fontWeight: 600, color: '#000000', fontFamily: '"Work Sans", sans-serif', marginBottom: '4px' }}>
                        Under Review
                      </p>
                      <p style={{ fontSize: '14px', color: '#64748B', fontFamily: '"Work Sans", sans-serif' }}>
                        Your application is being reviewed by the lab
                      </p>
                    </div>
                  )}

                  {(selectedApplication.status === 'accepted' || selectedApplication.status === 'rejected') && (
                    <div style={{ position: 'relative' }}>
                      <div style={{ position: 'absolute', left: '-32px', top: '4px', width: '16px', height: '16px', borderRadius: '50%', backgroundColor: selectedApplication.status === 'accepted' ? '#10B981' : '#EF4444', border: '3px solid #FFFFFF' }}></div>
                      <p style={{ fontSize: '15px', fontWeight: 600, color: '#000000', fontFamily: '"Work Sans", sans-serif', marginBottom: '4px' }}>
                        {selectedApplication.status === 'accepted' ? 'Application Accepted' : 'Application Not Selected'}
                      </p>
                      <p style={{ fontSize: '14px', color: '#64748B', fontFamily: '"Work Sans", sans-serif' }}>
                        {selectedApplication.status === 'accepted'
                          ? 'Congratulations! The lab has accepted your application.'
                          : 'Thank you for your interest. The lab has decided to move forward with other candidates.'}
                      </p>
                    </div>
                  )}
                </div>
              </div>

              {/* Submitted Materials */}
              <div style={{ marginBottom: '32px' }}>
                <h3
                  style={{
                    fontSize: '20px',
                    fontWeight: 600,
                    color: '#000000',
                    fontFamily: '"Work Sans", sans-serif',
                    marginBottom: '16px',
                    borderBottom: '2px solid #E2E8F0',
                    paddingBottom: '12px'
                  }}
                >
                  Submitted Materials
                </h3>

                <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
                  {selectedApplication.submittedMaterials.map((material, idx) => (
                    <div
                      key={idx}
                      style={{
                        padding: '12px 16px',
                        backgroundColor: '#F9FAFB',
                        border: '1px solid #E2E8F0',
                        borderRadius: '8px',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '8px'
                      }}
                    >
                      <svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
                        <path d="M9 2H4C3.46957 2 2.96086 2.21071 2.58579 2.58579C2.21071 2.96086 2 3.46957 2 4V12C2 12.5304 2.21071 13.0391 2.58579 13.4142C2.96086 13.7893 3.46957 14 4 14H12C12.5304 14 13.0391 13.7893 13.4142 13.4142C13.7893 13.0391 14 12.5304 14 12V7M13 1L8 6M13 1V4M13 1H10" stroke="#64748B" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
                      </svg>
                      <span style={{ fontSize: '14px', color: '#000000', fontFamily: '"Work Sans", sans-serif', fontWeight: 500 }}>
                        {material}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Action Buttons */}
              {selectedApplication.status === 'accepted' && (
                <div style={{ marginTop: '32px' }}>
                  <button
                    style={{
                      padding: '14px 24px',
                      backgroundColor: '#10B981',
                      color: '#FFFFFF',
                      fontFamily: '"Work Sans", sans-serif',
                      fontSize: '16px',
                      fontWeight: 600,
                      border: 'none',
                      borderRadius: '8px',
                      cursor: 'pointer',
                      marginRight: '12px'
                    }}
                  >
                    View Next Steps
                  </button>
                  <button
                    style={{
                      padding: '14px 24px',
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
                    Contact Lab
                  </button>
                </div>
              )}
            </div>
          </div>
        ) : (
          <div
            style={{
              flex: 1,
              backgroundColor: '#FFFFFF',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center'
            }}
          >
            <p style={{ fontSize: '16px', color: '#64748B', fontFamily: '"Work Sans", sans-serif' }}>
              Select an application to view details
            </p>
          </div>
        )}
      </div>
    </div>
  )
}
