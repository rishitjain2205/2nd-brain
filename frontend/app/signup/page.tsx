'use client'

import React, { useState } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import { setAuthCookie } from '@/lib/auth'

export default function SignupPage() {
  const [userType, setUserType] = useState<'student' | 'professor'>('student')
  const [fullName, setFullName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const router = useRouter()

  const handleSignup = async (e?: React.FormEvent) => {
    if (e) e.preventDefault()
    setError('')

    // Validation
    if (!fullName || !email || !password) {
      setError('All fields are required')
      return
    }

    // Email validation for students
    if (userType === 'student') {
      if (!email.endsWith('@ucla.edu') && !email.endsWith('@g.ucla.edu')) {
        setError('Students must use a UCLA email (@ucla.edu or @g.ucla.edu)')
        return
      }
    }

    // TODO: Call backend API to create account
    // For now, store in cookies and redirect
    setAuthCookie({
      email,
      userType,
      userName: fullName,
      isAuthenticated: true
    }, true) // Always remember on signup

    // Redirect based on user type
    if (userType === 'professor') {
      router.push('/professor/dashboard')
    } else {
      router.push('/student/dashboard')
    }
  }

  return (
    <div
      style={{
        width: '100vw',
        height: '100vh',
        backgroundColor: '#F3F4F6',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center'
      }}
    >
      <div
        style={{
          backgroundColor: '#FFFFFF',
          borderRadius: '12px',
          padding: '48px 40px',
          maxWidth: '480px',
          width: '90%',
          boxShadow: '0 1px 3px rgba(0, 0, 0, 0.1)'
        }}
      >
        <h1
          style={{
            color: '#111827',
            fontFamily: '"Work Sans", sans-serif',
            fontSize: '32px',
            fontWeight: 700,
            marginBottom: '8px'
          }}
        >
          Create your account
        </h1>
        <p
          style={{
            color: '#6B7280',
            fontFamily: '"Work Sans", sans-serif',
            fontSize: '16px',
            marginBottom: '32px'
          }}
        >
          Join Catalyst to find research opportunities
        </p>

        <form onSubmit={handleSignup}>
          {/* User Type Selection */}
          <div style={{ marginBottom: '24px' }}>
            <label
              style={{
                display: 'block',
                color: '#111827',
                fontFamily: '"Work Sans", sans-serif',
                fontSize: '14px',
                fontWeight: 500,
                marginBottom: '12px'
              }}
            >
              I am a
            </label>
            <div style={{ display: 'flex', gap: '12px' }}>
              <button
                type="button"
                onClick={() => setUserType('student')}
                style={{
                  flex: 1,
                  padding: '14px',
                  borderRadius: '8px',
                  border: `2px solid ${userType === 'student' ? '#111827' : '#E5E7EB'}`,
                  backgroundColor: '#FFFFFF',
                  color: '#111827',
                  fontFamily: '"Work Sans", sans-serif',
                  fontSize: '15px',
                  fontWeight: 500,
                  cursor: 'pointer',
                  transition: 'all 0.2s'
                }}
              >
                Student
              </button>
              <button
                type="button"
                onClick={() => setUserType('professor')}
                style={{
                  flex: 1,
                  padding: '14px',
                  borderRadius: '8px',
                  border: `2px solid ${userType === 'professor' ? '#111827' : '#E5E7EB'}`,
                  backgroundColor: '#FFFFFF',
                  color: '#111827',
                  fontFamily: '"Work Sans", sans-serif',
                  fontSize: '15px',
                  fontWeight: 500,
                  cursor: 'pointer',
                  transition: 'all 0.2s'
                }}
              >
                Professor
              </button>
            </div>
          </div>

          {/* Full Name */}
          <div style={{ marginBottom: '20px' }}>
            <label
              style={{
                display: 'block',
                color: '#111827',
                fontFamily: '"Work Sans", sans-serif',
                fontSize: '14px',
                fontWeight: 500,
                marginBottom: '8px'
              }}
            >
              Full name
            </label>
            <input
              type="text"
              value={fullName}
              onChange={(e) => setFullName(e.target.value)}
              placeholder="Jane Doe"
              style={{
                width: '100%',
                padding: '12px 16px',
                borderRadius: '8px',
                border: '1px solid #D1D5DB',
                backgroundColor: '#FFFFFF',
                fontSize: '15px',
                fontFamily: '"Work Sans", sans-serif',
                outline: 'none',
                boxSizing: 'border-box'
              }}
            />
          </div>

          {/* Email */}
          <div style={{ marginBottom: '20px' }}>
            <label
              style={{
                display: 'block',
                color: '#111827',
                fontFamily: '"Work Sans", sans-serif',
                fontSize: '14px',
                fontWeight: 500,
                marginBottom: '8px'
              }}
            >
              Email address
            </label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder={userType === 'student' ? 'your.name@ucla.edu' : 'professor@ucla.edu'}
              style={{
                width: '100%',
                padding: '12px 16px',
                borderRadius: '8px',
                border: '1px solid #D1D5DB',
                backgroundColor: '#FFFFFF',
                fontSize: '15px',
                fontFamily: '"Work Sans", sans-serif',
                outline: 'none',
                boxSizing: 'border-box'
              }}
            />
            {userType === 'student' && (
              <p
                style={{
                  fontSize: '13px',
                  color: '#6B7280',
                  marginTop: '6px',
                  fontFamily: '"Work Sans", sans-serif'
                }}
              >
                Must be a UCLA email (@ucla.edu or @g.ucla.edu)
              </p>
            )}
          </div>

          {/* Password */}
          <div style={{ marginBottom: '12px' }}>
            <label
              style={{
                display: 'block',
                color: '#111827',
                fontFamily: '"Work Sans", sans-serif',
                fontSize: '14px',
                fontWeight: 500,
                marginBottom: '8px'
              }}
            >
              Password
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && handleSignup()}
              placeholder="Create a password"
              style={{
                width: '100%',
                padding: '12px 16px',
                borderRadius: '8px',
                border: '1px solid #D1D5DB',
                backgroundColor: '#FFFFFF',
                fontSize: '15px',
                fontFamily: '"Work Sans", sans-serif',
                outline: 'none',
                boxSizing: 'border-box'
              }}
            />
          </div>

          {/* Error Message */}
          {error && (
            <div
              style={{
                padding: '12px 16px',
                borderRadius: '8px',
                backgroundColor: '#FEE2E2',
                border: '1px solid #FCA5A5',
                marginBottom: '20px',
                marginTop: '20px'
              }}
            >
              <p
                style={{
                  color: '#DC2626',
                  fontSize: '14px',
                  fontFamily: '"Work Sans", sans-serif',
                  margin: 0
                }}
              >
                {error}
              </p>
            </div>
          )}

          {/* Create Account Button */}
          <button
            type="submit"
            style={{
              width: '100%',
              padding: '14px',
              borderRadius: '8px',
              backgroundColor: '#1F2937',
              color: '#FFFFFF',
              fontFamily: '"Work Sans", sans-serif',
              fontSize: '16px',
              fontWeight: 600,
              border: 'none',
              cursor: 'pointer',
              marginTop: '24px',
              marginBottom: '20px',
              transition: 'background-color 0.2s'
            }}
            onMouseEnter={(e) => e.currentTarget.style.backgroundColor = '#111827'}
            onMouseLeave={(e) => e.currentTarget.style.backgroundColor = '#1F2937'}
          >
            Create account
          </button>

          {/* Sign In Link */}
          <p
            style={{
              textAlign: 'center',
              color: '#6B7280',
              fontFamily: '"Work Sans", sans-serif',
              fontSize: '14px',
              margin: 0
            }}
          >
            Already have an account?{' '}
            <Link
              href="/login"
              style={{
                color: '#111827',
                textDecoration: 'none',
                fontWeight: 600
              }}
            >
              Sign in
            </Link>
          </p>
        </form>
      </div>
    </div>
  )
}
