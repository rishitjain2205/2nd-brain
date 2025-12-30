'use client'

import React, { useState } from 'react'
import Image from 'next/image'
import { useRouter } from 'next/navigation'
import Link from 'next/link'

export default function Login() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [userType, setUserType] = useState<'student' | 'professor'>('student')
  const [error, setError] = useState('')
  const router = useRouter()

  const handleLogin = () => {
    setError('')

    if (!email || !password) {
      setError('Please enter both email and password')
      return
    }

    // Store user info in localStorage
    localStorage.setItem('userEmail', email)
    localStorage.setItem('userType', userType)

    // TODO: Fix routing once all pages are deployed
    // Temporarily redirect to signup which we know works
    // Redirect based on user type
    if (userType === 'professor') {
      // router.push('/create-lab') // 404 on Vercel currently
      router.push('/signup?success=true')
    } else {
      // router.push('/browse') // 404 on Vercel currently
      router.push('/signup?success=true')
    }
  }

  const handleAccessKnowledge = () => {
    // This is for the old 2nd Brain functionality - keeping for backwards compatibility
    router.push('/integrations')
  }

  return (
    <div 
      style={{
        width: '100vw',
        height: '100vh',
        backgroundColor: '#FFF3E4',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center'
      }}
    >
      {/* Logo at top left */}
      <div
        style={{
          position: 'absolute',
          top: '32px',
          left: '32px',
          display: 'flex',
          alignItems: 'center',
          gap: '12px'
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
      </div>

      {/* Main content */}
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '40px' }}>
        {/* Login Form */}
        <div style={{ width: '450px', textAlign: 'center' }}>
          <h2
            style={{
              color: '#081028',
              fontFamily: '"Work Sans", sans-serif',
              fontSize: '28px',
              fontWeight: 600,
              marginBottom: '24px'
            }}
          >
            Sign In to Catalyst
          </h2>

          {/* User Type Selection */}
          <div style={{ marginBottom: '20px' }}>
            <div style={{ display: 'flex', gap: '12px' }}>
              <button
                onClick={() => setUserType('student')}
                style={{
                  flex: 1,
                  padding: '12px',
                  borderRadius: '8px',
                  border: `2px solid ${userType === 'student' ? '#F97316' : 'rgba(52, 59, 79, 0.2)'}`,
                  backgroundColor: userType === 'student' ? '#FFF7ED' : '#FFE2BF',
                  color: '#081028',
                  fontFamily: '"Work Sans", sans-serif',
                  fontSize: '14px',
                  fontWeight: 500,
                  cursor: 'pointer',
                  transition: 'all 0.2s'
                }}
              >
                Student
              </button>
              <button
                onClick={() => setUserType('professor')}
                style={{
                  flex: 1,
                  padding: '12px',
                  borderRadius: '8px',
                  border: `2px solid ${userType === 'professor' ? '#F97316' : 'rgba(52, 59, 79, 0.2)'}`,
                  backgroundColor: userType === 'professor' ? '#FFF7ED' : '#FFE2BF',
                  color: '#081028',
                  fontFamily: '"Work Sans", sans-serif',
                  fontSize: '14px',
                  fontWeight: 500,
                  cursor: 'pointer',
                  transition: 'all 0.2s'
                }}
              >
                Professor
              </button>
            </div>
          </div>

          {/* Email input */}
          <div style={{ marginBottom: '16px' }}>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="your.email@ucla.edu"
              style={{
                width: '100%',
                height: '50px',
                padding: '0 20px',
                borderRadius: '8px',
                border: '0.6px solid #7E89AC',
                backgroundColor: '#FFE2BF',
                fontSize: '16px',
                fontFamily: '"Work Sans", sans-serif',
                outline: 'none',
                boxSizing: 'border-box'
              }}
            />
          </div>

          {/* Password input */}
          <div style={{ marginBottom: '16px' }}>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && handleLogin()}
              placeholder="Password"
              style={{
                width: '100%',
                height: '50px',
                padding: '0 20px',
                borderRadius: '8px',
                border: '0.6px solid #7E89AC',
                backgroundColor: '#FFE2BF',
                fontSize: '16px',
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
                padding: '12px',
                borderRadius: '8px',
                backgroundColor: '#FEE2E2',
                border: '1px solid #FCA5A5',
                marginBottom: '16px'
              }}
            >
              <p style={{ color: '#DC2626', fontSize: '14px', fontFamily: '"Work Sans", sans-serif' }}>
                {error}
              </p>
            </div>
          )}

          {/* Login Button */}
          <button
            onClick={handleLogin}
            style={{
              width: '100%',
              height: '50px',
              borderRadius: '8px',
              backgroundColor: '#F97316',
              color: '#FFFFFF',
              fontFamily: '"Work Sans", sans-serif',
              fontSize: '16px',
              fontWeight: 600,
              border: 'none',
              cursor: 'pointer',
              marginBottom: '16px',
              transition: 'background-color 0.2s'
            }}
            onMouseEnter={(e) => e.currentTarget.style.backgroundColor = '#EA580C'}
            onMouseLeave={(e) => e.currentTarget.style.backgroundColor = '#F97316'}
          >
            Sign In
          </button>

          {/* Sign Up Link */}
          <p
            style={{
              color: '#081028',
              fontFamily: '"Work Sans", sans-serif',
              fontSize: '14px',
              marginTop: '16px'
            }}
          >
            Don't have an account?{' '}
            <Link
              href="/signup"
              style={{
                color: '#F97316',
                textDecoration: 'none',
                fontWeight: 500
              }}
            >
              Sign up
            </Link>
          </p>

          {/* Browse Labs Link */}
          <p
            style={{
              color: '#64748B',
              fontFamily: '"Work Sans", sans-serif',
              fontSize: '14px',
              marginTop: '16px'
            }}
          >
            <Link
              href="/browse"
              style={{
                color: '#64748B',
                textDecoration: 'underline'
              }}
            >
              Browse labs without signing in
            </Link>
          </p>
        </div>
      </div>
    </div>
  )
}
