'use client'

import React, { useState } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import { setAuthCookie } from '@/lib/auth'

export default function Login() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [userType, setUserType] = useState<'student' | 'professor'>('student')
  const [rememberMe, setRememberMe] = useState(false)
  const router = useRouter()

  const handleLogin = (e?: React.FormEvent) => {
    if (e) e.preventDefault()

    if (!email || !password) {
      return
    }

    // Store user info in cookies (with Remember Me option)
    setAuthCookie({
      email,
      userType,
      isAuthenticated: true
    }, rememberMe)

    // Redirect based on user type to the correct dashboard
    if (userType === 'professor') {
      router.push('/professor/dashboard')
    } else {
      // IMPORTANT: Redirect students to the new gray/white student dashboard
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
          Welcome back
        </h1>
        <p
          style={{
            color: '#6B7280',
            fontFamily: '"Work Sans", sans-serif',
            fontSize: '16px',
            marginBottom: '32px'
          }}
        >
          Sign in to continue to Catalyst
        </p>

        <form onSubmit={handleLogin}>
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

          {/* Email Input */}
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
              placeholder="your.name@ucla.edu"
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

          {/* Password Input */}
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
              onKeyPress={(e) => e.key === 'Enter' && handleLogin()}
              placeholder="Enter your password"
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

          {/* Remember Me & Forgot Password */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
            <label
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                cursor: 'pointer'
              }}
            >
              <input
                type="checkbox"
                checked={rememberMe}
                onChange={(e) => setRememberMe(e.target.checked)}
                style={{
                  width: '16px',
                  height: '16px',
                  cursor: 'pointer'
                }}
              />
              <span
                style={{
                  color: '#6B7280',
                  fontFamily: '"Work Sans", sans-serif',
                  fontSize: '14px'
                }}
              >
                Remember me
              </span>
            </label>
            <a
              href="#"
              style={{
                color: '#6B7280',
                fontFamily: '"Work Sans", sans-serif',
                fontSize: '14px',
                textDecoration: 'none'
              }}
            >
              Forgot password?
            </a>
          </div>

          {/* Sign In Button */}
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
              marginBottom: '20px',
              transition: 'background-color 0.2s'
            }}
            onMouseEnter={(e) => e.currentTarget.style.backgroundColor = '#111827'}
            onMouseLeave={(e) => e.currentTarget.style.backgroundColor = '#1F2937'}
          >
            Sign in
          </button>

          {/* Divider */}
          <div style={{ display: 'flex', alignItems: 'center', margin: '24px 0' }}>
            <div style={{ flex: 1, height: '1px', backgroundColor: '#E5E7EB' }} />
            <span style={{ padding: '0 16px', color: '#6B7280', fontSize: '14px', fontFamily: '"Work Sans", sans-serif' }}>
              or
            </span>
            <div style={{ flex: 1, height: '1px', backgroundColor: '#E5E7EB' }} />
          </div>

          {/* SSO Button */}
          <button
            type="button"
            onClick={() => {
              // TODO: Implement Google SSO - requires backend OAuth2 setup
              alert('Google SSO integration coming soon!\n\nThis requires:\n1. Backend OAuth2 configuration\n2. Google Cloud Console setup\n3. UCLA email verification')
            }}
            style={{
              width: '100%',
              padding: '12px',
              borderRadius: '8px',
              backgroundColor: '#FFFFFF',
              color: '#111827',
              fontFamily: '"Work Sans", sans-serif',
              fontSize: '15px',
              fontWeight: 500,
              border: '1px solid #D1D5DB',
              cursor: 'pointer',
              marginBottom: '12px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '12px',
              transition: 'background-color 0.2s'
            }}
            onMouseEnter={(e) => e.currentTarget.style.backgroundColor = '#F9FAFB'}
            onMouseLeave={(e) => e.currentTarget.style.backgroundColor = '#FFFFFF'}
          >
            <svg width="18" height="18" viewBox="0 0 18 18">
              <path fill="#4285F4" d="M17.64 9.2c0-.637-.057-1.251-.164-1.84H9v3.481h4.844c-.209 1.125-.843 2.078-1.796 2.717v2.258h2.908c1.702-1.567 2.684-3.874 2.684-6.615z"/>
              <path fill="#34A853" d="M9 18c2.43 0 4.467-.806 5.956-2.184l-2.908-2.258c-.806.54-1.837.86-3.048.86-2.344 0-4.328-1.584-5.036-3.711H.957v2.332C2.438 15.983 5.482 18 9 18z"/>
              <path fill="#FBBC05" d="M3.964 10.707c-.18-.54-.282-1.117-.282-1.707s.102-1.167.282-1.707V4.961H.957C.347 6.175 0 7.55 0 9s.348 2.825.957 4.039l3.007-2.332z"/>
              <path fill="#EA4335" d="M9 3.58c1.321 0 2.508.454 3.44 1.345l2.582-2.58C13.463.891 11.426 0 9 0 5.482 0 2.438 2.017.957 4.961L3.964 7.293C4.672 5.163 6.656 3.58 9 3.58z"/>
            </svg>
            Continue with UCLA Google
          </button>

          {/* Sign Up Link */}
          <p
            style={{
              textAlign: 'center',
              color: '#6B7280',
              fontFamily: '"Work Sans", sans-serif',
              fontSize: '14px',
              marginTop: '20px'
            }}
          >
            Don't have an account?{' '}
            <Link
              href="/signup"
              style={{
                color: '#111827',
                textDecoration: 'none',
                fontWeight: 600
              }}
            >
              Sign up
            </Link>
          </p>
        </form>
      </div>
    </div>
  )
}
