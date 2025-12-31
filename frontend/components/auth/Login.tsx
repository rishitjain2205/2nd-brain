'use client'

import React, { useState } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'

export default function Login() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [userType, setUserType] = useState<'student' | 'professor'>('student')
  const router = useRouter()

  const handleLogin = (e?: React.FormEvent) => {
    if (e) e.preventDefault()

    if (!email || !password) {
      return
    }

    // Store user info in localStorage
    if (typeof window !== 'undefined') {
      localStorage.setItem('userEmail', email)
      localStorage.setItem('userType', userType)
      localStorage.setItem('isAuthenticated', 'true')
    }

    // Redirect based on user type to the correct dashboard
    if (userType === 'professor') {
      router.push('/create-lab')
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

          {/* Forgot Password */}
          <div style={{ textAlign: 'right', marginBottom: '24px' }}>
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

          {/* Sign Up Link */}
          <p
            style={{
              textAlign: 'center',
              color: '#6B7280',
              fontFamily: '"Work Sans", sans-serif',
              fontSize: '14px'
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
