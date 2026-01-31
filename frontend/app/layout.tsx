import './globals.css'
import type { Metadata } from 'next'

export const metadata: Metadata = {
  title: 'Catalyst - UCLA Research Lab Matching',
  description: 'Connect UCLA students with research opportunities',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  )
}
