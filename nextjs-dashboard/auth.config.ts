// auth.config.ts
import { NextResponse } from 'next/server'
import type { NextAuthConfig } from 'next-auth'
import NextAuth from 'next-auth'
import CredentialsProvider from 'next-auth/providers/credentials'
import { compare } from 'bcrypt'
import { db } from './lib/db'  // adjust this path if your DB client is elsewhere

export const authConfig: NextAuthConfig = {
  providers: [
    CredentialsProvider({
      name: 'Credentials',
      credentials: {
        email: { label: 'Email', type: 'text' },
        password: { label: 'Password', type: 'password' },
      },
      async authorize(credentials) {
        if (!credentials?.email || !credentials.password) {
          return null
        }
        const user = await db.user.findUnique({
          where: { email: credentials.email },
        })
        if (!user) return null

        const isValid = await compare(credentials.password, user.hashedPassword)
        if (!isValid) return null

        return { id: user.id.toString(), email: user.email, name: user.name }
      },
    }),
  ],
  pages: {
    signIn: '/login',
  },
  callbacks: {
    async authorized({ auth, request: { nextUrl } }) {
      const isLoggedIn = !!auth?.user
      const isOnDashboard = nextUrl.pathname.startsWith('/dashboard')

      // If user is on any /dashboard route:
      if (isOnDashboard) {
        // allow if signed in, else block → NextAuth will redirect to /login
        return isLoggedIn
      }

      // If user is already signed in but is NOT on /dashboard, redirect them
      if (isLoggedIn) {
        // Build a URL that points to /dashboard on the same origin
        const dashboardUrl = new URL('/dashboard', nextUrl.origin)
        return NextResponse.redirect(dashboardUrl)
      }

      // Otherwise (not on /dashboard and not logged in), allow
      return true
    },
  },
}

export default NextAuth(authConfig)
