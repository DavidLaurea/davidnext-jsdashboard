// app/auth.config.ts
import { NextResponse } from 'next/server';
import type { NextAuthConfig } from 'next-auth';
import NextAuth from 'next-auth';
import CredentialsProvider from 'next-auth/providers/credentials';
import { compare } from 'bcrypt';

// Import the SQL client from data.ts
import { sql } from './lib/data';

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
          return null;
        }

        // Use `sql` to look up the user by email in your users table
        const rows: { id: number; email: string; hashed_password: string; name: string }[] =
          await sql`
            SELECT id, email, hashed_password, name 
            FROM users 
            WHERE email = ${credentials.email}
          `;
        const userRow = rows[0];
        if (!userRow) return null;

        // Compare the password with bcrypt
        const isValid = await compare(credentials.password, userRow.hashed_password);
        if (!isValid) return null;

        // Return a minimal user object
        return {
          id: userRow.id.toString(),
          email: userRow.email,
          name: userRow.name,
        };
      },
    }),
  ],
  pages: {
    signIn: '/login',
  },
  callbacks: {
    async authorized({ auth, request: { nextUrl } }) {
      const isLoggedIn = !!auth?.user;
      const isOnDashboard = nextUrl.pathname.startsWith('/dashboard');

      if (isOnDashboard) {
        // If accessing /dashboard routes, only allow if signed in
        return isLoggedIn;
      }

      if (isLoggedIn) {
        // If already signed in but not on /dashboard, redirect to /dashboard
        const dashboardUrl = new URL('/dashboard', nextUrl.origin);
        return NextResponse.redirect(dashboardUrl);
      }

      // Otherwise (not on /dashboard and not logged in), allow
      return true;
    },
  },
};

export default NextAuth(authConfig);
