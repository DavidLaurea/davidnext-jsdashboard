import type { NextAuthConfig } from 'next-auth';

export const authConfig = {
  pages: {
    signIn: '/login',
  },
  providers: [
    // added later in auth.ts since it requires bcrypt which is only compatible with Node.js
    // while this file is also used in non-Node.js environments
  ],
  callbacks: {
    authorized({ auth, request: { nextUrl } }) {
      const isLoggedIn = !!auth?.user;
      const isOnDashboard = nextUrl.pathname.startsWith('/dashboard');

      // If user is on any /dashboard route:
      if (isOnDashboard) {
        if (isLoggedIn) {
          return true; // allow
        }
        return false; // show login (NextAuth will redirect automatically)
      }

      // If user is already signed in but is NOT on /dashboard, send them to /dashboard
      if (isLoggedIn) {
        // Use NextResponse.redirect and give it a valid base URL string
        const dashboardUrl = new URL('/dashboard', nextUrl.origin);
        return NextResponse.redirect(dashboardUrl);
      }

      // Otherwise (not on /dashboard and not logged in), allow
      return true;
    },
  },
} satisfies NextAuthConfig;
