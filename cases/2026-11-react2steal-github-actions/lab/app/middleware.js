import { NextResponse } from 'next/server';
// Contrôle d'accès typique : /admin exige un cookie de session.
export function middleware(req) {
  if (!req.cookies.get('session')) return NextResponse.redirect(new URL('/login', req.url));
  return NextResponse.next();
}
export const config = { matcher: ['/admin/:path*'] };
