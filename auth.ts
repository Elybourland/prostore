import NextAuth from 'next-auth';
import { PrismaAdapter } from '@auth/prisma-adapter';
import { prisma } from '@/db/prisma';
import CredentialsProvider from 'next-auth/providers/credentials';
import { compareSync } from 'bcrypt-ts-edge';
import { authConfig } from './auth.config';

export const config = {
  pages: {
    signIn: '/sign-in',
    error: '/sign-in',
  },
  session: {
    strategy: 'jwt' as const,
    maxAge: 30 * 24 * 60 * 60, // 30 days
  },
  adapter: PrismaAdapter(prisma),
  providers: [
    CredentialsProvider({
      credentials: {
        email: { type: 'email' },
        password: { type: 'password' }
      },
      async authorize(credentials) {
        if (!credentials) return null;

        const user = await prisma.user.findFirst({
          where: { email: credentials.email }
        });

        if (user && user.password) {
          const isMatch = compareSync(credentials.password, user.password);
          if (isMatch) {
            return {
              id: user.id,
              name: user.name,
              email: user.email,
              role: user.role
            };
          }
        }

        return null;
      }
    })
  ],
  callbacks: {
    ...authConfig.callbacks,
    session: async ({ session, user, trigger, token }: any) => {
      session.user.id = token.sub;
      session.user.role = token.role;
      session.user.name = token.name;

      if (trigger === 'update') {
        session.user.name = user.name;
      }

      return session;
    },
    jwt: async ({ token, user, trigger, session }: any) => {
      if (user) {
        token.role = user.role;

        if (user.name === 'NO_NAME') {
          token.name = user.email!.split('@')[0];

          if (user.id && token.name) {
            await prisma.user.update({
              where: { id: user.id },
              data: { name: token.name }
            });
          }
        }
      }

      return token;
    }
  }
};

export const { handlers, auth, signIn, signOut } = NextAuth(config);