import AuthIndicator from 'components/auth-indicator'
import AuthGate from 'components/auth-gate'
import { Provider as NextAuthProvider } from 'next-auth/client'

const shouldApplyAuth =
  process.env.HASHI_ENV === 'production' || process.env.HASHI_ENV === 'preview'

export default function ConditionalAuthProvider({ children, session }) {
  return shouldApplyAuth ? (
    <NextAuthProvider session={session}>
      <AuthGate>
        {children}
        <AuthIndicator />
      </AuthGate>
    </NextAuthProvider>
  ) : (
    <>{children}</>
  )
}
