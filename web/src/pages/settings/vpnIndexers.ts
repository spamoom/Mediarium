// Whether FlareSolverr fetches sites outside the VPN, for the note under "Send
// indexer traffic through the VPN". Only one on this machine (like the built-in
// one) can use the VPN. Kept apart from the page so it can be tested.
import type { Settings } from '../../api.ts'

export function flareSolverrOutsideVPN(s: Pick<Settings, 'flareSolverrUrl'>): boolean {
  const raw = s.flareSolverrUrl?.trim()
  if (!raw) return false
  try {
    const host = new URL(raw).hostname.toLowerCase()
    return !(host === 'localhost' || host === '[::1]' || host.startsWith('127.'))
  } catch {
    return true
  }
}
