// Run with: npm test (uses node's built-in test runner, no extra packages).
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { flareSolverrOutsideVPN } from './vpnIndexers.ts'

test('no FlareSolverr, or the built-in one: no warning needed', () => {
  assert.equal(flareSolverrOutsideVPN({}), false)
  assert.equal(flareSolverrOutsideVPN({ flareSolverrUrl: '  ' }), false)
  assert.equal(flareSolverrOutsideVPN({ flareSolverrUrl: 'http://127.0.0.1:8191' }), false)
  assert.equal(flareSolverrOutsideVPN({ flareSolverrUrl: 'http://localhost:8191/' }), false)
})

test('one at another address fetches outside the VPN', () => {
  assert.equal(flareSolverrOutsideVPN({ flareSolverrUrl: 'http://flaresolverr:8191' }), true)
  assert.equal(flareSolverrOutsideVPN({ flareSolverrUrl: 'http://192.168.1.20:8191' }), true)
})
