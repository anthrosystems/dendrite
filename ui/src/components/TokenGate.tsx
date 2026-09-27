import { useState } from 'react'
import type { FormEvent } from 'react'
import { setStoredToken } from '../api/token'

interface Props {
  onSubmit: () => void
}

/**
 * Shown once, only in a packaged/production build where the browser has
 * seen a 401 from dendrited's HTTP API and has no stored token yet. In
 * dev, the Vite proxy injects the token itself (see vite.config.ts), so
 * this never renders there.
 *
 * The token is retrieved by running `dendrite-cli http-token` on the host
 * dendrited is running on (it's deliberately only ever exposed over the
 * Unix socket, never served automatically by the HTTP API itself).
 */
export function TokenGate({ onSubmit }: Props) {
  const [value, setValue] = useState('')

  const submit = (event: FormEvent) => {
    event.preventDefault()
    if (!value.trim()) return
    setStoredToken(value)
    onSubmit()
  }

  return (
    <div className="token-gate">
      <form className="token-gate-card" onSubmit={submit}>
        <h1>Dendrite</h1>
        <p>
          This UI needs the HTTP API token before it can reach the local dendrited daemon. Run{' '}
          <code>dendrite-cli http-token</code> on the machine running dendrited and paste the
          result below.
        </p>
        <input
          type="password"
          autoFocus
          placeholder="API token"
          value={value}
          onChange={event => setValue(event.target.value)}
        />
        <button type="submit" disabled={!value.trim()}>
          Connect
        </button>
      </form>
    </div>
  )
}
