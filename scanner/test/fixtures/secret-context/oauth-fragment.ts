// FP fixture: '#access_token=' is the OAuth 2.0 implicit-grant URL fragment anchor.
// It is a literal spec-defined string, not a credential.
export function oauthMatcher (url: any) {
  const path = window.location.href
  if (path.includes('#access_token=')) {
    return ({ consumed: url })
  }
  return null
}

declare const window: any
