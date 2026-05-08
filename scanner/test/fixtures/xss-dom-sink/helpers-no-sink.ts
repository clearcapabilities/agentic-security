// FP fixture: localStorage.getItem flows into jwtDecode and a string comparison.
// No DOM sink (innerHTML/bypassSecurityTrust/document.write/etc.) is reached.
// Should not fire as XSS critical.
export function waitForAdminLogIn () {
  return async () => {
    while (true) {
      let role = ''
      try {
        const token = localStorage.getItem('token')
        const decodedToken = jwtDecode(token)
        const payload = decodedToken as any
        role = payload.data.role
      } catch {
        console.log('Role from token could not be accessed.')
      }
      if (role === 'admin') {
        break
      }
      await sleep(100)
    }
  }
}

declare const localStorage: any
declare function jwtDecode (t: any): any
declare function sleep (n: number): Promise<void>
