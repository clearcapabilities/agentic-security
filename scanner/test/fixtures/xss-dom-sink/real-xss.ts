// TP fixture: localStorage value flows into innerHTML — should fire critical XSS.
export function renderUsername () {
  const name = localStorage.getItem('username')
  document.getElementById('user').innerHTML = name
}

declare const localStorage: any
declare const document: any
