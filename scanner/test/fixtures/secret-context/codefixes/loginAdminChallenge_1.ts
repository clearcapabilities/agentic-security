// Educational code-fixture file (fixture name mirrors juice-shop/data/static/codefixes).
// Contains a SQL query template with an interpolated request value. Should NOT
// be flagged as Hardcoded Secret — the variable interpolation is the credential
// path; the literal `password = '${...}'` is just SQL syntax.
export function login () {
  return (req: any, res: any) => {
    models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`)
  }
}

declare const models: any
declare const security: any
