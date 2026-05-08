// TP fixture: req.body value flows directly into eval. Should fire critical.
import { type Request, type Response } from 'express'

export const evalEndpoint = () => (req: Request, res: Response) => {
  const expr = req.body.expression
  const result = eval(expr) // eslint-disable-line no-eval
  res.json({ result })
}
