// FP fixture: post-lookup ownership comparison with a guard. Should not fire IDOR critical/high.
import { type Request, type Response, type NextFunction } from 'express'

export function placeOrder () {
  return (req: Request, res: Response, next: NextFunction) => {
    const id = req.params.id
    BasketModel.findOne({ where: { id }, include: [{ model: ProductModel, as: 'Products' }] })
      .then(async (basket: any) => {
        if (basket != null) {
          const customer = security.authenticatedUsers.from(req)
          if (!customer || basket.UserId !== customer.data?.id) {
            next(new Error('Unauthorized access to basket.'))
            return
          }
          res.json({ ok: true, basket })
        }
      })
  }
}

declare const BasketModel: any
declare const ProductModel: any
declare const security: any
