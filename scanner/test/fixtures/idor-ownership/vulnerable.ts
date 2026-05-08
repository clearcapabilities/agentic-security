// TP fixture: req.params.id is the only WHERE constraint. No ownership check.
// Should still fire as IDOR after the change to the sanitizer.
import { type Request, type Response } from 'express'

export function getAddressById () {
  return async (req: Request, res: Response) => {
    const address = await AddressModel.findOne({ where: { id: req.params.id } })
    res.status(200).json({ status: 'success', data: address })
  }
}

export function delAddressById () {
  return async (req: Request, res: Response) => {
    const address = await AddressModel.destroy({ where: { id: req.params.id } })
    res.status(200).json({ status: 'success', data: 'Address deleted.' })
  }
}

// Even more obviously vulnerable: ownership column bound to a request-controlled value.
export function pretendingToCheckOwnership () {
  return async (req: Request, res: Response) => {
    const address = await AddressModel.findOne({ where: { id: req.params.id, UserId: req.body.userId } })
    res.status(200).json({ status: 'success', data: address })
  }
}

declare const AddressModel: any
