// FP fixture: ownership clause uses a locally-extracted auth variable.
// `userId` is extracted from the authenticated session and joined into the
// WHERE clause alongside `req.params.id`. This is NOT an IDOR.
import { type Request, type Response } from 'express'

const authenticatedUsers = new Map<string, { data: { id: number } }>()

export function getAddressById () {
  return async (req: Request, res: Response) => {
    const loggedInUser = authenticatedUsers.get(req.headers?.authorization?.replace('Bearer ', ''))
    const userId = loggedInUser?.data?.id
    const address = await AddressModel.findOne({ where: { id: req.params.id, UserId: userId } })
    if (address != null) {
      res.status(200).json({ status: 'success', data: address })
    } else {
      res.status(400).json({ status: 'error', data: 'Malicious activity detected.' })
    }
  }
}

export function delAddressById () {
  return async (req: Request, res: Response) => {
    const loggedInUser = authenticatedUsers.get(req.headers?.authorization?.replace('Bearer ', ''))
    const userId = loggedInUser?.data?.id
    const address = await AddressModel.destroy({ where: { id: req.params.id, UserId: userId } })
    if (address) {
      res.status(200).json({ status: 'success', data: 'Address deleted successfully.' })
    } else {
      res.status(400).json({ status: 'error', data: 'Malicious activity detected.' })
    }
  }
}

declare const AddressModel: any
