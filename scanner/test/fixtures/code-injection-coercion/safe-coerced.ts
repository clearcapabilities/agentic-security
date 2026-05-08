// FP fixture: req.body.captchaId is coerced via parseInt(..., 10) and NaN-checked
// before reaching any sink. Should not fire as Code Injection critical.
import { type Request, type Response } from 'express'

export const verifyCaptcha = () => async (req: Request, res: Response) => {
  const captchaId = parseInt(req.body.captchaId, 10)
  if (isNaN(captchaId)) {
    res.status(401).send('Wrong answer.')
    return
  }
  const captcha = await CaptchaModel.findOne({ where: { captchaId } })
  if ((captcha != null) && req.body.captcha === captcha.answer) {
    res.json({ ok: true })
  } else {
    res.status(401).send('Wrong answer.')
  }
}

declare const CaptchaModel: any
