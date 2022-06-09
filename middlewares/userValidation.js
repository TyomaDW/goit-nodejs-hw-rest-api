const Joi = require('joi')

const { Subscription } = require('../helpers/subscription')

const { STARTER, PRO, BUSINESS } = Subscription

const schemaRegLogUser = Joi.object({
  email: Joi.string()
    .email({ minDomainSegments: 2, tlds: { allow: ['com', 'net', 'org', 'ru', 'ua'] } })
    .pattern(
      /^([\w-]+(?:\.[\w-]+)*)@((?:[\w-]+\.)*\w[\w-]{0,66})\.([a-z]{2,6}(?:\.[a-z]{2})?)$/i)
    .required(),
  password: Joi.string()
    .pattern(/^((?=\S*?[A-Z])(?=\S*?[a-z])(?=\S*?[0-9]).{6,})\S$/)
    .required(),
  subscription: Joi.string().default(STARTER),
})

const schemaSubscriptionUser = Joi.object({
  subscription: Joi.any()
    .valid(STARTER, PRO, BUSINESS)
    .required(),
})

const validate = (schema, req, res, next) => {
  const validationData = schema.validate(req.body)

  if (validationData.error) {
    return res.status(400)
      .json({ message: validationData.error.message.replace(/"/g, '') })
  }
  next()
}

module.exports = {
  validationRegLog: (req, res, next) => {
    return validate(schemaRegLogUser, req, res, next)
  },
  validationSubscription: (req, res, next) => {
    return validate(schemaSubscriptionUser, req, res, next)
  }
}
