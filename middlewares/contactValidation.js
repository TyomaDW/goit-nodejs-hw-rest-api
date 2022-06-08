const Joi = require('joi')
const JoiID = require('joi-oid')

const schemaAddContact = Joi.object({
  name: Joi.string()
    .min(3)
    .max(30)
    .required(),
  email: Joi.string()
    .email({
      minDomainSegments: 2,
      tlds: { allow: ['com', 'net', 'org', 'ru', 'ua'] },
    })
    .required(),
  phone: Joi.string()
    .pattern(/^[+]?[(]?[0-9]{3}[)]?[-\s]?[0-9]{3}[-\s]?[0-9]{4}$/)
    .required(),
  favorite: Joi.boolean().optional()
})

const schemaUpdateContact = Joi.object({
  name: Joi.string()
    .min(3)
    .max(30)
    .optional(),
  email: Joi.string()
    .email({
      minDomainSegments: 2,
      tlds: { allow: ['com', 'net', 'org', 'ru', 'ua'] }
    })
    .optional(),
  phone: Joi.string()
    .pattern(/^[+]?[(]?[0-9]{3}[)]?[-\s]?[0-9]{3}[-\s]?[0-9]{4}$/)
    .optional(),
  favorite: Joi.boolean().optional()
}).min(1)

const schemaUpdateStatusContact = Joi.object({
  favorite: Joi.boolean().required()
})

const schemaId = Joi.object({
  contactId: JoiID.objectId(),
})

const validate = (schema, req, res, next) => {
  const validationData = schema.validate(req.body)

  if (validationData.error) {
    return res.status(400)
      .json({ message: validationData.error.message.replace(/"/g, '') })
  }
  next()
}

const validateId = (schema, req, res, next) => {
  const validationID = schema.validate(req.params)

  if (validationID.error) {
    return res.status(400)
      .json({ message: validationID.error.message.replace(/"/g, '') })
  }
  next()
}

module.exports = {
  validationAddContact: (req, res, next) => {
    return validate(schemaAddContact, req, res, next)
  },

  validationUpdateContact: (req, res, next) => {
    return validate(schemaUpdateContact, req, res, next)
  },

  validationUpdateStatusContact: (req, res, next) => {
    return validate(schemaUpdateStatusContact, req, res, next)
  },

  validationId: (req, res, next) => {
    return validateId(schemaId, req, res, next)
  },
}
