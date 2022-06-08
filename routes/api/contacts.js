const express = require('express')
const router = express.Router()

const {
  getListContactsController,
  getContactByIdController,
  addContactController,
  removeContactController,
  updateContactController,
  updateStatusContactController,
} = require('../../controllers/contactsController')

const {
  validationAddContact,
  validationUpdateContact,
  validationUpdateStatusContact,
  validationId,
} = require('../../middlewares/contactValidation')

const { asyncWrapper } = require('../../helpers/apiHelpers')

const { protect } = require('../../middlewares/authProtection')

router.use(protect)

router.get('/',
  asyncWrapper(getListContactsController))

router.get('/:contactId',
  validationId,
  asyncWrapper(getContactByIdController))

router.post('/',
  validationAddContact,
  asyncWrapper(addContactController))

router.delete('/:contactId',
  validationId,
  asyncWrapper(removeContactController))

router.put('/:contactId',
  [validationId, validationUpdateContact],
  asyncWrapper(updateContactController)
)

router.patch('/:contactId/favorite',
  [validationId, validationUpdateStatusContact],
  asyncWrapper(updateStatusContactController)
)

module.exports = router
