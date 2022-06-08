const {
  getListContacts,
  getContactById,
  addContact,
  removeContact,
  updateContact,
  updateStatusContact,
} = require('../services/contactsServices')

const getListContactsController = async (req, res) => {
  const { user: id, query } = req

  const contacts = await getListContacts(id, query)

  return res.status('200')
    .json({ status: 'success', ...contacts })
}

const getContactByIdController = async (req, res) => {
  const { user: id, params: contactId } = req

  const contact = await getContactById(id, contactId)

  return !contact
    ? res.status('404').json({ status: 'error', message: 'Not found' })
    : res.status('200').json({ status: 'success', contact })
}

const addContactController = async (req, res) => {
  const { user: id, body } = req

  const contact = await addContact(id, body)

  return res.status('201')
    .json({ status: 'success', contact })
}

const removeContactController = async (req, res) => {
  const { user: id, params: contactId } = req

  const contact = await getContactById(id, contactId)

  if (contact) {
    await removeContact(id, contactId)
    return res.status('200')
      .json({ status: 'success', message: `contact ID:${contact.id} deleted` })
  } else {
    return res.status('404')
      .json({ status: 'error', message: 'Not found' })
  }
}

const updateContactController = async (req, res) => {
  const { user: id, params: contactId, body } = req

  const contact = await updateContact(id, contactId, body)

  return !contact
    ? res.status('404').json({ status: 'error', message: 'Not found' })
    : res.status('200').json({ status: 'success', contact })
}

const updateStatusContactController = async (req, res, next) => {
  const { user: id, params: contactId, body } = req

  const contact = await updateStatusContact(id, contactId, body)

  return !contact
    ? res.status('400')
      .json({ status: 'error', message: 'missing field favorite' })
    : res.status('200').json({ status: 'success', contact })
}

module.exports = {
  getListContactsController,
  getContactByIdController,
  addContactController,
  removeContactController,
  updateContactController,
  updateStatusContactController,
}
