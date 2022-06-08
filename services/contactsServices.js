const Contact = require('../schemas/contactsSchema')

const getListContacts = async (userId, query) => {
  const {
    page = 1, limit = 20, sortBy, sortByDesc, filter, favorite = null
  } = query

  const search = { owner: userId }

  if (favorite !== null) {
    search.favorite = favorite
  }

  const result = await Contact.paginate(search, {
    page,
    limit,
    sort: {
      ...(sortBy ? { [`${sortBy}`]: 1 } : {}),
      ...(sortByDesc ? { [`${sortByDesc}`]: -1 } : {}),
    },
    select: filter ? filter.split('|').join(' ') : '',
    populate: { path: 'owner', select: 'email subscription' },
  })

  const { docs: contacts, totalDocs: total, totalPages } = result

  return {
    contacts, total, totalPages, page: Number(page), limit: Number(limit),
  }
}

const getContactById = async (userId, contactId) => {
  const contact = await Contact.findOne({
    _id: contactId,
    owner: userId
  }).populate({ path: 'owner', select: 'email subscription' })
    .select({ __v: 0 })
  return contact
}

const addContact = async (userId, body) => {
  const contactNew =
        await Contact.create({ ...body, owner: userId })
  return contactNew
}

const removeContact = async (userId, contactId) => {
  const contactRemoved =
        await Contact.findOneAndRemove({ _id: contactId, owner: userId })
  return contactRemoved
}

const updateContact = async (userId, contactId, body) => {
  const contactUpdated =
    await Contact.findOneAndUpdate(
      { _id: contactId, owner: userId },
      body,
      { new: true })
      .populate({ path: 'owner', select: 'email subscription' })
      .select({ __v: 0 })
  return contactUpdated
}

const updateStatusContact = async (userId, contactId, { favorite }) => {
  const statusUpdated =
    await Contact.findOneAndUpdate(
      { _id: contactId, owner: userId },
      { favorite },
      { new: true })
      .populate({ path: 'owner', select: 'email subscription' })
      .select({ __v: 0 })
  return statusUpdated
}

module.exports = {
  getListContacts,
  getContactById,
  addContact,
  removeContact,
  updateContact,
  updateStatusContact,
}
