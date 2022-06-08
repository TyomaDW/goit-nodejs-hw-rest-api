const mongoose = require('mongoose')
const { Schema, model, SchemaTypes } = mongoose

const mongoosePaginate = require('mongoose-paginate-v2')

const contact = new Schema({
  name: {
    type: String,
    required: [true, 'Set name for contact'],
  },
  email: {
    type: String,
  },
  phone: {
    type: String,
  },
  favorite: {
    type: Boolean,
    default: false,
  },
  owner: {
    type: SchemaTypes.ObjectId,
    ref: 'user',
  }
})

contact.plugin(mongoosePaginate)

const Contact = model('contact', contact)

module.exports = Contact
