const mongoose = require('mongoose')
const bcrypt = require('bcryptjs')

const { Schema, model } = mongoose
const gravatar = require('gravatar')
const { Subscription } = require('../helpers/subscription')

const { STARTER, PRO, BUSINESS } = Subscription

const userSchema = new Schema({
  password: {
    type: String,
    required: [true, 'Password is required'],
  },
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
  },
  subscription: {
    type: String,
    enum: [STARTER, PRO, BUSINESS],
    default: STARTER,
  },
  token: {
    type: String,
    default: null,
  },
  avatarURL: {
    type: String,
    default: function () {
      return gravatar.url(this.email, { s: '250' }, true)
    },
  },
  verify: {
    type: Boolean,
    default: false,
  },
  verifyToken: {
    type: String,
    required: [true, 'Verify token is required'],
  },
})

userSchema.pre('save', async function () {
  if (this.isNew) {
    this.password = await bcrypt.hash(this.password, 10)
  }
})

userSchema.methods.validPassword = async function (password) {
  const result = await bcrypt.compare(password, this.password)
  return result
}

userSchema.path('email').validate(function (value) {
  const emailRegEx = /^([\w-]+(?:\.[\w-]+)*)@((?:[\w-]+\.)*\w[\w-]{0,66})\.([a-z]{2,6}(?:\.[a-z]{2})?)$/i
  return emailRegEx.test(String(value).toLowerCase())
})

const User = model('user', userSchema)

module.exports = User
