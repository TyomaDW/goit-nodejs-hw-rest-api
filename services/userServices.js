const User = require('../schemas/userSchema')
const { nanoid } = require('nanoid')
const { sendEmail } = require('./emailServices')

const createUser = async (body) => {
  const verifyToken = nanoid()
  const { email } = body

  await sendEmail(verifyToken, email)

  const user = await new User({ ...body, verifyToken })
  console.log('created User: ', user)
  return user.save()
}

const verifyUser = async (token) => {
  const user = await User.findOne({ verifyToken: token })

  if (user) {
    await user.updateOne({ verify: true, verifyToken: null })
    return true
  } else {
    return false
  }
}

const reVerifyUser = async (email) => {
  const user = await User.findOne({ email, verify: false })

  if (user) {
    await sendEmail(user.verifyToken, email)
    return true
  }
}

const findUserById = async (id) => {
  const user = await User.findById(id)

  return user
}

const findUserByEmail = async (email) => {
  const user = await User.findOne({ email })

  return user
}

const updateToken = async (id, token) => {
  await User.updateOne({ _id: id }, { token })
}

const updateSubscription = async (id, subscription) => {
  const user = await User.findOneAndUpdate(
    { _id: id },
    { subscription },
    { new: true })

  return user
}

const updateAvatar = async (id, url) => {
  const { avatarURL } = await User.findOneAndUpdate(
    { _id: id },
    { avatarURL: url },
    { new: true },
  )

  return avatarURL
}

module.exports = {
  createUser,
  verifyUser,
  reVerifyUser,
  findUserById,
  findUserByEmail,
  updateToken,
  updateSubscription,
  updateAvatar,
}
