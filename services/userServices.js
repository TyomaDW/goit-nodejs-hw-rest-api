const User = require('../schemas/userSchema')

const createUser = async (body) => {
  const user = await new User(body)

  return user.save()
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
  findUserById,
  findUserByEmail,
  updateToken,
  updateSubscription,
  updateAvatar,
}
