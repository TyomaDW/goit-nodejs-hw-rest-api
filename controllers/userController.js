const fs = require('fs').promises
const path = require('path')

const { login, logout } = require('../services/authServices')
const {
  createUser,
  findUserById,
  findUserByEmail,
  updateSubscription,
  updateAvatar,
} = require('../services/userServices')
const { editAvatar } = require('../helpers/avatarEditor')

const AVATARS_DIR = path.join(
  process.cwd(),
  process.env.PUBLIC_DIR,
  process.env.FOLDER_AVATARS,
)

const registrationController = async (req, res) => {
  const { body } = req
  const user = await findUserByEmail(body.email)

  if (user) {
    return res.status(409)
      .json({ message: 'Email in use' })
  }

  const { email, subscription, avatarURL } = await createUser(body)

  res.status(201)
    .json({ user: { email, subscription, avatarURL } })
}

const loginController = async (req, res) => {
  const { body } = req
  const token = await login(body)

  if (token) {
    const { email, subscription, avatarURL } = await findUserByEmail(body.email)
    return res.status(200)
      .json({ token, user: { email, subscription, avatarURL } })
  }

  res.status(401)
    .json({ message: 'Email or password is wrong' })
}

const logoutController = async (req, res) => {
  const { user: id } = req
  await logout(id)
  res.status(204).json({ message: 'No Content' })
}

const currentUserController = async (req, res) => {
  const { user: id } = req
  const currentUser = await findUserById(id)

  if (currentUser) {
    const { email, subscription, avatarURL } = currentUser
    res.status(200)
      .json({ email, subscription, avatarURL })
  }
}

const subscriptionController = async (req, res) => {
  const id = req.user.id
  const subscription = req.body.subscription

  const result = await updateSubscription(id, subscription)

  if (result) {
    const { email, subscription } = result
    res.status(200)
      .json({ user: { email, subscription }, status: 'updated' })
  }
}

const avatarController = async (req, res) => {
  const { user, file, protocol, headers } = req
  const filePath = file.path
  const name = file.filename
  const host = headers.host
  const id = user.id

  if (req.file) {
    await editAvatar(filePath)
    await fs.rename(filePath, path.join(AVATARS_DIR, name))

    const newAvatarURL =
      `${protocol}://${host}/${process.env.FOLDER_AVATARS}/${name}`

    console.log(newAvatarURL)

    const url = await updateAvatar(id, newAvatarURL)

    return res.status(200).json({ avatarURL: url })
  }

  res.status(400).json({ message: 'Please, provide a valid file' })
}

module.exports = {
  registrationController,
  loginController,
  logoutController,
  currentUserController,
  subscriptionController,
  avatarController,
}
