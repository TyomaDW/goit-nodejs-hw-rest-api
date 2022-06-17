const { findUserByEmail, updateToken } = require('./userServices')
const jwt = require('jsonwebtoken')

const SECRET_KEY = process.env.SECRET_KEY

const login = async ({ email, password }) => {
  const user = await findUserByEmail(email)
  const isValidPassword = await user?.validPassword(password)

  if (!user || !isValidPassword || !user.verify) {
    return null
  }

  const id = user.id
  const payload = { id }
  const token = jwt.sign(payload, SECRET_KEY, { expiresIn: '1h' })

  await updateToken(id, token)
  return token
}

const logout = async (id) => {
  const data = await updateToken(id, null)
  return data
}

module.exports = { login, logout }
