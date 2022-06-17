const jwt = require('jsonwebtoken')
const User = require('../services/userServices')

const SECRET_KEY = process.env.SECRET_KEY

const protect = async (req, res, next) => {
  if (
    !req.headers.authorization ||
    !req.headers.authorization.startsWith('Bearer')
  ) {
    return res.status(401).json({ message: 'Not authorized' })
  }

  try {
    const token = req.headers.authorization.split(' ')[1]

    jwt.verify(token, SECRET_KEY, async (error, decodedUser) => {
      const user = await User.findUserById(decodedUser?.id)

      if (
        error || !user || !user.token || user.token !== token
      ) {
        return res.status(401).json({ message: 'Invalid token' })
      }

      req.user = user
      next()
    })
  } catch (error) {
    next(error)
  }
}

module.exports = {
  protect
}
