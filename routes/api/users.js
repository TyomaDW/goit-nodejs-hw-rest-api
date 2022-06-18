const express = require('express')
const router = express.Router()

const {
  registrationController,
  verifyController,
  reVerifyController,
  loginController,
  logoutController,
  currentUserController,
  subscriptionController,
  avatarController,
} = require('../../controllers/userController')

const {
  validationRegLog,
  validationSubscription,
  validationReVerify,
} = require('../../middlewares/userValidation')

const { asyncWrapper } = require('../../helpers/apiHelpers')

const { protect } = require('../../middlewares/authProtection')

const upload = require('../../helpers/upload')

router.post('/signup',
  validationRegLog, asyncWrapper(registrationController)
)

router.post('/login',
  validationRegLog, asyncWrapper(loginController)
)

router.post('/logout',
  protect, asyncWrapper(logoutController)
)

router.get('/current',
  protect, asyncWrapper(currentUserController)
)

router.patch('/subscription',
  protect, validationSubscription, asyncWrapper(subscriptionController)
)

router.patch('/avatars',
  protect, upload.single('avatar'), asyncWrapper(avatarController)
)

router.get('/verify/:verificationToken', asyncWrapper(verifyController))

router.get('/verify/', validationReVerify, asyncWrapper(reVerifyController))

module.exports = router
