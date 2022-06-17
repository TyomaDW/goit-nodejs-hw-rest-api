const sgMail = require('@sendgrid/mail')
const Mailgen = require('mailgen')

const PORT = process.env.PORT

sgMail.setApiKey(process.env.SENDGRID_API_KEY)

const createTemplate = (verifyToken, email) => {
  const mailGenerator = new Mailgen({
    theme: 'default',
    product: {
      name: 'System Contacts',
      link: `http://localhost:${PORT}/`,
    },
  })

  const template = {
    body: {
      name: email,
      intro:
        "Welcome to System Contacts! We're very excited to have you on board.",
      action: {
        instructions: 'To get started with System Contacts, please click here:',
        button: {
          color: '#22BC66',
          text: 'Confirm your account',
          link: `http://localhost:${PORT}/api/users/verify/${verifyToken}`,
        },
      },
      outro:
        "Need help, or have questions? Just reply to this email, we'd love to help.",
    },
  }

  const emailBody = mailGenerator.generate(template)
  return emailBody
}

const sendEmail = async (verifyToken, email) => {
  const emailBody = createTemplate(verifyToken, email)

  const msg = {
    to: email,
    from: 'glazyrinsb@gmail.com',
    subject: 'Sending with SendGrid is Fun',
    text: 'and easy to do anywhere, even with Node.js',
    html: emailBody,
  }

  await sgMail.send(msg)
}

module.exports = { sendEmail }
