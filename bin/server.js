const app = require('../app')
const path = require('path')
const db = require('../model/db')
const { createFolderIsNotExist } = require('../helpers/foldersCreator')

const PORT = process.env.PORT || 3000
const UPLOAD_DIR = path.join(
  process.cwd(),
  process.env.UPLOAD_DIR
)
const AVATARS_DIR = path.join(
  process.cwd(),
  process.env.PUBLIC_DIR,
  process.env.FOLDER_AVATARS
)

const start = async () => {
  try {
    await db()
    app.listen(PORT, async () => {
      await createFolderIsNotExist(UPLOAD_DIR)
      await createFolderIsNotExist(AVATARS_DIR)
      console.log('\x1b[32m%s\x1b[0m',
        `Server running. Use our API on port: ${PORT}`)
    })
  } catch (error) {
    console.log('\x1b[31m%s\x1b[0m',
        `Server not running. Error message: ${error.message}`)
  }
}

start()
