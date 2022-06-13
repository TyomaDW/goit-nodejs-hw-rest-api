const Jimp = require('jimp')

const editAvatar = async (filePath) => {
  const image = await Jimp.read(filePath)

  await image.autocrop()
    .cover(
      250,
      250,
      Jimp.HORIZONTAL_ALIGN_CENTER || Jimp.VERTICAL_ALIGN_MIDDLE
    )
    .quality(80)
    .writeAsync(filePath)
}

module.exports = {
  editAvatar
}
