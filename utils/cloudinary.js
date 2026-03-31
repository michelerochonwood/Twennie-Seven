const cloudinary = require('cloudinary').v2;
const { Readable } = require('stream');

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

console.log("✅ Cloudinary config loaded:");
console.log("cloud_name:", process.env.CLOUDINARY_NAME);
console.log("api_key:", process.env.CLOUDINARY_API_KEY ? '[REDACTED]' : 'undefined');
console.log("api_secret:", process.env.CLOUDINARY_API_SECRET ? '[REDACTED]' : 'undefined');

const uploadRawBuffer = (buffer, originalname, mimetype, folder = 'twennie_templates') => {
  return new Promise((resolve, reject) => {
    const safeOriginalName = originalname.replace(/[^\w.\-]/g, '_');
    const safePublicId = `${Date.now()}-${safeOriginalName}`;

    const stream = cloudinary.uploader.upload_stream(
      {
        resource_type: 'raw',
        folder,
        public_id: safePublicId,
        overwrite: false,
      },
      (error, result) => {
        if (error) return reject(error);

        if (!result?.secure_url) {
          return reject(new Error(`Cloudinary upload failed for file: ${originalname}`));
        }

        resolve({
          filename: originalname,
          mimetype: mimetype || 'application/octet-stream',
          url: result.secure_url
        });
      }
    );

    const readable = new Readable();
    readable._read = () => {};
    readable.push(buffer);
    readable.push(null);
    readable.pipe(stream);
  });
};

module.exports = {
  cloudinary,
  uploader: cloudinary.uploader,
  uploadRawBuffer
};

