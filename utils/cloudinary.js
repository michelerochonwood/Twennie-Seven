const cloudinary = require('cloudinary').v2;
const { Readable } = require('stream');

// Existing config (keep as-is)
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

console.log("✅ Cloudinary config loaded:");
console.log("cloud_name:", process.env.CLOUDINARY_NAME);
console.log("api_key:", process.env.CLOUDINARY_API_KEY ? '[REDACTED]' : 'undefined');
console.log("api_secret:", process.env.CLOUDINARY_API_SECRET ? '[REDACTED]' : 'undefined');

// ✅ New helper for raw (non-image) file uploads like PDFs, PPTs, DOCX
const uploadRawBuffer = (buffer, originalname, mimetype, folder = 'twennie_templates') => {
  return new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      {
        resource_type: 'raw',
        folder
      },
      (error, result) => {
        if (error) return reject(error);
        resolve({
          filename: originalname,
          mimetype,
          url: result.secure_url
        });
      }
    );

    const readable = new Readable();
    readable.push(buffer);
    readable.push(null);
    readable.pipe(stream);
  });
};

module.exports = {
  cloudinary,
  uploader: cloudinary.uploader,
  uploadRawBuffer // ✅ new export, optional for use in template controller only
};

