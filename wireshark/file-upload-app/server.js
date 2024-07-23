const express = require('express');
const multer = require('multer');
const cors = require('cors');
const path = require('path');

const app = express();
const port = 3000;

// Enable CORS for all origins


// Set up storage engine for multer
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/');
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + path.extname(file.originalname)); // Append the file extension
  }
});

const upload = multer({ storage: storage });

// Create uploads folder if it doesn't exist
const fs = require('fs');
const dir = './uploads';

if (!fs.existsSync(dir)){
  fs.mkdirSync(dir);
}
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
  });
// Handle file upload
app.post('/upload', upload.single('file'), (req, res) => {
    console.log(req)
    console.log(req.file)
  if (!req.file) {
    return res.status(400).send('No file uploaded.');
  }
  res.send(`File uploaded: ${req.file.filename}`);
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
