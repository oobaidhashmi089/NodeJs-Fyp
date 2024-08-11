import express from 'express';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import multer from 'multer';
import path from 'path';
import fs from 'fs';

const app = express();

app.use(cors());
app.use(express.json());
app.use('/uploads', express.static('uploads'));
const storage = multer.diskStorage({
  destination: './uploads/', // Directory to store images
  filename: (req, file, cb) => {
    cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname));
  }
});
const upload = multer({
  storage: storage,
  limits: { fileSize: 1000000 }, // Limit file size to 1MB
  fileFilter: (req, file, cb) => {
    checkFileType(file, cb);
  }
}).single('image');

function checkFileType(file, cb) {
  const filetypes = /jpeg|jpg|png|gif/;
  const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
  const mimetype = filetypes.test(file.mimetype);
  if (mimetype && extname) {
    return cb(null, true);
  } else {
    cb('Error: Images Only!');
  }
}



mongoose.connect("mongodb+srv://syedhashmi089:obaid123@cluster11.gwp1fno.mongodb.net/WidgetsWorld?retryWrites=true&w=majority", {
    
  }).then(() => {
    console.log('Connected to MongoDB Atlas');
  }).catch((error) => {
    console.error('Error connecting to MongoDB Atlas:', error);
  });

const userSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String,
  isAdmin: { type: Boolean, default: false },
});

const widgetSchema = new mongoose.Schema({
  widgetName: { type: String, required: true },
    status: {
    type: String,
    enum: ['Pending', 'Approved', 'Rejected'],
    default: 'Pending'
  },
  code: { type: String, required: true },
  category: { type: String, required: true },
  Image: { type: String, required: true },
  approvalDate: { type: Date },
  uploadDate: { type: Date, default: Date.now },
  updateDate: { type: Date },
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User1' },
  approved: { type: Boolean, default: false },
});

const User = mongoose.model('User1', userSchema);
const Widget = mongoose.model('Product', widgetSchema);

app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = new User({ username, email, password: hashedPassword });
  await user.save();
  res.status(201).send('User registered');
});

// app.post('/login', async (req, res) => {
//   const { email, password } = req.body;
//   const user = await User.findOne({ email });
//   if (!user || !await bcrypt.compare(password, user.password)) {
//     return res.status(400).send('Invalid credentials');
//   }
//   const token = jwt.sign({ userId: user._id }, 'secretKey');
//   res.json({token});
// });
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  
  if (!user || !await bcrypt.compare(password, user.password)) {
    return res.status(400).send('Invalid credentials');
  }
  
  const token = jwt.sign({ userId: user._id }, 'secretKey');
  
  res.json({
    token,
    user: {
      id: user._id,
      isAdmin: user.isAdmin
    }
  });
});





const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;
  console.log('Auth Header:', authHeader);
  
  const token = authHeader?.split(' ')[1];
  console.log('Token:', token);
  
  if (!token) return res.status(401).send('Unauthorized');
  try {
    const decoded = jwt.verify(token, 'secretKey');
    console.log('Decoded:', decoded);
    req.userId = decoded.userId;
    next();
  } catch (err) {
    console.log('Error:', err);
    res.status(401).send('Unauthorized');
  }
};

const adminMiddleware = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  console.log('Authorization Header:', authHeader);

  if (!authHeader) {
    return res.status(401).send('Unauthorized: No token provided');
  }

  const token = authHeader.split(' ')[1];
  console.log('Extracted Token:', token);

  if (!token) {
    return res.status(401).send('Unauthorized: Malformed token');
  }

  try {
    const decoded = jwt.verify(token, 'secretKey');
    console.log('Decoded Token:', decoded);

    const user = await User.findById(decoded.userId);
    console.log('User:', user);

    if (!user) {
      return res.status(401).send('Unauthorized: User not found');
    }

    if (!user.isAdmin) {
      return res.status(403).send('Forbidden: User is not an admin');
    }

    next();
  } catch (error) {
    console.error('JWT Verification Error:', error);
    return res.status(401).send('Unauthorized: Invalid token');
  }
};

// app.post('/widgets', authMiddleware, async (req, res) => {
//   const { widgetName, code, category, Image } = req.body;
//   const product = new Widget({ widgetName, code, category, Image, owner: req.userId, approved: false });
//   await product.save();
//   res.status(201).send('Widget created and pending approval');
// });

app.post('/widgets', authMiddleware, (req, res) => {
  upload(req, res, async (err) => {
    if (err) {
      return res.status(400).send({ message: err });
    } else {
      const { widgetName, code, category  } = req.body;
      const Image = req.file ? `/uploads/${req.file.filename}` : null;

      if (!Image) {
        return res.status(400).send('Image upload failed');
      }

      const widget = new Widget({
        widgetName,
        code,
        category,
        Image,
        owner: req.userId,
        approved: false
      });

      try {
        await widget.save();
        res.status(201).send('Widget created and pending approval');
      } catch (error) {
        console.error('Error saving widget:', error);
        res.status(500).send('Server error');
      }
    }
  });
});
// app.put('/widgets/:id', authMiddleware, async (req, res) => {
//   const { id } = req.params;
//   const { widgetName, code, category, Image } = req.body;
//   const widget = await Widget.findOneAndUpdate({ _id: id, owner: req.userId }, { widgetName, code, category, Image }, { new: true });
//   if (!widget) return res.status(404).send('Widget not found');
//   res.json(widget);
// });

// app.put('/widgets/:id', authMiddleware, async (req, res) => {
//   const { id } = req.params;
//   const { widgetName, code, category, Image } = req.body;
//   // Ensure that only the owner can update the widget
//   const widget = await Widget.findOne({ _id: id, owner: req.userId });
//   if (!widget) return res.status(404).send('Widget not found or unauthorized');
//   widget.widgetName = widgetName;
//   widget.code = code;
//   widget.category = category;
//   widget.Image = Image;
//   widget.updateDate = Date.now();
//   await widget.save();
//   res.json(widget);
// });
app.put('/widgets/:id', authMiddleware, (req, res) => {
  upload(req, res, async (err) => {
    if (err) {
      return res.status(400).send({ message: err });
    }

    const { id } = req.params;
    const { widgetName, code, category } = req.body;

    try {
      // Find the widget by id and owner
      const widget = await Widget.findOne({ _id: id, owner: req.userId });
      if (!widget) {
        return res.status(404).send('Widget not found or unauthorized');
      }

      // Update text fields
      widget.widgetName = widgetName;
      widget.code = code;
      widget.category = category;
      widget.updateDate = Date.now();

      // If a new image was uploaded, replace the old image
      if (req.file) {
        // Optional: Delete the old image file
        if (widget.Image) {
          fs.unlinkSync(`.${widget.Image}`);
        }

        widget.Image = `/uploads/${req.file.filename}`;
      }

      // Save the updated widget
      await widget.save();
      res.json(widget);
    } catch (error) {
      console.error('Error updating widget:', error);
      res.status(500).send('Server error');
    }
  });
});





app.put('/widgets/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const { widgetName, code, category, Image } = req.body;
  // Ensure that only the owner can update the widget
  const widget = await Widget.findOne({ _id: id, owner: req.userId });
  if (!widget) return res.status(404).send('Widget not found or unauthorized');
  widget.widgetName = widgetName;
  widget.code = code;
  widget.category = category;
  widget.Image = Image;
  widget.updateDate = Date.now();
  await widget.save();
  res.json(widget);
});


app.delete('/widgets/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const widget = await Widget.findByIdAndDelete(id);
  if (!widget) return res.status(404).send('Widget not found');
  res.status(204).send('Widget deleted');
});

app.get('/approvedwidgets', async (req, res) => {
  const widgets = await Widget.find({ approved: true }).populate('owner', 'username');
  res.json(widgets);
});

app.get('/widgets', async (req, res) => {
  const widgets = await Widget.find({ approved: false  }).populate('owner', 'username');
  res.json(widgets);
});

app.get('/my-widgets/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  try {
    const widget = await Widget.findOne({ _id: id, owner: req.userId });
    if (!widget) return res.status(404).send('Widget not found or you do not have permission to view it');
    res.json(widget);
  } catch (error) {
    console.error('Error fetching widget:', error);
    res.status(500).send('Server error');
  }
});

app.get('/my-widgets', authMiddleware, async (req, res) => {
  const widgets = await Widget.find({ owner: req.userId });
  res.json(widgets);
});

app.put('/admin/widgets/:id/approve', adminMiddleware, async (req, res) => {
  const { id } = req.params;
  const widget = await Widget.findByIdAndUpdate(id, { approved: true ,status : 'Approved'}, { new: true });
  if (!widget) return res.status(404).send('Widget not found');
  res.json(widget);
});

app.put('/admin/widgets/:id/reject', adminMiddleware, async (req, res) => {
  const { id } = req.params;
  const widget = await Widget.findByIdAndUpdate(id, { approved: false ,status : 'Rejected' }, { new: true });
  if (!widget) return res.status(404).send('Widget not found');
  res.json(widget);
});

app.put('/make-admin/:userId', async (req, res) => {
  const { userId } = req.params;
  await User.findByIdAndUpdate(userId, { isAdmin: true });
  res.send('User is now an admin');
});

app.listen(5000, () => console.log('Server running on port 5000'));
