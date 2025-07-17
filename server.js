const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const QRCode = require('qrcode');
const { Server } = require('socket.io');
const http = require('http');
const axios = require('axios');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
  console.log('Created uploads directory');
}

// Initialize Express app
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static(uploadsDir));

// Configuration
const PORT = process.env.PORT || 5000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://jamestan1496:eventhive@cluster0.gf6vat2.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-here';
const CLUSTERING_SERVICE_URL = process.env.CLUSTERING_SERVICE_URL || 'http://localhost:5001';

// File upload configuration
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/');
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname));
  }
});
const upload = multer({ storage: storage });

// MongoDB connection
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => {
  console.log('Connected to MongoDB');
});

// MongoDB Schemas
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['organizer', 'attendee'], default: 'attendee' },
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  interests: [String],
  professionalRole: String,
  createdAt: { type: Date, default: Date.now }
});

const eventSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  date: { type: Date, required: true },
  time: { type: String, required: true },
  location: { type: String, required: true },
  organizer: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  image: String,
  maxAttendees: { type: Number, default: 100 },
  status: { type: String, enum: ['upcoming', 'live', 'completed'], default: 'upcoming' },
  sessions: [{
    title: String,
    speaker: String,
    speakerBio: String,
    startTime: String,
    endTime: String,
    description: String
  }],
  createdAt: { type: Date, default: Date.now }
});

const registrationSchema = new mongoose.Schema({
  event: { type: mongoose.Schema.Types.ObjectId, ref: 'Event', required: true },
  attendee: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  qrCode: String,
  checkedIn: { type: Boolean, default: false },
  checkInTime: Date,
  cluster: String,
  registrationDate: { type: Date, default: Date.now }
});

const sessionTrackingSchema = new mongoose.Schema({
  event: { type: mongoose.Schema.Types.ObjectId, ref: 'Event', required: true },
  attendee: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  session: String,
  joinTime: { type: Date, default: Date.now },
  leaveTime: Date,
  duration: Number
});

// Models
const User = mongoose.model('User', userSchema);
const Event = mongoose.model('Event', eventSchema);
const Registration = mongoose.model('Registration', registrationSchema);
const SessionTracking = mongoose.model('SessionTracking', sessionTrackingSchema);

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Role-based authorization middleware
const authorizeRole = (roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
};

// Utility functions
const generateQRCode = async (data) => {
  try {
    const qrCodeData = await QRCode.toDataURL(JSON.stringify(data));
    return qrCodeData;
  } catch (error) {
    throw new Error('QR code generation failed');
  }
};

const calculateClusteringMetrics = (clusters) => {
  // Simple clustering metrics calculation
  const totalPoints = clusters.reduce((sum, cluster) => sum + cluster.length, 0);
  const numClusters = clusters.length;
  const avgClusterSize = totalPoints / numClusters;
  
  return {
    totalPoints,
    numClusters,
    avgClusterSize,
    silhouetteScore: Math.random() * 0.5 + 0.5 // Mock silhouette score
  };
};

// Socket.IO connection handling
io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  socket.on('join_event', (eventId) => {
    socket.join(eventId);
    console.log(`User ${socket.id} joined event ${eventId}`);
  });

  socket.on('leave_event', (eventId) => {
    socket.leave(eventId);
    console.log(`User ${socket.id} left event ${eventId}`);
  });

  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);
  });
});

// API Routes

// Authentication routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password, firstName, lastName, role, interests, professionalRole } = req.body;
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      username, email, password: hashedPassword, firstName, lastName,
      role: role || 'attendee', interests: interests || [], professionalRole
    });
    await user.save();
    const token = jwt.sign({ userId: user._id, role: user.role }, JWT_SECRET, { expiresIn: '24h' });
    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: { id: user._id, username: user.username, email: user.email, role: user.role, firstName: user.firstName, lastName: user.lastName }
    });
  } catch (error) {
    res.status(500).json({ error: 'Registration failed' });
  }
});
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ userId: user._id, role: user.role }, JWT_SECRET, { expiresIn: '24h' });
    res.json({
      message: 'Login successful',
      token,
      user: { id: user._id, username: user.username, email: user.email, role: user.role, firstName: user.firstName, lastName: user.lastName }
    });
  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

app.post('/api/events', authenticateToken, authorizeRole(['organizer']), upload.single('image'), async (req, res) => {
  try {
    console.log('=== CREATE EVENT REQUEST ===');
    console.log('Request body:', req.body);
    console.log('Request file:', req.file);
    console.log('Request user:', req.user);
    
    const { title, description, date, time, location, maxAttendees, sessions } = req.body;

    // Comprehensive validation
    if (!title || !description || !date || !time || !location) {
      console.log('Missing required fields:', { title: !!title, description: !!description, date: !!date, time: !!time, location: !!location });
      return res.status(400).json({ 
        error: 'Missing required fields',
        required: ['title', 'description', 'date', 'time', 'location'],
        received: { title: !!title, description: !!description, date: !!date, time: !!time, location: !!location }
      });
    }

    // Validate date
    const eventDate = new Date(date);
    if (isNaN(eventDate.getTime())) {
      console.log('Invalid date format:', date);
      return res.status(400).json({ error: 'Invalid date format' });
    }

    // Validate time format
    if (!/^([01]?[0-9]|2[0-3]):[0-5][0-9]$/.test(time)) {
      console.log('Invalid time format:', time);
      return res.status(400).json({ error: 'Invalid time format. Use HH:MM format' });
    }

    // Validate that the event date is not in the past
    const currentDate = new Date();
    currentDate.setHours(0, 0, 0, 0);
    eventDate.setHours(0, 0, 0, 0);
    
    if (eventDate < currentDate) {
      console.log('Event date is in the past:', { eventDate, currentDate });
      return res.status(400).json({ 
        error: 'Cannot create event for a past date. Please select a current or future date.' 
      });
    }

    // Parse sessions safely
    let parsedSessions = [];
    if (sessions) {
      try {
        parsedSessions = JSON.parse(sessions);
        console.log('Parsed sessions:', parsedSessions);
      } catch (sessionParseError) {
        console.log('Failed to parse sessions:', sessionParseError);
        return res.status(400).json({ error: 'Invalid sessions format' });
      }
    }

    // Validate maxAttendees
    const maxAttendeesNum = maxAttendees ? parseInt(maxAttendees) : 100;
    if (isNaN(maxAttendeesNum) || maxAttendeesNum < 1) {
      return res.status(400).json({ error: 'Invalid maxAttendees value' });
    }

    console.log('Creating event with data:', {
      title,
      description,
      date: eventDate,
      time,
      location,
      organizer: req.user.userId,
      maxAttendees: maxAttendeesNum,
      image: req.file ? req.file.filename : null,
      sessions: parsedSessions
    });

    const event = new Event({
      title: title.trim(),
      description: description.trim(),
      date: eventDate,
      time,
      location: location.trim(),
      organizer: req.user.userId,
      maxAttendees: maxAttendeesNum,
      image: req.file ? req.file.filename : null,
      sessions: parsedSessions
    });

    console.log('Saving event to database...');
    await event.save();
    console.log('Event saved successfully:', event._id);

    console.log('Populating organizer data...');
    await event.populate('organizer', 'firstName lastName email');

    console.log('=== CREATE EVENT SUCCESS ===');
    res.status(201).json({
      message: 'Event created successfully',
      event
    });

  } catch (error) {
    console.error('=== CREATE EVENT ERROR ===');
    console.error('Error type:', error.name);
    console.error('Error message:', error.message);
    console.error('Error stack:', error.stack);
    
    // Handle specific MongoDB errors
    if (error.name === 'ValidationError') {
      const validationErrors = Object.values(error.errors).map(err => err.message);
      return res.status(400).json({ 
        error: 'Validation failed', 
        details: validationErrors 
      });
    }

    if (error.name === 'MongoError' || error.name === 'MongoServerError') {
      console.error('MongoDB error:', error);
      return res.status(500).json({ error: 'Database error occurred' });
    }

    // Generic error response
    res.status(500).json({ 
      error: 'Failed to create event',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

// Event update route with date validation
app.put('/api/events/:id', authenticateToken, authorizeRole(['organizer']), upload.single('image'), async (req, res) => {
  try {
    console.log('=== UPDATE EVENT REQUEST ===');
    console.log('Event ID:', req.params.id);
    console.log('Request body:', req.body);
    console.log('Request file:', req.file);
    console.log('Request user:', req.user);

    const eventId = req.params.id;

    // Validate event ID format
    if (!eventId || eventId === 'null' || eventId === 'undefined') {
      console.log('Invalid event ID:', eventId);
      return res.status(400).json({ error: 'Valid event ID is required' });
    }

    // Validate ObjectId format
    if (!mongoose.Types.ObjectId.isValid(eventId)) {
      console.log('Invalid ObjectId format:', eventId);
      return res.status(400).json({ error: 'Invalid event ID format' });
    }

    const { title, description, date, time, location, maxAttendees, sessions, status } = req.body;

    console.log('Finding event...');
    const event = await Event.findById(eventId);
    if (!event) {
      console.log('Event not found:', eventId);
      return res.status(404).json({ error: 'Event not found' });
    }

    console.log('Checking authorization...');
    if (event.organizer.toString() !== req.user.userId) {
      console.log('Unauthorized update attempt:', { organizer: event.organizer, user: req.user.userId });
      return res.status(403).json({ error: 'Not authorized to update this event' });
    }

    // Validate date if it's being updated
    if (date) {
      const eventDate = new Date(date);
      const currentDate = new Date();
      
      currentDate.setHours(0, 0, 0, 0);
      eventDate.setHours(0, 0, 0, 0);
      
      if (eventDate < currentDate) {
        return res.status(400).json({ 
          error: 'Cannot update event to a past date. Please select a current or future date.' 
        });
      }
    }

    const updateData = {
      title: title ? title.trim() : event.title,
      description: description ? description.trim() : event.description,
      date: date ? new Date(date) : event.date,
      time: time || event.time,
      location: location ? location.trim() : event.location,
      maxAttendees: maxAttendees ? parseInt(maxAttendees) : event.maxAttendees,
      status: status || event.status
    };

    if (req.file) {
      updateData.image = req.file.filename;
    }

    if (sessions) {
      try {
        updateData.sessions = JSON.parse(sessions);
      } catch (sessionParseError) {
        return res.status(400).json({ error: 'Invalid sessions format' });
      }
    }

    console.log('Updating event with data:', updateData);
    const updatedEvent = await Event.findByIdAndUpdate(
      eventId,
      updateData,
      { new: true, runValidators: true }
    ).populate('organizer', 'firstName lastName email');

    console.log('=== UPDATE EVENT SUCCESS ===');
    res.json({
      message: 'Event updated successfully',
      event: updatedEvent
    });

  } catch (error) {
    console.error('=== UPDATE EVENT ERROR ===');
    console.error('Error type:', error.name);
    console.error('Error message:', error.message);
    console.error('Error stack:', error.stack);
    
    if (error.name === 'ValidationError') {
      const validationErrors = Object.values(error.errors).map(err => err.message);
      return res.status(400).json({ 
        error: 'Validation failed', 
        details: validationErrors 
      });
    }

    if (error.name === 'CastError') {
      return res.status(400).json({ error: 'Invalid event ID format' });
    }

    res.status(500).json({ 
      error: 'Failed to update event',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});
app.delete('/api/events/:id', authenticateToken, authorizeRole(['organizer']), async (req, res) => {
  try {
    const eventId = req.params.id;

    // Validate event ID
    if (!mongoose.Types.ObjectId.isValid(eventId)) {
      return res.status(400).json({ error: 'Invalid event ID' });
    }

    // Find event
    const event = await Event.findById(eventId);
    if (!event) {
      return res.status(404).json({ error: 'Event not found' });
    }

    // Check authorization
    if (event.organizer.toString() !== req.user.userId) {
      return res.status(403).json({ error: 'Not authorized to delete this event' });
    }

    // Check if event has registrations
    const registrationCount = await Registration.countDocuments({ event: eventId });
    if (registrationCount > 0) {
      return res.status(400).json({ 
        error: `Cannot delete event with ${registrationCount} registered attendees. Please contact attendees first.` 
      });
    }

    // Delete the event
    await Event.findByIdAndDelete(eventId);

    // Also delete any remaining registrations (cleanup)
    await Registration.deleteMany({ event: eventId });

    // Delete any session tracking records
    await SessionTracking.deleteMany({ event: eventId });

    res.json({
      message: 'Event deleted successfully',
      eventId: eventId
    });

  } catch (error) {
    console.error('Delete event error:', error);
    res.status(500).json({ error: 'Failed to delete event' });
  }
});

// Registration routes
app.post('/api/events/:eventId/register', authenticateToken, async (req, res) => {
  try {
    const eventId = req.params.eventId;
    const userId = req.user.userId;

    // Check if event exists
    const event = await Event.findById(eventId);
    if (!event) {
      return res.status(404).json({ error: 'Event not found' });
    }

    // Check if user is already registered
    const existingRegistration = await Registration.findOne({
      event: eventId,
      attendee: userId
    });

    if (existingRegistration) {
      return res.status(400).json({ error: 'Already registered for this event' });
    }

    // Check if event is full
    const registrationCount = await Registration.countDocuments({ event: eventId });
    if (registrationCount >= event.maxAttendees) {
      return res.status(400).json({ error: 'Event is full' });
    }

    // Generate QR code
    const qrData = {
      eventId,
      userId,
      registrationId: new mongoose.Types.ObjectId().toString()
    };
    const qrCode = await generateQRCode(qrData);

    // Create registration
    const registration = new Registration({
      event: eventId,
      attendee: userId,
      qrCode
    });

    await registration.save();

    res.status(201).json({
      message: 'Registration successful',
      registration: {
        id: registration._id,
        eventId,
        qrCode,
        registrationDate: registration.registrationDate
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.get('/api/events/:eventId/registrations', authenticateToken, async (req, res) => {
  try {
    const eventId = req.params.eventId;

    // Check if user is organizer of the event
    const event = await Event.findById(eventId);
    if (!event) {
      return res.status(404).json({ error: 'Event not found' });
    }

    if (event.organizer.toString() !== req.user.userId && req.user.role !== 'organizer') {
      return res.status(403).json({ error: 'Not authorized to view registrations' });
    }

    const registrations = await Registration.find({ event: eventId })
      .populate('attendee', 'firstName lastName email interests professionalRole')
      .sort({ registrationDate: -1 });

    res.json(registrations);
  } catch (error) {
    console.error('Get registrations error:', error);
    res.status(500).json({ error: 'Failed to fetch registrations' });
  }
});
app.get('/api/events', async (req, res) => {
  try {
    const { search, status } = req.query;
    let query = {};
    if (search) query.$or = [{ title: { $regex: search, $options: 'i' } }, { description: { $regex: search, $options: 'i' } }];
    if (status) query.status = status;
    const events = await Event.find(query).populate('organizer', 'firstName lastName email').sort({ date: 1 });
    res.json(events);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch events' });
  }

  }
);

// Check-in routes
app.post('/api/checkin', authenticateToken, async (req, res) => {
  try {
    const { qrData } = req.body;

    if (!qrData) {
      return res.status(400).json({ error: 'QR data required' });
    }

    let parsedData;
    try {
      parsedData = JSON.parse(qrData);
    } catch (error) {
      return res.status(400).json({ error: 'Invalid QR data format' });
    }

    const { eventId, userId } = parsedData;

    // Find registration
    const registration = await Registration.findOne({
      event: eventId,
      attendee: userId
    }).populate('attendee', 'firstName lastName email');

    if (!registration) {
      return res.status(404).json({ error: 'Registration not found' });
    }

    if (registration.checkedIn) {
      return res.status(400).json({ error: 'Already checked in' });
    }

    // Update check-in status
    registration.checkedIn = true;
    registration.checkInTime = new Date();
    await registration.save();

    // Emit real-time update
    io.to(eventId).emit('checkin_update', {
      attendeeId: userId,
      attendeeName: `${registration.attendee.firstName} ${registration.attendee.lastName}`,
      checkInTime: registration.checkInTime
    });

    res.json({
      message: 'Check-in successful',
      attendee: {
        name: `${registration.attendee.firstName} ${registration.attendee.lastName}`,
        email: registration.attendee.email,
        checkInTime: registration.checkInTime
      }
    });
  } catch (error) {
    console.error('Check-in error:', error);
    res.status(500).json({ error: 'Check-in failed' });
  }
});

app.post('/api/events/:eventId/checkin-manual', authenticateToken, authorizeRole(['organizer']), async (req, res) => {
  try {
    const { attendeeId } = req.body;
    const eventId = req.params.eventId;

    // Verify organizer owns the event
    const event = await Event.findById(eventId);
    if (!event || event.organizer.toString() !== req.user.userId) {
      return res.status(403).json({ error: 'Not authorized' });
    }

    // Find and update registration
    const registration = await Registration.findOne({
      event: eventId,
      attendee: attendeeId
    }).populate('attendee', 'firstName lastName email');

    if (!registration) {
      return res.status(404).json({ error: 'Registration not found' });
    }

    registration.checkedIn = true;
    registration.checkInTime = new Date();
    await registration.save();

    // Emit real-time update
    io.to(eventId).emit('checkin_update', {
      attendeeId,
      attendeeName: `${registration.attendee.firstName} ${registration.attendee.lastName}`,
      checkInTime: registration.checkInTime
    });

    res.json({
      message: 'Manual check-in successful',
      attendee: {
        name: `${registration.attendee.firstName} ${registration.attendee.lastName}`,
        email: registration.attendee.email,
        checkInTime: registration.checkInTime
      }
    });
  } catch (error) {
    console.error('Manual check-in error:', error);
    res.status(500).json({ error: 'Manual check-in failed' });
  }
});

// Clustering routes
app.post('/api/events/:eventId/cluster', authenticateToken, authorizeRole(['organizer']), async (req, res) => {
  try {
    const eventId = req.params.eventId;
    const { algorithm = 'kmeans', numClusters = 3 } = req.body;

    // Verify organizer owns the event
    const event = await Event.findById(eventId);
    if (!event || event.organizer.toString() !== req.user.userId) {
      return res.status(403).json({ error: 'Not authorized' });
    }

    // Get registrations with attendee data
    const registrations = await Registration.find({ event: eventId })
      .populate('attendee', 'firstName lastName email interests professionalRole');

    if (registrations.length === 0) {
      return res.status(400).json({ error: 'No registrations found for clustering' });
    }

    // Prepare data for clustering
    const attendeeData = registrations.map(reg => ({
      id: reg.attendee._id,
      name: `${reg.attendee.firstName} ${reg.attendee.lastName}`,
      email: reg.attendee.email,
      interests: reg.attendee.interests || [],
      professionalRole: reg.attendee.professionalRole || 'unknown'
    }));

    try {
      // Call clustering microservice
      const response = await axios.post(`${CLUSTERING_SERVICE_URL}/cluster`, {
        data: attendeeData,
        algorithm,
        numClusters
      });

      const { clusters, metrics } = response.data;

      // Update registrations with cluster assignments
      for (let i = 0; i < clusters.length; i++) {
        const cluster = clusters[i];
        for (const attendeeId of cluster) {
          await Registration.findOneAndUpdate(
            { event: eventId, attendee: attendeeId },
            { cluster: `cluster_${i}` }
          );
        }
      }

      res.json({
        message: 'Clustering completed successfully',
        clusters,
        metrics,
        totalAttendees: attendeeData.length
      });
    } catch (clusteringError) {
      console.log('Clustering service unavailable, using fallback method');
      
      // Fallback: Simple rule-based clustering
      const clusterMap = new Map();
      const clusters = [];
      
      attendeeData.forEach(attendee => {
        const key = attendee.professionalRole || 'general';
        if (!clusterMap.has(key)) {
          clusterMap.set(key, []);
          clusters.push([]);
        }
        clusterMap.get(key).push(attendee.id);
        clusters[clusters.length - 1].push(attendee.id);
      });

      // Update registrations with cluster assignments
      let clusterIndex = 0;
      for (const [role, attendeeIds] of clusterMap) {
        for (const attendeeId of attendeeIds) {
          await Registration.findOneAndUpdate(
            { event: eventId, attendee: attendeeId },
            { cluster: `cluster_${clusterIndex}` }
          );
        }
        clusterIndex++;
      }

      const metrics = calculateClusteringMetrics(clusters);

      res.json({
        message: 'Clustering completed successfully (fallback method)',
        clusters: Array.from(clusterMap.values()),
        metrics,
        totalAttendees: attendeeData.length
      });
    }
  } catch (error) {
    console.error('Clustering error:', error);
    res.status(500).json({ error: 'Clustering failed' });
  }
});

app.get('/api/events/:eventId/clusters', authenticateToken, async (req, res) => {
  try {
    const eventId = req.params.eventId;

    // Get registrations with cluster data
    const registrations = await Registration.find({ event: eventId })
      .populate('attendee', 'firstName lastName email interests professionalRole')
      .sort({ cluster: 1 });

    // Group by cluster
    const clusterMap = new Map();
    registrations.forEach(reg => {
      const cluster = reg.cluster || 'unassigned';
      if (!clusterMap.has(cluster)) {
        clusterMap.set(cluster, []);
      }
      clusterMap.get(cluster).push({
        id: reg.attendee._id,
        name: `${reg.attendee.firstName} ${reg.attendee.lastName}`,
        email: reg.attendee.email,
        interests: reg.attendee.interests,
        professionalRole: reg.attendee.professionalRole,
        checkedIn: reg.checkedIn
      });
    });

    const clusters = Array.from(clusterMap.entries()).map(([name, members]) => ({
      name,
      members,
      size: members.length
    }));

    res.json(clusters);
  } catch (error) {
    console.error('Get clusters error:', error);
    res.status(500).json({ error: 'Failed to fetch clusters' });
  }
});

// Analytics routes
app.get('/api/events/:eventId/analytics', authenticateToken, authorizeRole(['organizer']), async (req, res) => {
  try {
    const eventId = req.params.eventId;

    // Verify organizer owns the event
    const event = await Event.findById(eventId);
    if (!event || event.organizer.toString() !== req.user.userId) {
      return res.status(403).json({ error: 'Not authorized' });
    }

    // Get analytics data
    const totalRegistrations = await Registration.countDocuments({ event: eventId });
    const totalCheckedIn = await Registration.countDocuments({ event: eventId, checkedIn: true });
    const clusterCount = await Registration.distinct('cluster', { event: eventId });

    // Get session tracking data
    const sessionData = await SessionTracking.find({ event: eventId })
      .populate('attendee', 'firstName lastName');

    const analytics = {
      totalRegistrations,
      totalCheckedIn,
      checkInRate: totalRegistrations > 0 ? (totalCheckedIn / totalRegistrations * 100).toFixed(2) : 0,
      totalClusters: clusterCount.filter(c => c && c !== 'unassigned').length,
      sessionEngagement: sessionData.length,
      avgSessionDuration: sessionData.reduce((sum, s) => sum + (s.duration || 0), 0) / sessionData.length || 0
    };

    res.json(analytics);
  } catch (error) {
    console.error('Analytics error:', error);
    res.status(500).json({ error: 'Failed to fetch analytics' });
  }
});

// Session tracking routes
app.post('/api/events/:eventId/sessions/:sessionId/join', authenticateToken, async (req, res) => {
  try {
    const { eventId, sessionId } = req.params;
    const userId = req.user.userId;

    // Check if user is registered for the event
    const registration = await Registration.findOne({
      event: eventId,
      attendee: userId
    });

    if (!registration) {
      return res.status(403).json({ error: 'Not registered for this event' });
    }

    // Create session tracking record
    const sessionTracking = new SessionTracking({
      event: eventId,
      attendee: userId,
      session: sessionId
    });

    await sessionTracking.save();

    // Emit real-time update
    io.to(eventId).emit('session_join', {
      sessionId,
      attendeeId: userId,
      joinTime: sessionTracking.joinTime
    });

    res.json({
      message: 'Joined session successfully',
      sessionId,
      joinTime: sessionTracking.joinTime
    });
  } catch (error) {
    console.error('Session join error:', error);
    res.status(500).json({ error: 'Failed to join session' });
  }
});

app.post('/api/events/:eventId/sessions/:sessionId/leave', authenticateToken, async (req, res) => {
  try {
    const { eventId, sessionId } = req.params;
    const userId = req.user.userId;

    // Find and update session tracking record
    const sessionTracking = await SessionTracking.findOne({
      event: eventId,
      attendee: userId,
      session: sessionId,
      leaveTime: { $exists: false }
    });

    if (!sessionTracking) {
      return res.status(404).json({ error: 'Session tracking record not found' });
    }

    const leaveTime = new Date();
    const duration = Math.round((leaveTime - sessionTracking.joinTime) / 1000 / 60); // Duration in minutes

    sessionTracking.leaveTime = leaveTime;
    sessionTracking.duration = duration;
    await sessionTracking.save();

    // Emit real-time update
    io.to(eventId).emit('session_leave', {
      sessionId,
      attendeeId: userId,
      leaveTime,
      duration
    });

    res.json({
      message: 'Left session successfully',
      sessionId,
      leaveTime,
      duration
    });
  } catch (error) {
    console.error('Session leave error:', error);
    res.status(500).json({ error: 'Failed to leave session' });
  }
});

// User profile routes
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    console.log('=== GET PROFILE ===');
    console.log('User ID:', req.user.userId);

    const user = await User.findById(req.user.userId).select('-password');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    console.log('Profile loaded for:', user.email);
    res.json(user);
  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch profile',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

app.put('/api/profile', authenticateToken, async (req, res) => {
  try {
    console.log('=== UPDATE PROFILE ===');
    console.log('User ID:', req.user.userId);
    console.log('Update data:', req.body);

    const { firstName, lastName, interests, professionalRole } = req.body;
    
    const updatedUser = await User.findByIdAndUpdate(
      req.user.userId,
      { firstName, lastName, interests, professionalRole },
      { new: true, runValidators: true }
    ).select('-password');

    if (!updatedUser) {
      return res.status(404).json({ error: 'User not found' });
    }

    console.log('Profile updated for:', updatedUser.email);
    res.json({
      message: 'Profile updated successfully',
      user: updatedUser
    });
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ 
      error: 'Failed to update profile',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

// My events route
app.get('/api/my-events', authenticateToken, async (req, res) => {
  try {
    console.log('=== GET MY EVENTS ===');
    console.log('User:', req.user);

    if (req.user.role === 'organizer') {
      // Get events created by organizer
      const events = await Event.find({ organizer: req.user.userId })
        .populate('organizer', 'firstName lastName email')
        .sort({ date: 1 });
      
      console.log(`Found ${events.length} events for organizer`);
      res.json(events);
    } else {
      // Get events registered by attendee
      const registrations = await Registration.find({ attendee: req.user.userId })
        .populate({
          path: 'event',
          populate: {
            path: 'organizer',
            select: 'firstName lastName email'
          }
        })
        .sort({ 'event.date': 1 });
      
      const events = registrations.map(reg => ({
        ...reg.event.toObject(),
        registrationId: reg._id,
        checkedIn: reg.checkedIn,
        cluster: reg.cluster
      }));
      
      console.log(`Found ${events.length} registered events for attendee`);
      res.json(events);
    }
  } catch (error) {
    console.error('Get my events error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch events',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});
// Get attendee's own registration for an event (ADD THIS TO YOUR BACKEND)
app.get('/api/events/:eventId/my-registration', authenticateToken, async (req, res) => {
  try {
    const eventId = req.params.eventId;
    const userId = req.user.userId;

    const registration = await Registration.findOne({
      event: eventId,
      attendee: userId
    }).populate('attendee', 'firstName lastName email');

    if (!registration) {
      return res.status(404).json({ error: 'Registration not found' });
    }

    res.json(registration);
  } catch (error) {
    console.error('Get my registration error:', error);
    res.status(500).json({ error: 'Failed to fetch registration' });
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || 'development'
  });
});
// 6. Add request logging middleware for debugging
app.use('/api', (req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.originalUrl}`);
  console.log('Headers:', req.headers);
  if (req.body && Object.keys(req.body).length > 0) {
    console.log('Body:', req.body);
  }
  next();
});
app.use('/api/*', (req, res) => {
  console.log(`404 - Route not found: ${req.method} ${req.originalUrl}`);
  res.status(404).json({ 
    error: 'API route not found',
    method: req.method,
    path: req.originalUrl,
    available_routes: [
      'GET /api/health',
      'POST /api/auth/login',
      'POST /api/auth/register',
      'GET /api/events',
      'POST /api/events',
      'GET /api/my-events',
      'GET /api/profile',
      'PUT /api/profile'
    ]
  });
});
app.use(cors({
  origin: [
    'http://localhost:3000',
    'http://localhost:8080',
    'http://127.0.0.1:5500',
    'https://jamestan1496.github.io/CST_3990_Frontend/' // Add your actual frontend domain
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Start server
server.listen(PORT, () => {
  console.log(`EventHive backend server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  server.close(() => {
    mongoose.connection.close(false, () => {
      console.log('Server closed');
      process.exit(0);
    });
  });
});

module.exports = app;