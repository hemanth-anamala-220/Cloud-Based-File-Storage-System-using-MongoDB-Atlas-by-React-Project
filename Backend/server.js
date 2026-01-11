const express = require('express');
const cors = require('cors');
const { MongoClient, ObjectId } = require('mongodb');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

/**
 * Cloud File Storage System
 * Copyright (c) 2025 Hemanth Anamala. All Rights Reserved.
 */

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-this-in-production-12345';

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// MongoDB Connection
const MONGODB_URI = process.env.MONGODB_URI;
const DB_NAME = 'fileStorage';

let db;
let filesCollection;
let usersCollection;

async function connectToDatabase() {
    try {
        console.log('🔄 Attempting to connect to MongoDB...');
        
        const client = new MongoClient(MONGODB_URI, {
            serverSelectionTimeoutMS: 5000,
            socketTimeoutMS: 45000,
        });
        
        await client.connect();
        await client.db("admin").command({ ping: 1 });
        console.log('✅ Successfully connected to MongoDB Atlas');
        
        db = client.db(DB_NAME);
        filesCollection = db.collection('files');
        usersCollection = db.collection('users');
        
        await filesCollection.createIndex({ uploadDate: -1 });
        await filesCollection.createIndex({ filename: 1 });
        await filesCollection.createIndex({ userId: 1 });
        await usersCollection.createIndex({ email: 1 }, { unique: true });
        
        console.log('✅ Database collections and indexes ready');
    } catch (error) {
        console.error('❌ MongoDB Connection Error:', error.message);
        process.exit(1);
    }
}

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

app.post('/api/auth/register', async (req, res) => {
    try {
        const { email, password, name } = req.body;

        if (!email || !password || !name) {
            return res.status(400).json({ error: 'All fields required' });
        }

        const existingUser = await usersCollection.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'Email already registered' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        
        const result = await usersCollection.insertOne({
            email,
            password: hashedPassword,
            name,
            createdAt: new Date()
        });

        const token = jwt.sign(
            { userId: result.insertedId, email, name },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.status(201).json({
            success: true,
            token,
            user: { id: result.insertedId, email, name }
        });
    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({ error: 'Registration failed' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password required' });
        }

        const user = await usersCollection.findOne({ email });
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign(
            { userId: user._id, email: user.email, name: user.name },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({
            success: true,
            token,
            user: { id: user._id, email: user.email, name: user.name }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

app.post('/api/files/upload', authenticateToken, async (req, res) => {
    try {
        const { filename, fileData, size, type } = req.body;

        if (!filename || !fileData) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        const fileDocument = {
            filename,
            fileData,
            size: size || 0,
            type: type || 'application/octet-stream',
            userId: req.user.userId,
            uploadDate: new Date()
        };

        const result = await filesCollection.insertOne(fileDocument);

        res.status(201).json({
            success: true,
            message: 'File uploaded successfully',
            fileId: result.insertedId,
            filename: filename
        });
    } catch (error) {
        console.error('Upload error:', error);
        res.status(500).json({ error: 'Upload failed' });
    }
});

app.get('/api/files', authenticateToken, async (req, res) => {
    try {
        const files = await filesCollection
            .find({ userId: req.user.userId }, { projection: { fileData: 0 } })
            .sort({ uploadDate: -1 })
            .toArray();

        res.json({
            success: true,
            count: files.length,
            files: files
        });
    } catch (error) {
        console.error('Get files error:', error);
        res.status(500).json({ error: 'Failed to retrieve files' });
    }
});

app.get('/api/files/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;

        if (!ObjectId.isValid(id)) {
            return res.status(400).json({ error: 'Invalid file ID' });
        }

        const file = await filesCollection.findOne({ 
            _id: new ObjectId(id),
            userId: req.user.userId 
        });

        if (!file) {
            return res.status(404).json({ error: 'File not found' });
        }

        res.json({
            success: true,
            file: file
        });
    } catch (error) {
        console.error('Get file error:', error);
        res.status(500).json({ error: 'Failed to retrieve file' });
    }
});

app.delete('/api/files/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;

        if (!ObjectId.isValid(id)) {
            return res.status(400).json({ error: 'Invalid file ID' });
        }

        const result = await filesCollection.deleteOne({ 
            _id: new ObjectId(id),
            userId: req.user.userId 
        });

        if (result.deletedCount === 0) {
            return res.status(404).json({ error: 'File not found' });
        }

        res.json({
            success: true,
            message: 'File deleted successfully'
        });
    } catch (error) {
        console.error('Delete error:', error);
        res.status(500).json({ error: 'Failed to delete file' });
    }
});

app.get('/api/stats', authenticateToken, async (req, res) => {
    try {
        const files = await filesCollection.find({ userId: req.user.userId }).toArray();
        
        const totalFiles = files.length;
        const totalSize = files.reduce((sum, file) => sum + (file.size || 0), 0);

        res.json({
            success: true,
            stats: {
                totalFiles,
                totalSize,
                averageFileSize: totalFiles > 0 ? totalSize / totalFiles : 0
            }
        });
    } catch (error) {
        console.error('Stats error:', error);
        res.status(500).json({ error: 'Failed to retrieve statistics' });
    }
});

app.get('/api/files/search/:query', authenticateToken, async (req, res) => {
    try {
        const { query } = req.params;
        
        const files = await filesCollection
            .find(
                { 
                    userId: req.user.userId,
                    filename: { $regex: query, $options: 'i' } 
                },
                { projection: { fileData: 0 } }
            )
            .sort({ uploadDate: -1 })
            .toArray();

        res.json({
            success: true,
            count: files.length,
            files: files
        });
    } catch (error) {
        console.error('Search error:', error);
        res.status(500).json({ error: 'Failed to search files' });
    }
});

app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        timestamp: new Date(),
        database: db ? 'connected' : 'disconnected'
    });
});

async function startServer() {
    await connectToDatabase();
    
    app.listen(PORT, () => {
        console.log('='.repeat(60));
        console.log('  Cloud File Storage System');
        console.log('  Copyright (c) 2025 Hemanth Anamala');
        console.log('='.repeat(60));
        console.log(`🚀 Server running on port ${PORT}`);
        console.log(`📡 API: http://localhost:${PORT}/api`);
        console.log(`🏥 Health: http://localhost:${PORT}/api/health`);
        console.log('='.repeat(60));
    });
}

startServer().catch(console.error);

process.on('SIGINT', async () => {
    console.log('\n🛑 Shutting down...');
    console.log('© 2025 Hemanth Anamala');
    process.exit(0);
});