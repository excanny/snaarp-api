import { Router } from 'express';
const router = Router();
import pkg from 'bcryptjs';
const { hash, compare } = pkg;
import pkg2 from 'jsonwebtoken';
const { sign } = pkg2;
import User from '../models/User.js';
//import {auth, authorizeAdmin} from '../middleware/auth.js';
import { exec } from 'child_process';
//import fs from 'fs';
import { promises as fs } from 'fs';
import path from 'path';

//const localFolder = 'C:/Snaarp';
//const remoteFolder = './snaarp';
//const lastSyncFile = `${localFolder}/.last_sync`;

/**
 * @swagger
 * /api/auth/signup:
 *   post:
 *     summary: Create a new account
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *             properties:
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       201:
 *         description: The created user
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/User'
 * 
 */

router.post('/signup', async (req, res) => {
  try {
    const { email, password } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ status: false, message: 'User already exists' });
      
    const hashedPassword = await hash(password, 10);
    const user = new User({ email, password: hashedPassword });
    await user.save();
    res.status(201).json({ status: true, message: 'User created successfully' });
  } catch (error) {
    res.status(500).json({ status: false, message: error });
  }
});

/**
 * @swagger
 * /api/auth/login:
 *   post:
 *     summary: Login a user
 *     tags: [Users]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Login successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: boolean
 *                 message:
 *                   type: string
 *                 data:
 *                   type: string
 *       401:
 *         description: Invalid credentials
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: boolean
 *                 message:
 *                   type: string
 *       500:
 *         description: Error logging in
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: boolean
 *                 message:
 *                   type: string
 */

router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate email and password are provided
    if (!email || !password) {
      return res.json({ status: false, message: 'Email and password are required' });
    }

    const user = await User.findOne({ email });

    console.log(user, "User Object")
    if (!user) {
      return res.json({ status: false, message: 'Invalid credentials' });
    }

    if (!user.isActive) {
      return res.json({ status: false, message: 'Account is not active' });
    }

    const isMatch = await compare(password, user.password);
    if (!isMatch) {
      return res.json({ status: false, message: 'Invalid credentials' });
    }

    const token = sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ status: true, message: 'Login successful', data: { token, user } });

  } catch (error) {
    console.error('Login error:', error);
    res.json({ status: false, message: 'Error logging in', error: error.message });
  }
});

router.post('/check-auth', async (req, res) => {
  try {
    const { userId } = req.body;
    const user = await User.findById(userId);
    if (!user) {
      return res.status(401).json({ status: false, message: 'Invalid user id', data: req });
    }

    res.json({ status: true, message: 'Login successful', data: user });
  } catch (error) {
    res.status(500).json({ status: false, message: 'Error logging in', data: error });
  }
});

router.get('/users', async (req, res) => {
  try {
    const users = await User.find();
    res.json({ status: true, message: 'Users retrieved successfully', data: users });
  } catch (error) {
    res.status(500).json({ status: false, message: 'Error retrieving users' });
  }
});


router.patch('/users/:id/activate', async (req, res) => {
  try {
    const userId = req.params.id;
    const { isActive } = req.body; // Expecting { isActive: true } or { isActive: false }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ status: false, message: 'User not found' });
    }

    user.isActive = isActive;
    await user.save();

    res.json({ status: true, message: `User ${isActive ? 'activated' : 'deactivated'} successfully`, data: user });
  } catch (error) {
    res.status(500).json({ status: false, message: 'Error updating user status' });
  }
});

// Example function to check if a file is encrypted
async function isFileEncrypted(filePath) {
  try {
    const fileHeaderSize = 24; // 'ENCRYPTED_' prefix (10 bytes) + IV (16 bytes)
    const fileHeader = Buffer.alloc(fileHeaderSize);

    const fd = await fs.open(filePath, 'r');
    try {
      const { bytesRead } = await fd.read(fileHeader, 0, fileHeaderSize, 0);
      if (bytesRead < fileHeaderSize) {
        return false; // File is smaller than expected header size, not encrypted
      }

      const prefix = fileHeader.slice(0, 10).toString();
      if (prefix === 'ENCRYPTED_') {
        return true; // File is likely encrypted
      }
    } finally {
      await fd.close();
    }

    return false; // Default to false if prefix not found
  } catch (error) {
    console.error(`Error checking if file is encrypted: ${error.message}`);
    return false; // Default to false if an error occurs
  }
}

router.post('/sync-files', async (req, res) => {
  const { localFolder } = req.body;
  const remoteFolder = './snaarp';
  const lastSyncFile = path.join(remoteFolder, '.last_sync');
  if (!localFolder) {
    return res.status(400).send('Local folder path is required');
  }
  try {
    await fs.mkdir(remoteFolder, { recursive: true });
    let lastSyncTime;
    try {
      lastSyncTime = parseInt(await fs.readFile(lastSyncFile, 'utf8'), 10);
    } catch (err) {
      console.log(`No previous sync time found. Starting fresh sync.`);
      lastSyncTime = 0;
    }
    const files = await fs.readdir(localFolder);
    let syncedFiles = 0;
    let skippedFiles = 0;
    for (const file of files) {
      if (file === '.last_sync') {
        continue; // Skip .last_sync file
      }
      const filePath = path.join(localFolder, file);
      // Check if the file is encrypted before any further processing
      if (await isFileEncrypted(filePath)) {
        console.log(`Skipping file: ${file} (encrypted)`);
        skippedFiles++;
        continue;
      }
      const stats = await fs.stat(filePath);
      const fileExtension = path.extname(file).toLowerCase();
      // Skip specific file extensions
      const skipExtensions = ['.ico', '.ini'];
      if (skipExtensions.includes(fileExtension)) {
        console.log(`Skipping file: ${file} (excluded extension)`);
        skippedFiles++;
        continue;
      }
      const remoteFilePath = path.join(remoteFolder, file);
      
      let shouldSync = false;
      try {
        const remoteStats = await fs.stat(remoteFilePath);
        // File exists in both places, check if local is newer
        shouldSync = stats.mtimeMs > remoteStats.mtimeMs;
      } catch (err) {
        // File doesn't exist in remote folder, so it's new
        shouldSync = true;
      }
      if (shouldSync) {
        await fs.copyFile(filePath, remoteFilePath);
        console.log(`Synced file: ${file}`);
        syncedFiles++;
      } else {
        console.log(`Skipping file: ${file} (not modified)`);
        skippedFiles++;
      }
    }
    await fs.writeFile(lastSyncFile, Date.now().toString());
    
    res.json({
      status: true,
      message: 'Sync completed successfully',
      data: {
        syncedFiles,
        skippedFiles,
        totalProcessed: syncedFiles + skippedFiles
      }
    });
  } catch (err) {
    console.error(`Error during sync process: ${err.message}`);
    res.status(500).json({
      status: 'error',
      message: 'Error syncing files',
      error: {
        description: err.message,
        code: err.code || 'UNKNOWN_ERROR'
      }
    });
  }
});

/**
 * @swagger
 * /api/auth/logout:
 *   post:
 *     summary: Logout a user
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Logout successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: boolean
 *                 message:
 *                   type: string
 *       500:
 *         description: Error logging out
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: boolean
 *                 message:
 *                   type: string
 */
router.post('/logout', async (req, res) => {
  try {
    // Since JWT tokens are stateless and stored on the client side, 
    // logging out typically involves clearing the token from the client.
    // For example, if using cookies, you would clear the cookie that holds the token.

    // For demonstration purposes, let's assume clearing a cookie named 'jwtToken':
    res.clearCookie('jwtToken');
    
    // Alternatively, if using local storage:
    // res.json({ status: true, message: 'Logged out successfully' });
    
    // Respond with success message
    res.json({ status: true, message: 'Logged out successfully' });
  } catch (error) {
    res.status(500).json({ status: false, message: 'Error logging out' });
  }
});


router.patch('/users/:id/activate', async (req, res) => {
  try {
    const userId = req.params.id;
    const { isActive } = req.body; // Expecting { isActive: true } or { isActive: false }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ status: false, message: 'User not found' });
    }

    user.isActive = isActive;
    await user.save();

    res.json({ status: true, message: `User ${isActive ? 'activated' : 'deactivated'} successfully`, data: user });
  } catch (error) {
    res.status(500).json({ status: false, message: 'Error updating user status' });
  }
});

// API routes for key management
router.post('/api/keys', async (req, res) => {
  const { keyId, keyValue } = req.body;

  // Encrypt the key value before storing
  const encryptedValue = encrypt(keyValue);

  try {
      // Store encrypted key in MongoDB
      const newKey = await EncryptedKey.create({ keyId, encryptedValue });
      res.json({ message: 'Key stored successfully', keyId: newKey.keyId });
  } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Failed to store key' });
  }
});

router.get('/api/keys/:keyId', (req, res) => {
  // Implement logic to retrieve encryption key from secure storage
  const keyId = req.params.keyId;
  // Example: Replace with your logic to retrieve key from secure storage
  const encryptionKey = retrieveEncryptionKeyFromSecureStorage(keyId);
  if (encryptionKey) {
      res.json({ key: encryptionKey });
  } else {
      res.status(404).json({ error: 'Key not found' });
  }
});

function encrypt(text) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
  let encrypted = cipher.update(text);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
  const parts = text.split(':');
  const iv = Buffer.from(parts[0], 'hex');
  const encryptedText = Buffer.from(parts[1], 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
  let decrypted = decipher.update(encryptedText);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString();
}


export default router;