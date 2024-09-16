import express from 'express';
import { json } from 'express';
import { connect } from 'mongoose';
import cors from 'cors';
import helmet from 'helmet';
import dotenv from 'dotenv';
import authRoutes from './routes/auth.js';
import swaggerSetup from './swagger.js';
import http from 'http';
import { WebSocket, WebSocketServer } from 'ws';

dotenv.config();

const app = express();

app.use(json());
app.use(cors());
app.use(helmet());

swaggerSetup(app);

connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('Connected to MongoDB'))
.catch((err) => console.error('MongoDB connection error:', err));

app.get('/', (req, res) => {
  res.redirect('/swagger');
});

app.use('/api/auth', authRoutes);

const server = http.createServer(app);

const wss = new WebSocketServer({ server });

const clients = new Map(); 

wss.on('connection', (ws) => {
  console.log('New WebSocket connection');

  // When the client sends its ID
  ws.on('message', (message) => {
    console.log(`Received message from client: ${message}`);

    try {
      const { clientId } = JSON.parse(message); // Assume the message contains clientId
      if (!clientId) {
        console.error('Client ID is missing');
        ws.close(); // Close connection if clientId is not provided
        return;
      }

      clients.set(clientId, ws); // Store the WebSocket connection with the client ID
      console.log(`Client connected with ID: ${clientId}`);

      // Optionally, you can send a welcome message or confirmation
      ws.send(JSON.stringify({ status: 'Connected', clientId }));

      ws.on('pong', () => {
        console.log('Received pong from client:', clientId);
      });

      ws.on('close', () => {
        console.log('WebSocket connection closed for client:', clientId);
        clients.delete(clientId); // Remove the client on disconnection
      });
    } catch (error) {
      console.error('Failed to parse WebSocket message:', error);
    }
  });

  // Ping interval to keep the connection alive
  const pingInterval = setInterval(() => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.ping();
    }
  }, 30000);

  ws.on('close', () => {
    clearInterval(pingInterval); // Clear the ping interval on close
  });
});

// Endpoint to get all connected clients
app.get('/api/connected-clients', (req, res) => {
  const connectedClients = Array.from(clients.entries()).map(([clientId, ws]) => ({
    clientId,
    readyState: ws.readyState
  }));

  res.json({ connectedClients });
});

// Endpoint to lock out a user
app.post('/api/lock-out-user', (req, res) => {
  const { userId } = req.body; // Get the user ID from the request body
  sendCommandToClient(userId, 'unlock-user', res); // Call the function to send the unlock command
});

// Endpoint to unlock a user
app.post('/api/unlock-user', (req, res) => {
  const { userId } = req.body; // Get the user ID from the request body
  sendCommandToClient(userId, 'unlock-user', res); // Call the function to send the unlock command
});

// Endpoint to disable usb
app.post('/api/disable-usb', (req, res) => {
  const { userId } = req.body; // Get the user ID from the request body
  sendCommandToClient(userId, 'disable-usb', res); // Call the function to send the unlock command
});

// Endpoint to disable usb
app.post('/api/enable-usb', (req, res) => {
  const { userId } = req.body; // Get the user ID from the request body
  sendCommandToClient(userId, 'enable-usb', res); // Call the function to send the unlock command
});

// Endpoint to disable usb
app.post('/api/encrypt-when-offline', (req, res) => {
  const { userId } = req.body; // Get the user ID from the request body
  sendCommandToClient(userId, 'encrypt-when-offline', res); // Call the function to send the unlock command
});

// Endpoint to disable usb
app.post('/api/disable-encrypt-when-offline', (req, res) => {
  const { userId } = req.body; // Get the user ID from the request body
  sendCommandToClient(userId, 'disable-encrypt-when-offline', res); // Call the function to send the unlock command
});

// Endpoint to wipe a device
app.post('/api/wipe-device', (req, res) => {
  const { userId } = req.body; // Get the user ID from the request body
  sendCommandToClient(userId, 'wipe-device', res); // Call the function to send the wipe command
});

// Function to send command to a specific client
const sendCommandToClient = (userId, commandType, res) => {
  const command = JSON.stringify({ command: commandType, clientId: userId });
  
  console.log(`Sending command to client ${userId}:`, command);

  const client = clients.get(userId); // Retrieve the specific client by user ID

  if (client && client.readyState === WebSocket.OPEN) {
    client.send(command); // Send the command to the specific client
    res.json({ status: `Command "${commandType}" sent to client ${userId}` });
  } else {
    res.status(404).json({ status: `Client ${userId} not found or not connected` });
  }
};

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`WebSocket server running on ws://localhost:${PORT}`);
});