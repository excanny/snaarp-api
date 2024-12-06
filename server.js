import express from 'express';
import { json } from 'express';
import { connect } from 'mongoose';
import cors from 'cors';
import helmet from 'helmet';
import dotenv from 'dotenv';
import authRoutes from './routes/auth.js';
import swaggerSetup from './swagger.js';
import http from 'http';
import { WebSocketServer } from 'ws';

dotenv.config();

const app = express();

app.use(cors());
app.use(json());
app.use(helmet());

swaggerSetup(app);

const server = http.createServer(app);

const wss = new WebSocketServer({ server });

const clients = new Set(); 

wss.on('connection', (ws) => {
  console.log('New WebSocket connection established');

  // Add client to the set of connected clients
  clients.add(ws);

  ws.on('message', (message) => {
    console.log(`Received message: ${message}`);
    
    // Broadcast message to all connected clients
    clients.forEach(client => {
      if (client !== ws) {
        client.send(message.toString());
      }
    });
  });

  ws.on('close', () => {
    console.log('WebSocket connection closed');
    // Remove client from the set
    clients.delete(ws);
  });
});

// Existing endpoints remain the same
app.get('/', (req, res) => {
  res.redirect('/swagger');
});

app.use('/api/auth', authRoutes);

// Endpoint to get connected clients count
app.get('/api/connected-clients', (req, res) => {
  res.json({ connectedClients: clients.size });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`WebSocket server running on ws://localhost:${PORT}`);
});