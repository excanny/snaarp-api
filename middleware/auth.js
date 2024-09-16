import pkg from 'jsonwebtoken';
const { verify, JsonWebTokenError, NotBeforeError, TokenExpiredError } = pkg;
import User from './models/User';

export default (req, res, next) => {
  const authHeader = req.header('Authorization');
  if (!authHeader) {
    return res.status(401).json({ error: 'No token, authorization denied' });
  }
  
  const token = authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'Token format is invalid' });
  }

  try {
    const decoded = verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    next(); // Don't forget to call next() on success
  } catch (error) {
    if (error instanceof JsonWebTokenError) {
      console.error('Invalid Token:', error.message);
      return res.status(401).json({ error: 'Token is not valid' });
    } else if (error instanceof NotBeforeError) {
      console.error('Token Not Active:', error.message);
      return res.status(401).json({ error: 'Token not active yet' });
    } else if (error instanceof TokenExpiredError) {
      console.error('Token Expired:', error.message);
      return res.status(401).json({ error: 'Token expired' });
    } else {
      console.error('Token Verification Error:', error.message);
      return res.status(500).json({ error: 'Server error' });
    }
  }
};

export const authorizeAdmin = async (req, res, next) => {
  const user = await User.findById(req.user.userId);
  if (!user || !user.isAdmin) {
    return res.status(403).json({ status: false, message: 'Access denied.' });
  }
  next();
};