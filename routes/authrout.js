import express from 'express';

const authrouter = express.Router();

import { register, login, logout } from '../controller/authcontroller.js';

authrouter.post('/register', register);
authrouter.post('/login', login);       
authrouter.get('/logout', logout);

export default authrouter;