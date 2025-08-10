import express from 'express';
import dotenv from 'dotenv';
dotenv.config(); 
import cors from 'cors';
import cookieParser from 'cookie-parser';
import connectDB from './config/mongodb.js';
import authrouter from './routes/authrout.js';  

const app = express();

const port = process.nextTick.PORT || 7070;
connectDB();

app.use(express.json());
app.use(cookieParser());
app.use(cors({credentials: true}));

app.get("/", (req, res) =>{
    return res.send("API is running");
})
app.use('/api/auth', authrouter);


app.listen(port, ()=>{
    console.log(`server is up and running on port ${port}`);
});