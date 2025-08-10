import expess from 'express';
import dotenv from 'dotenv';
import usermodel from '../models/usermodel.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

export const register = async (req, res) => {
    const {name, email, password} = req.body;
    if(!name||!email||!paasord){
        return res.json({ success:false, statuscode:401, message: "All fields are required"});
    }
    try{
        // Check if user already exists
        const existinguser = await usermodel.findOne(email);
        if(existinguser){
            return res.json({success : false, statuscode: 401, message: "User already exists"});
        }

        // Hash the password
        const hashedpassword = await bcrypt.hash(password, 10);
        if(!hashedpassword){
            return res.json({success: false, statuscode: 500, message: "Internal server error"});
        }   

        // Create new user
        const newuser = new usermodel({name, email, password});
        await newuser.save(); 

        //create token and  add the token to cookie
        const token = jwt.sign({id: newuser._id}, process.env.JWT_SECRET, {expiresIn: '1d'});
        res.cookie("token", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 24 * 60 * 60 * 1000 // 1 day
        });  

        return res.json({success: true, statuscode: 200, message: "NEW User registered successfully"});

    }catch(error){
        return res.json({success: false, statuscode: 500, message: "Internal server error"});
    }
}

export const login = async(req, res)=>{
    const {email, password} = req.body;
    if(!email||!password){
        return res.json({success: false, statuscode: 401, message: "email and password fields are required"});
    }
    try{
        // Check if user exists
        const user = await usermodel.findOne(email);
        if(!user){
            return res.json({success: false, statuscode: 401, message: "User does not exist"});
        }
        // Check password
        const isPasswordmatch = await bcrypt.compare(password, user.password);
        if(!isPasswordmatch){
            return res.json({success: false, statuscode: 401, message: "Invalid password"});
        }
        // Create token and add it to cookie
        const token = jwt.sign({id: user._id}, process.env.JWT_SECRET, {expiresIn: '1d'});
        res.cookie("token", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 24 * 60 * 60 * 1000 // 1 day
        });

        return res.json({success: true, statuscode: 200, message: "User logged in successfully"});
    }catch(error){
        return res.json({success: false, statuscode: 500, message: "Internal server error"});
    }
}

export const logout = async(req, res)=>{
    try{
        res.clearCookie("token", {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict'
        });
        return res.json({success: true, statuscode: 200, message: "User logged out successfully"});

    }catch(error){
        return res.json({success: false, statuscode: 500, message: "Internal server error"});
    }
}