const express = require('express');
const {z} = require('zod')
const bcrypt = require('bcrypt')
const mongoose = require('mongoose');
const ProfileModel = require('./Models/profiles');
const jwt = require("jsonwebtoken")
const cors = require("cors")
require('dotenv').config();

const app = express();
app.use(express.json());

app.use(cors());

const JWT_SECRET = process.env.JWT_SECRET
const SALT_ROUNDS = 10

mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log("Connected to MongoDB"))
    .catch((error) => console.error("MongoDB connection error: ", error));

const userSchema = z.object({
    name: z.string().min(4).max(20),
    email: z.string().min(10).max(30).email(),
    password: z.string().min(6).max(20)
})

const updatedSchema = z.object({
    name: z.string().min(4).max(20),
    email: z.string().min(10).max(30).email().optional(),
    currentPassword: z.string().min(6).max(20).optional(),
    newPassword: z.string().min(6).max(20).optional(),
})

const authenticateToken = (req,res,next) => {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]

    if(!token) {
        return res.status(401).json({
            message: "Authentication token required"
        })
    }

    try{
        const decoded = jwt.verify(token, JWT_SECRET)
        req.user = decoded
        next()
    } catch(e){
        return res.status(403).json({
            message: "Invalid or expired token"
        })
    }
}

const errorHandeling = (err, req, res, next) =>{
    console.error(err.stack)
    res.status(500).json({
        message: "Internal Server Error",
        error: process.env.NODE_ENV === 'development' ? err.message : undefined
    })
}

app.post("/register", async (req,res,next) =>{
   try{
    const parseResult = userSchema.safeParse(req.body)

    if(!parseResult.success){
        res.json({
            message: "Name or password are too short"
        })
        return
    }

    const {name,password,email} = req.body

    const existingUser = await ProfileModel.findOne({email})

    if(existingUser){
        return res.status(409).json({
            message: "Email already exists"
        })
    }

    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS)

    const user = await ProfileModel.create({
        name,
        email,
        password: hashedPassword
    })

    const token = jwt.sign({
        userId: user._id,
        name: user.name,
        email: user.email
    }, JWT_SECRET,{expiresIn: "1h"})

    res.status(201).json({
        message: "You are signed in",
        token,
        user: {
            name: user.name,
            email: user.email
        }
    })

    } catch(error){
        next(error)
    }
})

app.post("/login", async (req,res,next) =>{
    try {
        const {email,password} = req.body

        const user = await ProfileModel.findOne({email})

        if(!user) {
            return res.status(404).json({
                message: "User Not Found"
            })
        }
        const isPasswordValid = await bcrypt.compare(password, user.password)

        if(!isPasswordValid){
            return res.status(401).json({
                message: "Wrong Password"
            })
        }
        const token = jwt.sign({
            userId: user._id,
            name: user.name,
            email: user.email 
        },JWT_SECRET,{expiresIn:"1hr"})

        res.json({
            message: "Login Successful",
            token,
            user: {
                name: user.name,
                email: user.email
            }
        })
    } catch(error){
       next(error)
    }
})

app.put("/profile", authenticateToken, async (req,res,next) =>{
    try{
        const parseResult = updatedSchema.safeParse(req.body)

        if(!parseResult.success){
            return res.status(400).json({
                message: "Validation Failed",
                errors: parseResult.error.errors
            })
        }

        const { name, email, currentPassword, newPassword} = parseResult.data
        const user = await ProfileModel.findById(req.user.userId)

        if(!user){
            return res.status(404).json({
                message: "User not Found"
            })
        }

        if(currentPassword && newPassword) { 
            const isPasswordValid = await bcrypt.compare(currentPassword,user.password)
            if(!isPasswordValid) { 
                return res.status(401).json({
                    message: "Current Password is incorrect"
                })
            }

            user.password = await bcrypt.hash(newPassword, SALT_ROUNDS)
        }
        if(name) user.name = name
        if(email) {
            const existingUser = await ProfileModel.findOne({email, _id: { $ne: user._id }})

            if(existingUser){
                return res.status(409).json({
                    message: "Email already exists"
                })
            }
            user.email = email
        }

        await user.save()

        res.json({
            message: "Profile updated successfully",
            user: {
                name: user.name,
                email: user.email
            }
        })
    } catch(error){
        next(error)
    }
})

// Add a basic health check endpoint
app.get("/health", (req, res) => {
    res.json({ status: "healthy" });
});

app.use(errorHandeling)
 
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});