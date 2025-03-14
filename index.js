const express = require('express');
const {z} = require('zod')
const bcrypt = require('bcrypt')
const mongoose = require('mongoose');
const ProfileModel = require('./Models/profiles');
const WorkoutPlanModel = require('./Models/workoutPlans');
const FoodLogModel = require('./Models/foodLogs');
const jwt = require("jsonwebtoken")
const cors = require("cors")
const cloudinary = require('cloudinary').v2;
require('dotenv').config();

const app = express();
app.use(express.json({ limit: '10mb' }));

app.use(cors("*"));

app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    if (req.method === 'OPTIONS') {
        return res.status(200).json({});
    }
    next();
});

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

const errorHandeling = (err, req, res, next) => {
    console.error(err.stack);
    
    // Handle Zod validation errors
    if (err.name === 'ZodError') {
        return res.status(400).json({
            message: "Validation Error",
            errors: err.errors
        });
    }
    
    // Handle Mongoose validation errors
    if (err.name === 'ValidationError') {
        const errors = {};
        for (const field in err.errors) {
            errors[field] = err.errors[field].message;
        }
        return res.status(400).json({
            message: "Validation Error",
            errors
        });
    }
    
    // Handle other errors
    res.status(500).json({
        message: "Internal Server Error",
        error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
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

// Workout Plan Schema Validation
const workoutPlanSchema = z.object({
    name: z.string().min(3).max(50),
    description: z.string().max(200).optional(),
    days: z.array(
        z.object({
            name: z.string(),
            exercises: z.array(
                z.object({
                    id: z.string(),
                    name: z.string(),
                    muscle: z.string(),
                    gif_url: z.string(),
                    description1: z.string(),
                    description2: z.string(),
                    sets: z.number().optional(),
                    reps: z.number().optional()
                })
            )
        })
    )
})

// Workout Plan Routes
app.post('/api/workout-plans', authenticateToken, async (req, res, next) => {
    try {
        const validatedData = workoutPlanSchema.parse(req.body);
        
        const newWorkoutPlan = new WorkoutPlanModel({
            userId: req.user.userId,
            ...validatedData
        });
        
        const savedPlan = await newWorkoutPlan.save();
        res.status(201).json(savedPlan);
    } catch (error) {
        next(error);
    }
});

app.get('/api/workout-plans', authenticateToken, async (req, res, next) => {
    try {
        const workoutPlans = await WorkoutPlanModel.find({ userId: req.user.userId });
        res.status(200).json(workoutPlans);
    } catch (error) {
        next(error);
    }
});

app.get('/api/workout-plans/:id', authenticateToken, async (req, res, next) => {
    try {
        const workoutPlan = await WorkoutPlanModel.findOne({ 
            _id: req.params.id,
            userId: req.user.userId
        });
        
        if (!workoutPlan) {
            return res.status(404).json({ message: 'Workout plan not found' });
        }
        
        res.status(200).json(workoutPlan);
    } catch (error) {
        next(error);
    }
});

app.put('/api/workout-plans/:id', authenticateToken, async (req, res, next) => {
    try {
        const validatedData = workoutPlanSchema.parse(req.body);
        
        const updatedPlan = await WorkoutPlanModel.findOneAndUpdate(
            { _id: req.params.id, userId: req.user.userId },
            validatedData,
            { new: true }
        );
        
        if (!updatedPlan) {
            return res.status(404).json({ message: 'Workout plan not found' });
        }
        
        res.status(200).json(updatedPlan);
    } catch (error) {
        next(error);
    }
});

app.delete('/api/workout-plans/:id', authenticateToken, async (req, res, next) => {
    try {
        const deletedPlan = await WorkoutPlanModel.findOneAndDelete({
            _id: req.params.id,
            userId: req.user.userId
        });
        
        if (!deletedPlan) {
            return res.status(404).json({ message: 'Workout plan not found' });
        }
        
        res.status(200).json({ message: 'Workout plan deleted successfully' });
    } catch (error) {
        next(error);
    }
});

// User preferences schema
const userPreferencesSchema = z.object({
    weight: z.number().min(20).max(300).optional(),
    height: z.number().min(100).max(250).optional(),
    age: z.number().min(13).max(100).optional(),
    gender: z.enum(['male', 'female', 'other']).optional(),
    activityLevel: z.enum(['sedentary', 'lightly active', 'moderately active', 'very active', 'extremely active']).optional(),
    dietType: z.enum(['vegetarian', 'non-vegetarian', 'vegan']).optional(),
    fitnessGoals: z.array(z.string()).optional(),
});

// Food log schema
const foodLogSchema = z.object({
    date: z.string().optional(),
    meal: z.object({
        name: z.string(),
        foodName: z.string(),
        calories: z.number(),
        protein: z.number(),
        carbs: z.number(),
        fats: z.number(),
        mealTime: z.enum(['breakfast', 'lunch', 'dinner', 'snack']).optional()
    })
});

// Calculate daily caloric and macronutrient needs based on user data
const calculateNutritionNeeds = (weight, height, age, gender, activityLevel, dietType, fitnessGoals) => {
    // Base metabolic rate (BMR) using Mifflin-St Jeor Equation
    let bmr = 0;
    if (gender === 'male') {
        bmr = 10 * weight + 6.25 * height - 5 * age + 5;
    } else {
        bmr = 10 * weight + 6.25 * height - 5 * age - 161;
    }
    
    // Activity multiplier
    let activityMultiplier = 1.2; // sedentary
    if (activityLevel === 'lightly active') activityMultiplier = 1.375;
    else if (activityLevel === 'moderately active') activityMultiplier = 1.55;
    else if (activityLevel === 'very active') activityMultiplier = 1.725;
    else if (activityLevel === 'extremely active') activityMultiplier = 1.9;
    
    // Total Daily Energy Expenditure (TDEE)
    let tdee = bmr * activityMultiplier;
    
    // Adjust based on fitness goals
    if (fitnessGoals.includes('weight loss')) {
        tdee = tdee * 0.85; // 15% deficit for weight loss
    } else if (fitnessGoals.includes('muscle gain')) {
        tdee = tdee * 1.1; // 10% surplus for muscle gain
    }
    
    // Calculate macronutrients
    let protein = 0, carbs = 0, fats = 0;
    
    // Protein: higher for muscle gain, moderate for weight loss
    if (fitnessGoals.includes('muscle gain')) {
        protein = weight * 2.2; // 2.2g per kg for muscle gain
    } else if (fitnessGoals.includes('weight loss')) {
        protein = weight * 2.0; // 2.0g per kg for weight loss
    } else {
        protein = weight * 1.6; // 1.6g per kg for maintenance
    }
    
    // Fats: minimum 20% of calories
    fats = (tdee * 0.25) / 9; // 25% of calories from fat, 9 calories per gram
    
    // Carbs: remaining calories
    const proteinCalories = protein * 4; // 4 calories per gram
    const fatCalories = fats * 9; // 9 calories per gram
    carbs = (tdee - proteinCalories - fatCalories) / 4; // 4 calories per gram
    
    // Adjust for vegetarian/vegan (slightly higher carbs, lower protein)
    if (dietType === 'vegetarian' || dietType === 'vegan') {
        protein = protein * 0.9;
        carbs = carbs * 1.1;
    }
    
    return {
        dailyCalorieNeeds: Math.round(tdee),
        dailyProteinNeeds: Math.round(protein),
        dailyCarbsNeeds: Math.round(carbs),
        dailyFatsNeeds: Math.round(fats)
    };
};

// Update user preferences
app.put('/api/user-preferences', authenticateToken, async (req, res, next) => {
    try {
        const parseResult = userPreferencesSchema.safeParse(req.body);
        if (!parseResult.success) {
            return res.status(400).json({
                message: "Validation Error",
                errors: parseResult.error.errors
            });
        }
        
        const userId = req.user.userId;
        const user = await ProfileModel.findById(userId);
        
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }
        
        // Update user preferences
        const preferences = parseResult.data;
        Object.keys(preferences).forEach(key => {
            user[key] = preferences[key];
        });
        
        // Calculate nutrition needs if we have enough data
        if (user.weight && user.height && user.age && user.gender && user.activityLevel && user.dietType) {
            const nutritionNeeds = calculateNutritionNeeds(
                user.weight, 
                user.height, 
                user.age, 
                user.gender, 
                user.activityLevel, 
                user.dietType, 
                user.fitnessGoals || ['weight maintenance']
            );
            
            user.dailyCalorieNeeds = nutritionNeeds.dailyCalorieNeeds;
            user.dailyProteinNeeds = nutritionNeeds.dailyProteinNeeds;
            user.dailyCarbsNeeds = nutritionNeeds.dailyCarbsNeeds;
            user.dailyFatsNeeds = nutritionNeeds.dailyFatsNeeds;
        }
        
        await user.save();
        
        return res.status(200).json({
            message: "User preferences updated successfully",
            user: {
                name: user.name,
                email: user.email,
                weight: user.weight,
                height: user.height,
                age: user.age,
                gender: user.gender,
                activityLevel: user.activityLevel,
                dietType: user.dietType,
                fitnessGoals: user.fitnessGoals,
                dailyCalorieNeeds: user.dailyCalorieNeeds,
                dailyProteinNeeds: user.dailyProteinNeeds,
                dailyCarbsNeeds: user.dailyCarbsNeeds,
                dailyFatsNeeds: user.dailyFatsNeeds
            }
        });
    } catch (error) {
        next(error);
    }
});

// Get user preferences
app.get('/api/user-preferences', authenticateToken, async (req, res, next) => {
    try {
        const userId = req.user.userId;
        const user = await ProfileModel.findById(userId);
        
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }
        
        return res.status(200).json({
            user: {
                name: user.name,
                email: user.email,
                weight: user.weight,
                height: user.height,
                age: user.age,
                gender: user.gender,
                activityLevel: user.activityLevel,
                dietType: user.dietType,
                fitnessGoals: user.fitnessGoals,
                dailyCalorieNeeds: user.dailyCalorieNeeds,
                dailyProteinNeeds: user.dailyProteinNeeds,
                dailyCarbsNeeds: user.dailyCarbsNeeds,
                dailyFatsNeeds: user.dailyFatsNeeds
            }
        });
    } catch (error) {
        next(error);
    }
});

// Log food
app.post('/api/food-log', authenticateToken, async (req, res, next) => {
    try {
        const parseResult = foodLogSchema.safeParse(req.body);
        if (!parseResult.success) {
            return res.status(400).json({
                message: "Validation Error",
                errors: parseResult.error.errors
            });
        }
        
        const userId = req.user.userId;
        const { date, meal } = parseResult.data;
        
        // Parse date or use current date
        const logDate = date ? new Date(date) : new Date();
        // Set time to beginning of day for consistent date comparison
        logDate.setHours(0, 0, 0, 0);
        
        // Find or create food log for this date
        let foodLog = await FoodLogModel.findOne({ 
            userId: userId,
            date: {
                $gte: logDate,
                $lt: new Date(logDate.getTime() + 24 * 60 * 60 * 1000)
            }
        });
        
        if (!foodLog) {
            foodLog = new FoodLogModel({
                userId: userId,
                date: logDate,
                meals: [],
                dailyTotals: {
                    calories: 0,
                    protein: 0,
                    carbs: 0,
                    fats: 0
                }
            });
        }
        
        // Add meal to log
        foodLog.meals.push(meal);
        
        // Update daily totals
        foodLog.dailyTotals.calories += meal.calories || 0;
        foodLog.dailyTotals.protein += meal.protein || 0;
        foodLog.dailyTotals.carbs += meal.carbs || 0;
        foodLog.dailyTotals.fats += meal.fats || 0;
        
        await foodLog.save();
        
        return res.status(201).json({
            message: "Food logged successfully",
            foodLog
        });
    } catch (error) {
        next(error);
    }
});

// Get food logs for a date range
app.get('/api/food-logs', authenticateToken, async (req, res, next) => {
    try {
        const userId = req.user.userId;
        const { startDate, endDate } = req.query;
        
        let start = startDate ? new Date(startDate) : new Date();
        start.setHours(0, 0, 0, 0);
        
        let end = endDate ? new Date(endDate) : new Date(start);
        end.setHours(23, 59, 59, 999);
        
        // If no dates provided, default to today
        if (!startDate && !endDate) {
            start = new Date();
            start.setHours(0, 0, 0, 0);
            end = new Date();
            end.setHours(23, 59, 59, 999);
        }
        
        const foodLogs = await FoodLogModel.find({
            userId: userId,
            date: {
                $gte: start,
                $lte: end
            }
        }).sort({ date: 1 });
        
        return res.status(200).json({ foodLogs });
    } catch (error) {
        next(error);
    }
});

// Add a basic health check endpoint
app.get("/health", (req, res) => {
    res.json({ status: "healthy" });
});


app.use(errorHandeling)
 
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});