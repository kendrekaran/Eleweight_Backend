const mongoose = require("mongoose")

const FoodLogSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'account',
        required: true
    },
    date: {
        type: Date,
        default: Date.now
    },
    meals: [{
        name: String,
        foodName: String,
        calories: Number,
        protein: Number,
        carbs: Number,
        fats: Number,
        mealTime: {
            type: String,
            enum: ['breakfast', 'lunch', 'dinner', 'snack'],
            default: 'snack'
        }
    }],
    dailyTotals: {
        calories: { type: Number, default: 0 },
        protein: { type: Number, default: 0 },
        carbs: { type: Number, default: 0 },
        fats: { type: Number, default: 0 }
    }
}, { timestamps: true })

// Create a compound index on userId and date for efficient queries
FoodLogSchema.index({ userId: 1, date: 1 });

const FoodLogModel = mongoose.model("foodlog", FoodLogSchema)

module.exports = FoodLogModel 