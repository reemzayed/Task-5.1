
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

// Instructor Portal account.
const instructorSchema = new mongoose.Schema(
    {
        name: {
            type: String,
            required: true
        },

        username: {
            type: String,
            required: true,
            unique: true,
            trim: true
        },

        password: {
            type: String,
            required: true,
            select: false
        },

        department: {
            type: String
        },

        role: {
            type: String,
            default: 'instructor'
        },

        apiKey: {
            type: String
        },

        privateEmail: {
            type: String
        },

        privatePhone: {
            type: String
        }
    },
    {
        timestamps: true
    }
);

// Hash the password before saving a new or modified password.
instructorSchema.pre('save', async function () {
    if (!this.isModified('password')) {
        return;
    }

    this.password = await bcrypt.hash(this.password, 12);
});

export const Instructor = mongoose.model(
    'Instructor',
    instructorSchema
);
