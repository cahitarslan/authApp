const mongoose = require('mongoose');

const Schema = mongoose.Schema;

const UserSchema = new Schema(
    {
        ad: {
            type: String,
            required: [true, 'Ad alanı boş olamaz'],
            trim: true,
            minlength: 2,
            maxlength: 30,
        },
        soyad: {
            type: String,
            required: true,
            trim: true,
            minlength: 2,
            maxlength: [30, 'Soyadı maksimum 30 karakter olmalı'],
        },
        email: {
            type: String,
            required: true,
            trim: true,
            unique: true,
            lowercase: true,
        },
        emailAktif: {
            type: Boolean,
            default: false,
        },
        sifre: {
            type: String,
            required: true,
            trim: true,
        },
        avatar: {
            type: String,
            default: 'default.jpeg',
        },
    },
    { collection: 'kullanicilar', timestamps: true }
);

const User = mongoose.model('User', UserSchema);

module.exports = User;
