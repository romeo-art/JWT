const express = require('express');
// const jwt = require('jsonwebtoken');
const app = express();
const dotenv = require('dotenv');
const mongoose = require('mongoose');
//Import Routes
const authRoute = require('./routes/auth');
const postRoute = require('./routes/posts');

dotenv.config();

//Connect to DB
mongoose.connect(process.env.DB_CONNECT, { useUnifiedTopology: true, useNewUrlParser: true}, () => 
    console.log("Connected to DB!"));

//Middleware
app.use(express.json());

//Route Middleware
app.use('/api/user', authRoute);
app.use('/api/posts', postRoute);

app.listen(8000, ()=> console.log('App listening at port 8000!'));

