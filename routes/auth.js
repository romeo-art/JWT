const router = require("express").Router();
const User = require("../model/User");
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { registerValidation, loginValidation } = require("../validation");

let refreshTokens = [];

router.post("/token", async (req, res) => {
    const refreshToken = req.body.token;

    console.log(refreshToken)
    console.log(refreshTokens)

    if(refreshToken == null) return res.status(401).send('RefreshToken is null!');
    if(!refreshTokens.includes(refreshToken)) return res.status(403).send('RefreshToken is not present!');
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN, (err, user) => {
        if(err) return res.status(403).send('Error upon verifying!')
        const accessToken = generateAccessToken(user);
        res.json({accessToken: accessToken})
    })
})

router.post("/register", async (req, res) => {
    //Validate passed data
    const {
        error
    } = registerValidation(req.body);
    if (error) return res.status(400).send(error.details[0].message)

    //Checking if the user is already in the database
    const emailExist = await User.findOne({
        email: req.body.email
    });
    if (emailExist) return res.status(400).send('Email already exists');

    //Hash the password
    const salt = await bcrypt.genSalt(10);
    const hashPassword = await bcrypt.hash(req.body.password, salt)

    //Create a new user
    const user = new User({
        name: req.body.name,
        email: req.body.email,
        password: hashPassword,
    });
    try {
        const savedUser = await user.save();
        res.send({
            user: user._id
        });
    } catch (err) {
        res.status(400).send(err);
    }
});

//LOGIN
router.post('/login', async (req, res) => {
    //Validate data before login
    const {error} = loginValidation(req.body);
    if (error) return res.status(400).send(error.details[0].message);

    //Checking if the user is already in the database
    const user = await User.findOne({email: req.body.email});
    if (!user) return res.status(400).send('Email or password is wrong');
    
    //Password is correct
    const validPass = await bcrypt.compare(req.body.password, user.password);
    if(!validPass) return res.status(400).send("Invalid password")

    const token = generateAccessToken(user);
    // const token = jwt.sign({_id: user._id}, process.env.TOKEN_SECRET);

    const refreshToken = jwt.sign({_id: user._id}, process.env.REFRESH_TOKEN);
    refreshTokens.push(refreshToken);

    res.header('auth-token', token).send({token: token, refreshToken: refreshToken});
});

function generateAccessToken(user) {
    return jwt.sign({_id: user._id}, process.env.TOKEN_SECRET, {expiresIn: '10m'});
}

module.exports = router;