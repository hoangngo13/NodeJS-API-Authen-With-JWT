const router = require('express').Router();
const Admin = require('../model/Admin');
const { registerValidation, loginValidation } = require('../validation');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

//REGISTER
router.post('/register', async (req, res) => {

    //Let validate the data
    const { error } = registerValidation(req.body);

    if (error) return res.status(400).send(error.details[0].message);

    //Checking if the admin is already in the database
    const emailExist = await Admin.findOne({ email: req.body.email });
    if (emailExist) return res.status(400).send('Email already exists');

    //Hash the password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(req.body.password, salt);


    const admin = new Admin({
        email: req.body.email,
        password: hashedPassword
    });
    try {
        const savedAdmin = await admin.save();
        res.send({ admin: admin._id });
    } catch (err) {
        res.status(400).send(err);
    }
});

//LOGIN
router.post('/login', async (req, res) => {

    //Let validate the data
    const { error } = loginValidation(req.body);

    if (error) return res.status(400).send(error.details[0].message);

    //Checking if the email exists
    const admin = await Admin.findOne({ email: req.body.email });
    if (!admin) return res.status(400).send('Email is not found');

    //Checking if the password valid
    const validPass = await bcrypt.compare(req.body.password, admin.password);
    if (!validPass) return res.status(400).send('Password is not valid');


    //Create and assign a token
    const token = jwt.sign({ _id: admin._id }, process.env.TOKEN_SECRET);
    res.header('auth-token', token).send(token);
});

module.exports = router;